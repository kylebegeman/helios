package gitdeploy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// SigningDir holds the machine's signing policy: the keys whose signed
// commits may deploy, and the apps that deploy nothing else. Root writes
// it, and the bedrock user, who runs the push hook, reads it.
const SigningDir = "/etc/bedrock/git"

// The policy's two files, both 0640 root:bedrock. allowed_signers is
// ssh-keygen's own format, which git reads as gpg.ssh.allowedSignersFile.
const (
	signersName = "allowed_signers"
	policyName  = "signing.json"
)

// gitOnly limits a signer's key to signatures git makes, so a signature
// the same key made for anything else can't pass for a commit's.
const gitOnly = `namespaces="git"`

var principalPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._%+@-]{0,99}$`)

// ValidPrincipal reports whether a name can be a signer's: one name, such
// as an email address, with nothing ssh-keygen would read as a pattern.
func ValidPrincipal(p string) bool { return principalPattern.MatchString(p) }

// Signer is one line of the allowed signers file: who signs, and the key
// they sign with.
type Signer struct {
	Principal string `json:"principal"`
	// Options are the line's ssh-keygen options. helios writes only
	// namespaces="git"; a line written by hand keeps its own.
	Options string `json:"options,omitempty"`
	Type    string `json:"type"`
	Blob    string `json:"-"`
	// at is the signer's line in the file as read, from 1, or 0 for one
	// helios adds.
	at int
}

// Fingerprint is the signer's key fingerprint, as ssh-keygen -l prints it.
func (s Signer) Fingerprint() string { return Key{Blob: s.Blob}.Fingerprint() }

// Line is the signer's allowed signers line.
func (s Signer) Line() string {
	line := s.Principal
	if s.Options != "" {
		line += " " + s.Options
	}
	return line + " " + s.Type + " " + s.Blob
}

// parseSigner reads an allowed signers line: principals, then options if
// there are any, then the key.
func parseSigner(line string) (Signer, bool) {
	f := strings.Fields(line)
	if len(f) < 3 {
		return Signer{}, false
	}
	s := Signer{Principal: f[0]}
	i := 1
	if !keyTypes[f[i]] {
		s.Options = f[i]
		i++
	}
	if i+1 >= len(f) {
		return Signer{}, false
	}
	k, err := ParseKey(f[i] + " " + f[i+1])
	if err != nil {
		return Signer{}, false
	}
	s.Type, s.Blob = k.Type, k.Blob
	return s, true
}

// Policy is the machine's signing policy.
type Policy struct {
	Dir     string
	Signers []Signer
	// Others are allowed signers lines helios can't read, kept as they
	// were; ssh-keygen may still honour them.
	Others []string
	// RequireSigned are the apps that deploy only signed commits.
	RequireSigned []string
	// lines are the allowed signers file as read, less helios's header,
	// so a write keeps what a person wrote there: comments, order and all.
	lines []string
}

// signersHeader opens the allowed signers file helios writes.
const signersHeader = "# Written by helios git signers. An app that requires signed commits deploys a tip signed by one of these keys, and nothing else."

type policyFile struct {
	RequireSigned []string `json:"require_signed"`
}

// ReadPolicy reads the signing policy in dir. A missing file is an empty
// policy, so a machine nobody configured deploys as it always has. Any
// other failure is an error, never an empty policy: a deploy that can't
// read the policy can't know it isn't gated.
func ReadPolicy(dir string) (*Policy, error) {
	p := &Policy{Dir: dir}
	path := filepath.Join(dir, policyName)
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, unreadable(err)
	default:
		var f *policyFile
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("the signing policy %s can't be read: %w", path, err)
		}
		if f == nil {
			return nil, fmt.Errorf("the signing policy %s must be a JSON object", path)
		}
		for _, a := range f.RequireSigned {
			if !ValidApp(a) {
				return nil, fmt.Errorf("the signing policy %s names %q, which can't be an app", path, a)
			}
			p.require(a)
		}
	}
	file, err := os.Open(filepath.Join(dir, signersName))
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, unreadable(err)
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == signersHeader {
			continue
		}
		p.lines = append(p.lines, sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if s, ok := parseSigner(line); ok {
			s.at = len(p.lines)
			p.Signers = append(p.Signers, s)
		} else {
			p.Others = append(p.Others, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("can't read the allowed signers: %w", err)
	}
	return p, nil
}

func unreadable(err error) error {
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("can't read the signing policy, so no commit can be held to it: %w; helios host reconcile, run as root, lets the push user read it", err)
	}
	return fmt.Errorf("can't read the signing policy: %w", err)
}

// Requires reports whether an app deploys only signed commits.
func (p *Policy) Requires(app string) bool { return slices.Contains(p.RequireSigned, app) }

func (p *Policy) require(app string) {
	if !p.Requires(app) {
		p.RequireSigned = append(p.RequireSigned, app)
		slices.Sort(p.RequireSigned)
	}
}

// Require makes an app deploy only signed commits, or, with off, any
// commit again. It reports whether anything changed.
func (p *Policy) Require(app string, off bool) bool {
	if off {
		before := len(p.RequireSigned)
		p.RequireSigned = slices.DeleteFunc(p.RequireSigned, func(a string) bool { return a == app })
		return len(p.RequireSigned) != before
	}
	if p.Requires(app) {
		return false
	}
	p.require(app)
	return true
}

// Holder is who already signs with a key: principal itself when it does,
// or else another principal that does, or "" when no one does.
func (p *Policy) Holder(blob, principal string) string {
	holder := ""
	for _, s := range p.Signers {
		switch {
		case s.Blob != blob:
		case s.Principal == principal:
			return principal
		case holder == "":
			holder = s.Principal
		}
	}
	return holder
}

// Match lists the signers named by a principal, a SHA256: fingerprint or a
// public key.
func (p *Policy) Match(which string) []Signer {
	var found []Signer
	for _, s := range p.Signers {
		switch {
		case strings.HasPrefix(which, "SHA256:"):
			if s.Fingerprint() != which {
				continue
			}
		case strings.Contains(which, " "):
			k, err := ParseKey(which)
			if err != nil || k.Blob != s.Blob {
				continue
			}
		default:
			if s.Principal != which {
				continue
			}
		}
		found = append(found, s)
	}
	return found
}

// Remove takes away the signers Match finds for which, and only those: a
// line that gives the same key to another principal stays. It returns
// the signers it removed.
func (p *Policy) Remove(which string) []Signer {
	found := p.Match(which)
	p.Signers = slices.DeleteFunc(p.Signers, func(s Signer) bool { return slices.Contains(found, s) })
	return found
}

// Who names the allowed signers for a refusal or a plan.
func (p *Policy) Who() string {
	var names []string
	for _, s := range p.Signers {
		if !slices.Contains(names, s.Principal) {
			names = append(names, s.Principal)
		}
	}
	if len(p.Others) > 0 {
		names = append(names, fmt.Sprintf("%d hand-written line(s)", len(p.Others)))
	}
	const shown = 5
	if len(names) > shown {
		names = append(names[:shown], fmt.Sprintf("%d more", len(names)-shown))
	}
	if len(names) == 0 {
		return "no one yet"
	}
	return strings.Join(names, ", ")
}

// UpdatePolicy changes the signing policy in dir under one lock, and
// writes both files in one step each, owned by root and readable by the
// bedrock user, so a push never reads half a policy.
func UpdatePolicy(dir string, change func(*Policy) error) error {
	gid, err := policyGroup()
	if err != nil {
		return err
	}
	if err := EnsureSigningDir(dir, gid); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	p, err := ReadPolicy(dir)
	if err != nil {
		return err
	}
	before := slices.Clone(p.Signers)
	if err := change(p); err != nil {
		return err
	}
	// The signers file is written only when the signers changed, and then
	// line for line as it was, less the lines of signers taken away.
	if !slices.Equal(before, p.Signers) {
		kept := map[int]bool{}
		for _, s := range p.Signers {
			kept[s.at] = true
		}
		gone := map[int]bool{}
		for _, s := range before {
			gone[s.at] = !kept[s.at]
		}
		var signers strings.Builder
		signers.WriteString(signersHeader + "\n")
		for i, line := range p.lines {
			if !gone[i+1] {
				signers.WriteString(line + "\n")
			}
		}
		for _, s := range p.Signers {
			if s.at == 0 {
				signers.WriteString(s.Line() + "\n")
			}
		}
		if err := writePolicyFile(filepath.Join(dir, signersName), []byte(signers.String()), gid); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(policyFile{RequireSigned: append([]string{}, p.RequireSigned...)}, "", "  ")
	if err != nil {
		return err
	}
	return writePolicyFile(filepath.Join(dir, policyName), append(raw, '\n'), gid)
}

// policyGroup is the bedrock group's id, which may read the policy, or -1
// when this process isn't root and so can't give files away (a test, or a
// developer's machine).
func policyGroup() (int, error) {
	if os.Geteuid() != 0 {
		return -1, nil
	}
	g, err := user.LookupGroup(User)
	if err != nil {
		return -1, fmt.Errorf("the %s group doesn't exist; run helios host reconcile", User)
	}
	return strconv.Atoi(g.Gid)
}

// EnsureSigningDir makes dir, root:bedrock 0750, and lets the bedrock group
// reach it through its parent. A parent of root's or the bedrock group's
// becomes bedrock's with group bits --x, so the group passes through and
// lists nothing, as helios host reconcile leaves it. A parent of another
// group keeps that group and gains only others' x, where reconcile would
// give it to bedrock (see sharedParent). A gid below zero makes dir as it
// is.
func EnsureSigningDir(dir string, gid int) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if gid < 0 {
		return nil
	}
	if err := os.Chown(dir, 0, gid); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		return err
	}
	parent := filepath.Dir(dir)
	info, err := os.Stat(parent)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("can't tell who owns " + parent)
	}
	mode := info.Mode()
	group, shared := sharedParent(mode, int(st.Gid), gid)
	if group >= 0 {
		if err := os.Chown(parent, -1, group); err != nil {
			return err
		}
	}
	if shared.Perm() == mode.Perm() {
		return nil
	}
	return os.Chmod(parent, shared)
}

// sharedParent says what the signing dir's parent becomes, from its mode
// as os.Stat gives it and its group pgid: the group to give it, or -1 to
// keep its own, and the mode to chmod it to. A parent of root's or the
// bedrock group's goes to bedrock with group bits --x, whatever others
// have, as reconcile's chmod g=x leaves it. Passing through, not listing:
// what is inside keeps its own owner and mode, so the group reads only the
// policy. A parent of another group is someone's choice, and gains only
// others' x if it lacks it. Its setuid, setgid and sticky bits stay, as
// they do under chmod g=x.
func sharedParent(mode os.FileMode, pgid, bedrock int) (int, os.FileMode) {
	special := mode & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	perm := mode.Perm()
	switch pgid {
	case bedrock:
		return -1, perm&^0o070 | 0o010 | special
	case 0:
		return bedrock, perm&^0o070 | 0o010 | special
	default:
		return -1, perm | 0o001 | special
	}
}

// ShareSigningDir gives the push user its way to the signing policy, for
// the daemon to do as it starts: a machine set up before the policy
// existed may keep /etc/bedrock closed to everyone but root, and then
// every push would be refused for want of reading it. A stock /etc/bedrock,
// 755 root:root, becomes 715 root:bedrock, as reconcile leaves it, so the
// push user passes through and no longer lists it. It does nothing unless
// this process is root and the bedrock group exists.
func ShareSigningDir() error {
	if os.Geteuid() != 0 {
		return nil
	}
	g, err := user.LookupGroup(User)
	if err != nil {
		return nil
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return err
	}
	return EnsureSigningDir(SigningDir, gid)
}

func writePolicyFile(path string, content []byte, gid int) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	fail := func(err error) error {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(0o640); err != nil {
		return fail(err)
	}
	if gid >= 0 {
		if err := tmp.Chown(0, gid); err != nil {
			return fail(err)
		}
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

// Signature is who signed a commit: a principal of the allowed signers
// file, and the fingerprint of the key that made the signature.
type Signature struct {
	Principal   string
	Fingerprint string
}

func (s Signature) String() string { return s.Principal + " (" + s.Fingerprint + ")" }

// SignatureError says why a commit's signature doesn't let it deploy.
type SignatureError struct {
	Commit string
	Reason string
}

func (e *SignatureError) Error() string { return "commit " + short(e.Commit) + " " + e.Reason }

// The first line of each kind of signature a commit can carry. git picks
// the program that checks a signature by this line, whatever gpg.format
// says, so only an SSH one is ever handed to git to check.
const (
	sshArmor  = "-----BEGIN SSH SIGNATURE-----"
	pgpArmor  = "-----BEGIN PGP SIGNATURE-----"
	x509Armor = "-----BEGIN SIGNED MESSAGE-----"
)

var (
	goodSignature = regexp.MustCompile(`(?m)^Good "git" signature for (\S+) with (\S+) key (SHA256:\S+)$`)
	unknownSigner = regexp.MustCompile(`(?m)^Good "git" signature with (\S+) key (SHA256:\S+)$`)
)

// VerifyTip checks that a commit carries an SSH signature made by a key
// the signers file allows to sign git commits, and says whose it is. GPG
// and X.509 signatures never count, GitHub's own on its web merges among
// them. git runs in repoDir with the caller's environment, so a
// pre-receive hook checks a pushed commit while it is still in quarantine.
func VerifyTip(ctx context.Context, repoDir, commit, signersFile string) (Signature, error) {
	if !commitPattern.MatchString(commit) {
		return Signature{}, errors.New("invalid commit")
	}
	env := append(os.Environ(), "LC_ALL=C")
	// Replace refs would let a pushed ref swap what a signed commit holds,
	// so git reads every object as it is, here and in ExportCommit.
	cat := exec.CommandContext(ctx, "git", "--no-replace-objects", "-C", repoDir, "cat-file", "commit", commit)
	cat.Env = env
	var catErr bytes.Buffer
	cat.Stderr = &catErr
	raw, err := cat.Output()
	if err != nil {
		return Signature{}, fmt.Errorf("read commit %s: %s", short(commit), lastLine(catErr.String(), err))
	}
	refuse := func(reason string) (Signature, error) {
		return Signature{}, &SignatureError{Commit: commit, Reason: reason}
	}
	switch signatureArmor(raw) {
	case "":
		return refuse("isn't signed")
	case sshArmor:
	case pgpArmor:
		return refuse("has a GPG signature, and only SSH signatures count; GitHub signs the merges it makes this way")
	case x509Armor:
		return refuse("has an X.509 signature, and only SSH signatures count")
	default:
		return refuse("has a signature of a kind helios doesn't check, and only SSH signatures count")
	}
	verify := exec.CommandContext(ctx, "git", "--no-replace-objects", "-C", repoDir,
		"-c", "gpg.format=ssh", "-c", "gpg.ssh.program=ssh-keygen", "-c", "gpg.ssh.allowedSignersFile="+signersFile,
		"verify-commit", "--raw", commit)
	verify.Env = env
	var report bytes.Buffer
	verify.Stdout, verify.Stderr = &report, &report
	err = verify.Run()
	text := report.String()
	if err == nil {
		if m := goodSignature.FindStringSubmatch(text); m != nil {
			return Signature{Principal: m[1], Fingerprint: m[3]}, nil
		}
		return refuse("verifies, but git's report doesn't say who signed it")
	}
	if ctx.Err() != nil {
		return Signature{}, ctx.Err()
	}
	if exit := (*exec.ExitError)(nil); !errors.As(err, &exit) {
		return Signature{}, fmt.Errorf("check commit %s: %w", short(commit), err)
	}
	switch {
	case strings.Contains(text, "not permitted for use in signature namespace"):
		return refuse("is signed with a key that isn't allowed to sign git commits")
	case strings.Contains(text, "key has expired"), strings.Contains(text, "key is not yet valid"):
		// ssh-keygen's words when the commit's date falls outside the
		// valid-after and valid-before of the key's allowed signers line.
		return refuse("is signed with a key its allowed signers line doesn't allow at the commit's date (valid-after or valid-before)")
	case unknownSigner.MatchString(text):
		m := unknownSigner.FindStringSubmatch(text)
		return refuse(fmt.Sprintf("is signed with %s key %s, which isn't an allowed signer", m[1], m[2]))
	default:
		return refuse("has an SSH signature that doesn't verify: " + lastLine(text, err))
	}
}

// signatureArmor is the first line of a commit's signature, or "" when it
// has none. A signature is a gpgsig header (gpgsig-sha256 for a SHA-256
// object), continued on lines that start with a space. Every signature a
// commit carries must be SSH, so any other one is what this reports.
func signatureArmor(raw []byte) string {
	header, _, _ := bytes.Cut(raw, []byte("\n\n"))
	armor := ""
	for line := range strings.SplitSeq(string(header), "\n") {
		name, value, ok := strings.Cut(line, " ")
		if !ok || (name != "gpgsig" && name != "gpgsig-sha256") {
			continue
		}
		if value = strings.TrimSpace(value); armor == "" || value != sshArmor {
			armor = value
		}
	}
	return armor
}

// lastLine is the last thing a command said, or its error when it said
// nothing.
func lastLine(text string, err error) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	if last == "" {
		return err.Error()
	}
	if len(last) > 200 {
		last = last[:200]
	}
	return last
}

// CheckTip holds a commit an app is about to deploy to the signing policy
// in dir. It returns who signed the commit, or "" for an app that doesn't
// require signed commits. An error refuses the deploy, and says which
// commit and who may sign.
func CheckTip(ctx context.Context, dir, appName, repoDir, commit string) (string, error) {
	p, err := ReadPolicy(dir)
	if err != nil {
		return "", err
	}
	if !p.Requires(appName) {
		return "", nil
	}
	if len(p.Signers) == 0 && len(p.Others) == 0 {
		return "", fmt.Errorf("%s deploys only signed commits, and no signer is allowed yet, so commit %s can't deploy; helios git signers add allows one", appName, short(commit))
	}
	sig, err := VerifyTip(ctx, repoDir, commit, filepath.Join(dir, signersName))
	if err != nil {
		return "", fmt.Errorf("%s deploys only commits signed by %s, and %w", appName, p.Who(), err)
	}
	return sig.String(), nil
}

// CheckTree refuses an uploaded tree for an app that deploys only signed
// commits: a tree carries no commit to check. Root can still deploy one,
// with helios deploy --to root@ or on the machine, as the way past the
// policy.
func CheckTree(dir, appName string) error {
	p, err := ReadPolicy(dir)
	if err != nil {
		return err
	}
	if p.Requires(appName) {
		return fmt.Errorf("%s deploys only signed commits, and an uploaded tree has no commit to check; push a signed commit instead (root can still deploy a tree, with helios deploy --to root@<machine>)", appName)
	}
	return nil
}

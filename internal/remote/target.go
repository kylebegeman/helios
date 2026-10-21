// Package remote operates explicitly named machines through pinned SSH connections.
package remote

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const ConfigVersion = 1

const maxConfigSize = 1 << 20

// Target contains connection settings, never credential values.
type Target struct {
	MachineID      string `json:"machine_id,omitempty"`
	SSH            string `json:"ssh"`
	Port           int    `json:"port,omitempty"`
	IdentityFile   string `json:"identity_file,omitempty"`
	KnownHostsFile string `json:"known_hosts_file,omitempty"`
	Binary         string `json:"binary,omitempty"`
	Sudo           bool   `json:"sudo,omitempty"`
}

type Config struct {
	Version int               `json:"version"`
	Targets map[string]Target `json:"targets"`
}

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
var destinationPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@:\[\]-]*$`)

func (t Target) Validate() error {
	if !destinationPattern.MatchString(t.SSH) && net.ParseIP(t.SSH) == nil {
		return errors.New("SSH destination must be a host or an SSH configuration alias, optionally user@host")
	}
	if t.Port < 0 || t.Port > 65535 {
		return errors.New("SSH port must be 1 to 65535, or omitted")
	}
	if t.Binary != "" && (!filepath.IsAbs(t.Binary) || strings.ContainsAny(t.Binary, "\x00\r\n")) {
		return errors.New("remote binary must be an absolute path")
	}
	for _, p := range []string{t.IdentityFile, t.KnownHostsFile} {
		if strings.ContainsAny(p, "\x00\r\n") {
			return errors.New("SSH file path contains a control character")
		}
	}
	return nil
}

func ValidName(name string) bool { return namePattern.MatchString(name) }

func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{Version: ConfigVersion, Targets: map[string]Target{}}, nil
	}
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return Config{}, err
	}
	if len(data) > maxConfigSize {
		return Config{}, errors.New("target configuration is oversized")
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("target configuration: %w", err)
	}
	if dec.Decode(new(any)) != io.EOF {
		return c, errors.New("target configuration has trailing or oversized data")
	}
	if c.Version != ConfigVersion {
		return c, fmt.Errorf("target configuration version %d is unsupported", c.Version)
	}
	if c.Targets == nil {
		c.Targets = map[string]Target{}
	}
	for name, t := range c.Targets {
		if !ValidName(name) {
			return c, fmt.Errorf("invalid target name %q", name)
		}
		if err := t.Validate(); err != nil {
			return c, fmt.Errorf("target %s: %w", name, err)
		}
	}
	return c, nil
}

func Save(path string, c Config) error {
	if c.Version != ConfigVersion {
		return errors.New("unsupported target configuration version")
	}
	for name, t := range c.Targets {
		if !ValidName(name) {
			return errors.New("invalid target name")
		}
		if err := t.Validate(); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > maxConfigSize {
		return errors.New("target configuration is oversized")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".targets-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0o600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Quote quotes a single remote shell argument. SSH otherwise joins its
// command arguments into shell code, even when the local command uses argv.
func Quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func Shell(args ...string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = Quote(a)
	}
	return strings.Join(q, " ")
}

// Transport executes SSH directly. Program supports the existing BEDROCK_SSH
// wrapper convention; it is not passed through a local shell.
type Transport struct{ Program []string }

func (tr Transport) Command(ctx context.Context, t Target, script string) (*exec.Cmd, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	program := tr.Program
	if len(program) == 0 {
		program = []string{"ssh"}
	}
	args := append([]string{}, program[1:]...)
	args = append(args, "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15")
	if t.Port != 0 {
		args = append(args, "-p", fmt.Sprint(t.Port))
	}
	if t.IdentityFile != "" {
		args = append(args, "-i", t.IdentityFile, "-o", "IdentitiesOnly=yes")
	}
	if t.KnownHostsFile != "" {
		// OpenSSH parses -o as configuration syntax after argv parsing.
		// Keep spaces, quotes and backslashes inside one filename.
		path := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(t.KnownHostsFile)
		args = append(args, "-o", `UserKnownHostsFile="`+path+`"`)
	}
	args = append(args, "--", t.SSH, script)
	return exec.CommandContext(ctx, program[0], args...), nil
}
func (tr Transport) RunScript(ctx context.Context, t Target, script string, in io.Reader, out, errOut io.Writer) error {
	cmd, err := tr.Command(ctx, t, script)
	if err != nil {
		return err
	}
	cmd.Stdin = in
	cmd.Stdout = out
	cmd.Stderr = errOut
	return cmd.Run()
}
func (t Target) Arguments(args ...string) []string {
	binary := t.Binary
	if binary == "" {
		binary = "/usr/local/bin/bedrock"
	}
	all := []string{binary}
	if t.Sudo {
		all = []string{"sudo", "-n", "--", binary}
	}
	return append(all, args...)
}
func (tr Transport) Run(ctx context.Context, t Target, args []string, in io.Reader, out, errOut io.Writer) error {
	return tr.RunScript(ctx, t, Shell(t.Arguments(args...)...), in, out, errOut)
}

// ScopeDigest binds a remote plan to its explicitly selected connection.
// It can be unwrapped without retaining a local approval cache.
func ScopeDigest(t Target, digest string) string {
	b, _ := json.Marshal(t)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8]) + "." + digest
}
func UnscopeDigest(t Target, digest string) (string, error) {
	scope, raw, ok := strings.Cut(digest, ".")
	if !ok || raw == "" || ScopeDigest(t, raw) != scope+"."+raw {
		return "", errors.New("plan digest belongs to another target or is not a target plan; read --plan on this target again")
	}
	return raw, nil
}

// Binding adds the observed machine, remote state and uploaded input to a target approval.
type Binding struct {
	Target     Target   `json:"target"`
	SourceHash string   `json:"source_hash,omitempty"`
	StateArgs  []string `json:"state_args,omitempty"`
}

func (b Binding) ScopeDigest(digest string) string {
	raw, _ := json.Marshal(b)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:16]) + "." + digest
}
func (b Binding) UnscopeDigest(token string) (string, error) {
	_, raw, ok := strings.Cut(token, ".")
	if !ok || raw == "" || b.ScopeDigest(raw) != token {
		return "", errors.New("plan digest belongs to another target, machine, remote state or source snapshot; read --plan again")
	}
	return raw, nil
}

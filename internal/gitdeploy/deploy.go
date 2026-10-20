package gitdeploy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/api"
	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/ui"
)

// Deployer runs a deploy and reports its events.
type Deployer func(ctx context.Context, in app.DeployInput, emit func(kernel.Event)) (*kernel.Receipt, error)

// ThroughDaemon asks the daemon on a socket to deploy. It never falls back
// to a kernel of its own: the bedrock user can't touch the machine's state,
// and shouldn't.
func ThroughDaemon(socket string) Deployer {
	return func(ctx context.Context, in app.DeployInput, emit func(kernel.Event)) (*kernel.Receipt, error) {
		c := api.Dial(socket)
		defer c.Close()
		if !c.Reachable(ctx) {
			return nil, fmt.Errorf("the helios daemon isn't answering on %s", socket)
		}
		raw, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		return c.Run(ctx, app.DeployKind, raw, emit)
	}
}

// Deploy deploys a source tree, writing its steps to out the way the CLI
// shows them without a terminal. signer is who signed commit, for an app
// that deploys only signed commits. It reports whether the deploy
// succeeded.
func Deploy(ctx context.Context, d Deployer, source, commit, signer string, out io.Writer) (bool, error) {
	in := app.DeployInput{Source: source, Revision: app.NewRevision(time.Now()), Commit: commit, Signer: signer}
	r := ui.New(out, false, false)
	receipt, err := d(ctx, in, r.Event)
	if err != nil {
		return false, err
	}
	return receipt.Status == state.Succeeded, nil
}

const zeroCommit = "0000000000000000000000000000000000000000"

var commitPattern = regexp.MustCompile(`^(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$`)

// hookBuildsDir is where the hook writes source trees, and signingDir is
// the signing policy it holds pushes to; tests move them.
var (
	hookBuildsDir = BuildsDir
	signingDir    = SigningDir
)

// Hook is the pre-receive hook: a push to the deploy branch deploys that
// commit, and a failed deploy refuses the push, so the branch on the
// machine is always what runs. Other branches are kept and not deployed.
func Hook(ctx context.Context, appName string, stdin io.Reader, out io.Writer, d Deployer) int {
	if !ValidApp(appName) {
		fmt.Fprintln(out, "helios: invalid app name")
		return 1
	}
	repo, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(out, "helios: %v\n", err)
		return 1
	}
	branch := Branch(repo)
	target := ""
	sc := bufio.NewScanner(stdin)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 3 || !commitPattern.MatchString(f[0]) || !commitPattern.MatchString(f[1]) {
			fmt.Fprintln(out, "helios: invalid git ref update")
			return 1
		}
		if strings.HasPrefix(f[2], "refs/replace/") {
			// A replace ref makes git read one object as another, so it
			// could change what a signed commit deploys. Deleting one is
			// always fine.
			if strings.Trim(f[1], "0") == "" {
				continue
			}
			fmt.Fprintf(out, "helios: %s would make git read one object as another; replace refs aren't kept here, and the push is refused\n", f[2])
			return 1
		}
		if f[2] != "refs/heads/"+branch {
			fmt.Fprintf(out, "helios: %s kept; pushes to %s deploy\n", strings.TrimPrefix(f[2], "refs/heads/"), branch)
			continue
		}
		if strings.Trim(f[1], "0") == "" {
			fmt.Fprintf(out, "helios: %s is the branch that deploys %s; it can't be deleted here\n", branch, appName)
			return 1
		}
		target = f[1]
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(out, "helios: read git updates: %v\n", err)
		return 1
	}
	if target == "" {
		return 0
	}
	short := target[:12]
	// The tip is checked before anything leaves the repository, so a
	// commit the policy refuses is never exported, let alone built.
	signer, err := CheckTip(ctx, signingDir, appName, repo, target)
	if err != nil {
		fmt.Fprintf(out, "helios: %v; the push is refused\n", err)
		return 1
	}
	if signer != "" {
		fmt.Fprintf(out, "helios: %s is signed by %s\n", short, signer)
	}
	fmt.Fprintf(out, "helios: deploying %s of %s\n", short, appName)
	dir, err := NewBuildDir(hookBuildsDir, appName, short)
	if err != nil {
		fmt.Fprintf(out, "helios: %v\n", err)
		return 1
	}
	defer PruneBuilds(hookBuildsDir, appName, 3)
	if err := ExportCommit(ctx, repo, target, dir); err != nil {
		fmt.Fprintf(out, "helios: %v\n", err)
		return 1
	}
	return deployTree(ctx, appName, dir, short, signer, out, d, "the push is refused and the running revision stays")
}

// ReceiveTree takes a source tree as a tar stream, as helios deploy --to
// sends it, and deploys it.
func ReceiveTree(ctx context.Context, appName string, stdin io.Reader, out io.Writer, d Deployer, buildsRoot string) int {
	dir, err := NewBuildDir(buildsRoot, appName, "upload")
	if err != nil {
		fmt.Fprintf(out, "helios: %v\n", err)
		return 1
	}
	defer PruneBuilds(buildsRoot, appName, 3)
	if err := Extract(stdin, dir); err != nil {
		fmt.Fprintf(out, "helios: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "helios: deploying %s from the uploaded tree\n", appName)
	return deployTree(ctx, appName, dir, "", "", out, d, "the running revision stays")
}

func deployTree(ctx context.Context, appName, dir, commit, signer string, out io.Writer, d Deployer, onFailure string) int {
	m, err := CheckSource(dir, appName)
	if err != nil {
		fmt.Fprintf(out, "helios: %v\n", err)
		return 1
	}
	ok, err := Deploy(ctx, d, dir, commit, signer, out)
	if errors.Is(err, api.ErrDisconnected) {
		fmt.Fprintf(out, "helios: %v; the daemon finishes the deploy on its own\n", err)
		return 1
	}
	if err != nil {
		fmt.Fprintf(out, "helios: %v; %s\n", err, onFailure)
		return 1
	}
	if !ok {
		fmt.Fprintf(out, "helios: the deploy failed; %s\n", onFailure)
		return 1
	}
	fmt.Fprintf(out, "helios: %s is live%s\n", appName, liveAt(m))
	return 0
}

func liveAt(m *manifest.Manifest) string {
	hosts := m.Hosts()
	if len(hosts) == 0 {
		return ""
	}
	return " at https://" + hosts[0]
}

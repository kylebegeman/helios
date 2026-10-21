package docker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/moby/moby/client"
)

// HelperImage runs small jobs against volumes: listing, restoring, chowning.
const HelperImage = "alpine:3.21"

// VolumeName names an app's volume.
func VolumeName(app, volume string) string { return "bedrock-" + app + "-" + volume }

// AppVolume is the name an app's manifest gives a Docker volume: the
// inverse of VolumeName, or the volume's own name when it isn't the app's.
func AppVolume(app, volume string) string {
	if name, ok := strings.CutPrefix(volume, "bedrock-"+app+"-"); ok && name != "" {
		return name
	}
	return volume
}

// EnsureVolume creates a named volume if it doesn't exist.
func (e *Engine) EnsureVolume(ctx context.Context, name string) error {
	res, err := e.cli.VolumeCreate(ctx, client.VolumeCreateOptions{Name: name, Labels: map[string]string{LabelOwner: OwnerValue}})
	if err != nil {
		return fmt.Errorf("volume %s: %w", name, err)
	}
	// Docker returns an existing volume without changing its labels. Older
	// Helios containers implicitly created unlabeled volumes; keep those,
	// but never mount or change one another system explicitly owns.
	if owner := res.Volume.Labels[LabelOwner]; owner != "" && owner != OwnerValue {
		return fmt.Errorf("volume %s belongs to another owner", name)
	}
	return nil
}

// ensureHelper pulls the helper image once.
func (e *Engine) ensureHelper(ctx context.Context) error {
	if e.HasImage(ctx, HelperImage) {
		return nil
	}
	return e.Pull(ctx, HelperImage, io.Discard)
}

// VolumeEmpty reports whether a volume holds nothing.
func (e *Engine) VolumeEmpty(ctx context.Context, name string) (bool, error) {
	if err := e.ensureHelper(ctx); err != nil {
		return false, err
	}
	out, err := cliOutput(ctx, nil, "docker", "run", "--rm", "-v", name+":/v:ro", HelperImage, "sh", "-c", "ls -A /v | head -1")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == "", nil
}

// RestoreVolume unpacks a .tar.gz into a volume.
func (e *Engine) RestoreVolume(ctx context.Context, name, tarball string) error {
	if err := e.ensureHelper(ctx); err != nil {
		return err
	}
	abs, err := filepath.Abs(tarball)
	if err != nil {
		return err
	}
	if _, err := os.Stat(abs); err != nil {
		return err
	}
	args := []string{"run", "--rm", "-v", name + ":/v", "-v", filepath.Dir(abs) + ":/backup:ro", HelperImage,
		"tar", "xzf", "/backup/" + filepath.Base(abs), "-C", "/v", "--no-same-owner"}
	// An archive of a Docker volume's directory itself (tar -C volumes/x
	// _data) wraps everything in _data/; unwrap it.
	if wrappedInData(ctx, abs) {
		args = append(args, "--strip-components=1")
	}
	if _, err := cliOutput(ctx, nil, "docker", args...); err != nil {
		return fmt.Errorf("restore %s: %w", name, err)
	}
	return nil
}

// wrappedInData reports whether every entry of a tarball sits under _data/.
func wrappedInData(ctx context.Context, tarball string) bool {
	out, err := cliOutput(ctx, nil, "tar", "tzf", tarball)
	if err != nil || out == "" {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		if line != "_data/" && !strings.HasPrefix(line, "_data/") {
			return false
		}
	}
	return true
}

// ImageUser returns the user an image runs as, as its config says.
func (e *Engine) ImageUser(ctx context.Context, ref string) (string, error) {
	res, err := e.cli.ImageInspect(ctx, ref)
	if err != nil {
		return "", err
	}
	if res.Config == nil {
		return "", nil
	}
	return res.Config.User, nil
}

// ExecToEnv runs a command in a running container, streaming its stdout to
// w, with environment variables for the command. Their values reach docker
// through its environment, never its arguments, which any user of the
// machine can read. The command's stderr comes back as text, for errors.
func (e *Engine) ExecToEnv(ctx context.Context, container string, env map[string]string, w io.Writer, cmd ...string) (string, error) {
	c := exec.CommandContext(ctx, "docker", execArgs(container, env, false, cmd)...)
	c.Env = execEnv(env)
	var stderr bytes.Buffer
	c.Stdout, c.Stderr = w, &stderr
	err := c.Run()
	text := strings.TrimSpace(stderr.String())
	if err != nil {
		lines := strings.Split(text, "\n")
		return text, fmt.Errorf("%s: %s", err, lines[len(lines)-1])
	}
	return text, nil
}

// execArgs builds a docker exec command line that names env's variables
// without their values.
func execArgs(container string, env map[string]string, stdin bool, cmd []string) []string {
	args := []string{"exec"}
	if stdin {
		args = append(args, "-i")
	}
	names := make([]string, 0, len(env))
	for k := range env {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		args = append(args, "-e", k)
	}
	return append(append(args, container), cmd...)
}

// execEnv is docker's own environment plus env; nil keeps the default.
func execEnv(env map[string]string) []string {
	if len(env) == 0 {
		return nil
	}
	out := os.Environ()
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}

// VolumeMountpoint is where a volume's files live on the machine.
func (e *Engine) VolumeMountpoint(ctx context.Context, name string) (string, error) {
	res, err := e.cli.VolumeInspect(ctx, name, client.VolumeInspectOptions{})
	if err != nil {
		return "", err
	}
	return res.Volume.Mountpoint, nil
}

// Exec runs a command in a running container and returns its output.
func (e *Engine) Exec(ctx context.Context, container string, stdin io.Reader, cmd ...string) (string, error) {
	return e.ExecEnv(ctx, container, nil, stdin, cmd...)
}

// ExecEnv is Exec with environment variables for the command, kept out
// of every process's arguments as ExecToEnv keeps them.
func (e *Engine) ExecEnv(ctx context.Context, container string, env map[string]string, stdin io.Reader, cmd ...string) (string, error) {
	c := exec.CommandContext(ctx, "docker", execArgs(container, env, stdin != nil, cmd)...)
	c.Env = execEnv(env)
	c.Stdin = stdin
	out, err := c.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		lines := strings.Split(text, "\n")
		return text, fmt.Errorf("%s: %s", err, lines[len(lines)-1])
	}
	return text, nil
}

// ExitCode returns a stopped container's exit code, or -1 while it runs.
func (e *Engine) ExitCode(ctx context.Context, name string) (int, bool, error) {
	res, err := e.cli.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	if err != nil {
		return 0, false, err
	}
	if res.Container.State == nil || res.Container.State.Running {
		return -1, false, nil
	}
	return res.Container.State.ExitCode, true, nil
}

// WaitExit polls until a container stops or the context ends.
func (e *Engine) WaitExit(ctx context.Context, name string) (int, error) {
	for {
		code, done, err := e.ExitCode(ctx, name)
		if err != nil {
			return -1, err
		}
		if done {
			return code, nil
		}
		select {
		case <-ctx.Done():
			return -1, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// LogTail returns the last lines of a container's output.
func (e *Engine) LogTail(ctx context.Context, name string, lines int) string {
	var buf bytes.Buffer
	_ = e.Logs(ctx, name, LogOptions{Tail: fmt.Sprint(lines)}, &buf)
	return buf.String()
}

func cliOutput(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = stdin
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		lines := strings.Split(text, "\n")
		return text, fmt.Errorf("%s: %s", err, lines[len(lines)-1])
	}
	return text, nil
}

// Volumes lists the names of the volumes whose names start with prefix,
// sorted. Helios labels the volumes it makes, but Docker makes one
// without a label when a container mounts a name that isn't there yet,
// so the name is what is matched.
func (e *Engine) Volumes(ctx context.Context, prefix string) ([]string, error) {
	res, err := e.cli.VolumeList(ctx, client.VolumeListOptions{})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, v := range res.Items {
		if strings.HasPrefix(v.Name, prefix) {
			out = append(out, v.Name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// RemoveVolume deletes a volume and reports whether there was one.
func (e *Engine) RemoveVolume(ctx context.Context, name string) (bool, error) {
	_, err := e.cli.VolumeRemove(ctx, name, client.VolumeRemoveOptions{Force: true})
	if IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("remove volume %s: %w", name, err)
	}
	return true, nil
}

// RemoveNetwork deletes a network. Missing is fine.
func (e *Engine) RemoveNetwork(ctx context.Context, name string) error {
	_, err := e.cli.NetworkRemove(ctx, name, client.NetworkRemoveOptions{})
	if err != nil && !IsNotFound(err) {
		return fmt.Errorf("remove network %s: %w", name, err)
	}
	return nil
}

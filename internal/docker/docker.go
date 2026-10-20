// Package docker is helios's view of the Docker Engine: containers,
// networks and images it owns, named readably and labeled so nothing else
// is ever touched. Builds go through the docker CLI, everything else
// through the Engine API.
package docker

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

// Labels helios puts on everything it creates.
const (
	LabelOwner    = "bedrock.owner"
	LabelApp      = "bedrock.app"
	LabelWorkload = "bedrock.workload"
	LabelRevision = "bedrock.revision"
	OwnerValue    = "bedrock"
)

// EdgeNetwork is the network the edge and every routed workload share.
const EdgeNetwork = "bedrock-edge"

// Engine is a connection to the local Docker daemon.
type Engine struct {
	cli *client.Client
}

// Connect opens the connection. It fails only when Docker isn't there.
func Connect(ctx context.Context) (*Engine, error) {
	cli, err := client.New(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("docker: %w", err)
	}
	if _, err := cli.Ping(ctx, client.PingOptions{}); err != nil {
		cli.Close()
		return nil, fmt.Errorf("docker isn't answering: %w", err)
	}
	return &Engine{cli: cli}, nil
}

// Close releases the connection.
func (e *Engine) Close() error { return e.cli.Close() }

// AppNetwork names an app's own network.
func AppNetwork(app string) string { return "bedrock-" + app }

// ContainerName names a workload's container for one revision.
func ContainerName(app, workload, revision string) string {
	return "bedrock-" + app + "-" + workload + "-" + revision
}

// NetworkExists reports whether the exact network name is already in use.
func (e *Engine) NetworkExists(ctx context.Context, name string) (bool, error) {
	_, err := e.cli.NetworkInspect(ctx, name, client.NetworkInspectOptions{})
	if IsNotFound(err) {
		return false, nil
	}
	return err == nil, err
}

// EnsureNetwork creates a bridge network if it doesn't exist.
func (e *Engine) EnsureNetwork(ctx context.Context, name string) error {
	return e.ensureNetwork(ctx, name, false)
}

// EnsureInternalNetwork isolates recovery workloads from outbound traffic.
// Their restored queues must not send mail or mutate external services.
func (e *Engine) EnsureInternalNetwork(ctx context.Context, name string) error {
	return e.ensureNetwork(ctx, name, true)
}

func (e *Engine) ensureNetwork(ctx context.Context, name string, internal bool) error {
	check := func() error {
		n, err := e.cli.NetworkInspect(ctx, name, client.NetworkInspectOptions{})
		if err != nil {
			return err
		}
		if n.Network.Labels[LabelOwner] != OwnerValue {
			return fmt.Errorf("network %s belongs to another owner", name)
		}
		if n.Network.Internal != internal {
			return fmt.Errorf("network %s has internal=%t; expected internal=%t", name, n.Network.Internal, internal)
		}
		return nil
	}
	if err := check(); !IsNotFound(err) {
		return err
	}
	_, err := e.cli.NetworkCreate(ctx, name, client.NetworkCreateOptions{
		Driver:   "bridge",
		Internal: internal,
		Labels:   map[string]string{LabelOwner: OwnerValue},
	})
	if errdefs.IsConflict(err) {
		// A concurrent creator may have claimed the name for a different
		// owner or isolation mode. Verify it before joining any workload.
		return check()
	}
	if err != nil {
		return fmt.Errorf("create network %s: %w", name, err)
	}
	return nil
}

// ConnectNetwork joins a container to a network. Already joined is fine.
func (e *Engine) ConnectNetwork(ctx context.Context, containerName, networkName string) error {
	_, err := e.cli.NetworkConnect(ctx, networkName, client.NetworkConnectOptions{Container: containerName, EndpointConfig: &network.EndpointSettings{}})
	if err != nil && !strings.Contains(err.Error(), "already exists") && !errdefs.IsConflict(err) {
		return fmt.Errorf("connect %s to %s: %w", containerName, networkName, err)
	}
	return nil
}

// DisconnectNetwork takes a container off a network. Not joined, or no
// such network, is fine.
func (e *Engine) DisconnectNetwork(ctx context.Context, containerName, networkName string) error {
	_, err := e.cli.NetworkDisconnect(ctx, networkName, client.NetworkDisconnectOptions{Container: containerName, Force: true})
	if err != nil && !IsNotFound(err) && !strings.Contains(err.Error(), "is not connected") {
		return fmt.Errorf("disconnect %s from %s: %w", containerName, networkName, err)
	}
	return nil
}

// Networks lists the networks helios made whose names start with prefix.
func (e *Engine) Networks(ctx context.Context, prefix string) ([]string, error) {
	res, err := e.cli.NetworkList(ctx, client.NetworkListOptions{})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range res.Items {
		if n.Labels[LabelOwner] == OwnerValue && strings.HasPrefix(n.Name, prefix) {
			out = append(out, n.Name)
		}
	}
	return out, nil
}

// Spec is a container helios wants running.
type Spec struct {
	Name  string
	Image string
	// Entrypoint replaces the image's own; nil keeps it.
	Entrypoint []string
	Cmd        []string
	Env        []string
	Labels     map[string]string
	// Networks the container joins; the first is its primary.
	Networks []string
	// Publish maps host ports, as "127.0.0.1:2019:2019/tcp", "443:443/udp"
	// or "[::1]:8443:8443/tcp".
	Publish []string
	// Mounts as "volume:/path" or "/host/path:/path[:ro]".
	Mounts      []string
	MemoryBytes int64
	NanoCPUs    int64
	// Restart keeps the container running across reboots.
	Restart bool
	// HostNetwork puts the container on the machine's own network, for
	// helpers that only make outbound connections.
	HostNetwork bool
	// User overrides the image's user.
	User string
	// Isolated drops every capability and forbids gaining privileges,
	// except the ones in Capabilities. Privileged does the opposite.
	Isolated     bool
	Capabilities []string
	Privileged   bool
	// ReadOnly makes the root filesystem read-only; Tmpfs are writable
	// in-memory paths (/tmp comes with ReadOnly).
	ReadOnly bool
	Tmpfs    []string
	// PidsLimit bounds the processes in the container; 0 means the default.
	PidsLimit int64
	// Aliases are more names the container answers to on its first network.
	Aliases []string
	// Stdin, when set, is copied to the container's standard input, which
	// is closed at its end.
	Stdin io.Reader
	// NoHealthcheck turns off the image's own HEALTHCHECK, for a container
	// whose health helios checks its own way.
	NoHealthcheck bool
}

// DefaultPidsLimit bounds every isolated container's processes.
const DefaultPidsLimit int64 = 4096

// Run creates and starts a container, or starts it if it already exists.
func (e *Engine) Run(ctx context.Context, spec Spec) error {
	if info, err := e.Inspect(ctx, spec.Name); err == nil {
		if info.Labels[LabelOwner] != OwnerValue {
			return fmt.Errorf("container %s belongs to another owner", spec.Name)
		}
		for name, expected := range spec.Labels {
			if info.Labels[name] != expected {
				return fmt.Errorf("container %s has another %s identity", spec.Name, name)
			}
		}
		// Creation may have stopped after connecting only some networks.
		// Complete the requested attachments before adopting or starting it.
		for _, name := range spec.Networks {
			if err := e.ConnectNetwork(ctx, info.ID, name); err != nil {
				return err
			}
		}
		if info.Running {
			return nil
		}
		if spec.Stdin != nil {
			return e.startAttached(ctx, info.ID, spec)
		}
		_, err := e.cli.ContainerStart(ctx, info.ID, client.ContainerStartOptions{})
		return err
	} else if !IsNotFound(err) {
		return fmt.Errorf("inspect %s: %w", spec.Name, err)
	}
	hostConfig, exposed, err := hostConfigFor(spec)
	if err != nil {
		return err
	}
	endpoints := map[string]*network.EndpointSettings{}
	if len(spec.Networks) > 0 {
		endpoints[spec.Networks[0]] = &network.EndpointSettings{Aliases: spec.Aliases}
	}
	created, err := e.cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name:             spec.Name,
		Config:           containerConfigFor(spec, exposed),
		HostConfig:       hostConfig,
		NetworkingConfig: &network.NetworkingConfig{EndpointsConfig: endpoints},
	})
	if err != nil {
		return fmt.Errorf("create %s: %w", spec.Name, err)
	}
	for _, extra := range spec.Networks[min(1, len(spec.Networks)):] {
		if _, err := e.cli.NetworkConnect(ctx, extra, client.NetworkConnectOptions{Container: created.ID, EndpointConfig: &network.EndpointSettings{}}); err != nil {
			return fmt.Errorf("connect %s to %s: %w", spec.Name, extra, err)
		}
	}
	if spec.Stdin != nil {
		return e.startAttached(ctx, created.ID, spec)
	}
	if _, err := e.cli.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("start %s: %w", spec.Name, err)
	}
	return nil
}

// journalSocket is where journald takes logs on a machine that runs it.
const journalSocket = "/run/systemd/journal/socket"

// journaldListening reports whether the machine's journald takes logs.
// Tests replace it.
var journaldListening = func() bool {
	_, err := os.Stat(journalSocket)
	return err == nil
}

// hostConfigFor is how Docker is to run a spec: its mounts, limits and
// privileges, where it logs, and the ports it publishes, which the
// container also exposes.
func hostConfigFor(spec Spec) (*container.HostConfig, network.PortSet, error) {
	hostConfig := &container.HostConfig{
		Binds:          spec.Mounts,
		LogConfig:      container.LogConfig{Type: "json-file", Config: map[string]string{"max-size": "20m", "max-file": "5"}},
		Resources:      container.Resources{Memory: spec.MemoryBytes, NanoCPUs: spec.NanoCPUs},
		ReadonlyRootfs: spec.ReadOnly,
		Privileged:     spec.Privileged,
	}
	// An app's workloads and jobs, the containers labeled with a
	// revision, log to the journal, so what they wrote outlives them.
	// Each line carries the container's name and whose it is.
	if spec.Labels[LabelRevision] != "" && journaldListening() {
		hostConfig.LogConfig = container.LogConfig{Type: "journald", Config: map[string]string{
			"tag":    "{{.Name}}",
			"labels": strings.Join([]string{LabelApp, LabelWorkload, LabelRevision}, ","),
		}}
	}
	if !spec.Privileged {
		hostConfig.SecurityOpt = []string{"no-new-privileges"}
	}
	if spec.Isolated && !spec.Privileged {
		hostConfig.CapDrop = []string{"ALL"}
		hostConfig.CapAdd = spec.Capabilities
		pids := spec.PidsLimit
		if pids == 0 {
			pids = DefaultPidsLimit
		}
		hostConfig.Resources.PidsLimit = &pids
	} else if spec.PidsLimit > 0 {
		// A privileged container keeps a bound it asked for.
		pids := spec.PidsLimit
		hostConfig.Resources.PidsLimit = &pids
	}
	if spec.ReadOnly || len(spec.Tmpfs) > 0 {
		hostConfig.Tmpfs = map[string]string{}
		if spec.ReadOnly {
			hostConfig.Tmpfs["/tmp"] = "rw,nosuid"
		}
		for _, t := range spec.Tmpfs {
			hostConfig.Tmpfs[t] = "rw,nosuid"
		}
	}
	if spec.Restart {
		hostConfig.RestartPolicy = container.RestartPolicy{Name: container.RestartPolicyUnlessStopped}
	}
	if spec.HostNetwork {
		hostConfig.NetworkMode = "host"
	}
	exposed := network.PortSet{}
	if len(spec.Publish) > 0 {
		hostConfig.PortBindings = network.PortMap{}
		for _, p := range spec.Publish {
			port, binding, err := parsePublish(p)
			if err != nil {
				return nil, nil, err
			}
			exposed[port] = struct{}{}
			hostConfig.PortBindings[port] = append(hostConfig.PortBindings[port], binding)
		}
	}
	return hostConfig, exposed, nil
}

// containerConfigFor is what the container is: its image, command,
// environment, labels and user.
func containerConfigFor(spec Spec, exposed network.PortSet) *container.Config {
	labels := map[string]string{LabelOwner: OwnerValue}
	for k, v := range spec.Labels {
		labels[k] = v
	}
	config := &container.Config{Image: spec.Image, Entrypoint: spec.Entrypoint, Cmd: spec.Cmd, Env: spec.Env, Labels: labels, ExposedPorts: exposed, User: spec.User}
	if spec.NoHealthcheck {
		config.Healthcheck = &container.HealthConfig{Test: []string{"NONE"}}
	}
	if spec.Stdin != nil {
		config.OpenStdin, config.StdinOnce, config.AttachStdin = true, true, true
	}
	return config
}

// startAttached starts a container with its input attached first, so no
// input is lost, and feeds it spec.Stdin.
func (e *Engine) startAttached(ctx context.Context, id string, spec Spec) error {
	attached, err := e.cli.ContainerAttach(ctx, id, client.ContainerAttachOptions{Stream: true, Stdin: true})
	if err != nil {
		return fmt.Errorf("attach %s: %w", spec.Name, err)
	}
	if _, err := e.cli.ContainerStart(ctx, id, client.ContainerStartOptions{}); err != nil {
		attached.Close()
		return fmt.Errorf("start %s: %w", spec.Name, err)
	}
	go func() {
		defer attached.Close()
		_, _ = io.Copy(attached.Conn, spec.Stdin)
		_ = attached.CloseWrite()
		// Hold the connection until the container has read what it wants;
		// its end closes the stream.
		_, _ = io.Copy(io.Discard, attached.Reader)
	}()
	return nil
}

func parsePublish(spec string) (network.Port, network.PortBinding, error) {
	proto := "tcp"
	if i := strings.LastIndex(spec, "/"); i >= 0 {
		proto = spec[i+1:]
		spec = spec[:i]
	}
	var hostIP, hostPort, containerPort string
	// An IPv6 address carries colons of its own, so it comes in brackets,
	// as in [::1]:8443:8443/tcp.
	if strings.HasPrefix(spec, "[") {
		end := strings.Index(spec, "]:")
		if end < 0 {
			return network.Port{}, network.PortBinding{}, fmt.Errorf("bad port publish %q", spec)
		}
		hostIP, spec = spec[1:end], spec[end+2:]
	}
	parts := strings.Split(spec, ":")
	switch {
	case len(parts) == 2:
		hostPort, containerPort = parts[0], parts[1]
	case len(parts) == 3 && hostIP == "":
		hostIP, hostPort, containerPort = parts[0], parts[1], parts[2]
	default:
		return network.Port{}, network.PortBinding{}, fmt.Errorf("bad port publish %q", spec)
	}
	port, err := network.ParsePort(containerPort + "/" + proto)
	if err != nil {
		return network.Port{}, network.PortBinding{}, err
	}
	binding := network.PortBinding{HostPort: hostPort}
	if hostIP != "" {
		addr, err := netip.ParseAddr(hostIP)
		if err != nil {
			return network.Port{}, network.PortBinding{}, fmt.Errorf("bad host address in %q: %w", spec, err)
		}
		binding.HostIP = addr
	}
	return port, binding, nil
}

// Info is what helios needs to know about a container.
type Info struct {
	ID      string
	Name    string
	Image   string
	Running bool
	Status  string
	Health  string
	// Restarts counts the times Docker restarted it.
	Restarts   int
	ExitCode   int
	StartedAt  time.Time
	FinishedAt time.Time
	// IPs by network.
	IPs    map[string]string
	Labels map[string]string
	// User is who the container runs as, as Docker keeps it; helios sets
	// it as uid:gid.
	User string
	// Volumes are the named volumes it mounts.
	Volumes []VolumeMount
	// Binds are its mounts as it was created with them, such as
	// "/host/path:/path:ro".
	Binds []string
}

// VolumeMount is a named volume mounted into a container, with where it
// lives on the machine.
type VolumeMount struct {
	Name        string
	Source      string
	Destination string
	RW          bool
}

// Inspect describes a container by name or ID.
func (e *Engine) Inspect(ctx context.Context, name string) (*Info, error) {
	res, err := e.cli.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	if err != nil {
		return nil, err
	}
	c := res.Container
	info := &Info{ID: c.ID, Name: strings.TrimPrefix(c.Name, "/"), IPs: map[string]string{}, Restarts: c.RestartCount}
	if c.Config != nil {
		info.Image, info.Labels, info.User = c.Config.Image, c.Config.Labels, c.Config.User
	}
	if c.HostConfig != nil {
		info.Binds = c.HostConfig.Binds
	}
	for _, m := range c.Mounts {
		if m.Type == "volume" {
			info.Volumes = append(info.Volumes, VolumeMount{Name: m.Name, Source: m.Source, Destination: m.Destination, RW: m.RW})
		}
	}
	if c.State != nil {
		info.Running, info.Status, info.ExitCode = c.State.Running, string(c.State.Status), c.State.ExitCode
		info.StartedAt, _ = time.Parse(time.RFC3339Nano, c.State.StartedAt)
		info.FinishedAt, _ = time.Parse(time.RFC3339Nano, c.State.FinishedAt)
		if c.State.Health != nil {
			info.Health = string(c.State.Health.Status)
		}
	}
	if c.NetworkSettings != nil {
		for net, ep := range c.NetworkSettings.Networks {
			if ep == nil {
				continue
			}
			if ep.IPAddress.IsValid() {
				info.IPs[net] = ep.IPAddress.String()
			} else if ep.GlobalIPv6Address.IsValid() {
				info.IPs[net] = ep.GlobalIPv6Address.String()
			}
		}
	}
	return info, nil
}

// IsNotFound reports whether err means the thing doesn't exist.
func IsNotFound(err error) bool { return err != nil && errdefs.IsNotFound(err) }

// Remove stops (within timeout) and removes a container. A missing
// container is fine.
func (e *Engine) Remove(ctx context.Context, name string, timeout time.Duration) error {
	secs := int(timeout.Seconds())
	if _, err := e.cli.ContainerStop(ctx, name, client.ContainerStopOptions{Timeout: &secs}); err != nil && !IsNotFound(err) {
		return fmt.Errorf("stop %s: %w", name, err)
	}
	// Anonymous volumes (an image's VOLUME lines) go with the container;
	// named volumes never do.
	if _, err := e.cli.ContainerRemove(ctx, name, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true}); err != nil && !IsNotFound(err) {
		return fmt.Errorf("remove %s: %w", name, err)
	}
	return nil
}

// Stop stops a container within timeout and keeps it, to start again.
// A missing container is fine.
func (e *Engine) Stop(ctx context.Context, name string, timeout time.Duration) error {
	secs := int(timeout.Seconds())
	if _, err := e.cli.ContainerStop(ctx, name, client.ContainerStopOptions{Timeout: &secs}); err != nil && !IsNotFound(err) {
		return fmt.Errorf("stop %s: %w", name, err)
	}
	return nil
}

// Start starts a stopped container.
func (e *Engine) Start(ctx context.Context, name string) error {
	if _, err := e.cli.ContainerStart(ctx, name, client.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}
	return nil
}

// Owned lists every container helios created, running or not.
func (e *Engine) Owned(ctx context.Context) ([]Info, error) {
	res, err := e.cli.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return nil, err
	}
	var out []Info
	for _, c := range res.Items {
		if c.Labels[LabelOwner] != OwnerValue {
			continue
		}
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		out = append(out, Info{ID: c.ID, Name: name, Image: c.Image, Running: c.State == container.StateRunning, Status: c.Status, Labels: c.Labels})
	}
	return out, nil
}

// Unowned counts containers helios didn't create.
func (e *Engine) Unowned(ctx context.Context) ([]string, error) {
	res, err := e.cli.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return nil, err
	}
	var names []string
	for _, c := range res.Items {
		if c.Labels[LabelOwner] != OwnerValue && len(c.Names) > 0 {
			names = append(names, strings.TrimPrefix(c.Names[0], "/"))
		}
	}
	return names, nil
}

// Logs streams a container's output, stdout and stderr together.
func (e *Engine) Logs(ctx context.Context, name string, follow bool, tail string, w io.Writer) error {
	r, err := e.cli.ContainerLogs(ctx, name, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Follow: follow, Tail: tail, Timestamps: false})
	if err != nil {
		return err
	}
	defer r.Close()
	_, err = stdcopy.StdCopy(w, w, r)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// HasImage reports whether an image is present locally.
func (e *Engine) HasImage(ctx context.Context, ref string) bool {
	_, err := e.cli.ImageInspect(ctx, ref)
	return err == nil
}

// Pull fetches an image and says so on out once it is there; the pull's
// own progress is not worth a step's output.
func (e *Engine) Pull(ctx context.Context, ref string, out io.Writer) error {
	resp, err := e.cli.ImagePull(ctx, ref, client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	defer resp.Close()
	dec := json.NewDecoder(resp)
	for {
		var progress struct {
			Error  string `json:"error"`
			Detail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := dec.Decode(&progress); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("pull %s: %w", ref, err)
		}
		if progress.Error != "" || progress.Detail.Message != "" {
			message := progress.Error
			if message == "" {
				message = progress.Detail.Message
			}
			return fmt.Errorf("pull %s: %s", ref, message)
		}
	}
	fmt.Fprintf(out, "pulled %s\n", ref)
	return nil
}

// Digest returns an immutable image reference. Repository digests survive
// transfer to another machine; an imported or locally built image can instead
// be pinned by its content ID.
func (e *Engine) Digest(ctx context.Context, ref string) (string, error) {
	res, err := e.cli.ImageInspect(ctx, ref)
	if err != nil {
		return "", err
	}
	for _, d := range res.RepoDigests {
		if strings.HasPrefix(d, strings.SplitN(ref, ":", 2)[0]+"@") || strings.HasPrefix(d, repository(ref)+"@") {
			return d, nil
		}
	}
	if len(res.RepoDigests) > 0 {
		return res.RepoDigests[0], nil
	}
	if id, ok := strings.CutPrefix(res.ID, "sha256:"); ok && len(id) == 64 {
		if _, err := hex.DecodeString(id); err == nil {
			return res.ID, nil
		}
	}
	return "", fmt.Errorf("%s has no immutable image reference", ref)
}

// repository strips the tag from an image reference.
func repository(ref string) string {
	if at := strings.Index(ref, "@"); at >= 0 {
		return ref[:at]
	}
	slash := strings.LastIndex(ref, "/")
	if colon := strings.LastIndex(ref, ":"); colon > slash {
		return ref[:colon]
	}
	return ref
}

// RemoveImage deletes an image helios built. Missing is fine.
func (e *Engine) RemoveImage(ctx context.Context, ref string) error {
	_, err := e.cli.ImageRemove(ctx, ref, client.ImageRemoveOptions{})
	if err != nil && !IsNotFound(err) {
		return err
	}
	return nil
}

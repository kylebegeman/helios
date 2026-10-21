package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/kernel"
	"github.com/kylebegeman/helios/internal/restic"
	"github.com/kylebegeman/helios/internal/state"
)

func extractFixture(t *testing.T) (BackupExtract, BackupExtractInput) {
	t.Helper()
	r, _ := recoveryFixture(t)
	if _, _, err := integration.Set(r.Secrets, integration.StorageName, map[string]string{
		"kind": "b2", "endpoint": "", "key_id": "synthetic-id", "key": "target-storage-value", "bucket_prefix": "synthetic", "password": "synthetic-restic-password",
	}); err != nil {
		t.Fatal(err)
	}
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	generation := "/data/volumes/snapshots/generations/g-" + strings.Repeat("c", 32) + "/"
	return BackupExtract{Secrets: r.Secrets, StateDir: r.StateDir}, BackupExtractInput{
		App: "loom-vault-backup", Snapshot: strings.Repeat("a", 64), Destination: filepath.Join(parent, "retrieved"),
		Paths: []string{generation + "snapshot.snap", generation + "completion.json", generation + "receipt"},
	}
}

func extractPlan(t *testing.T, b BackupExtract, in BackupExtractInput) *kernel.Plan {
	t.Helper()
	raw, _ := json.Marshal(in)
	plan, err := b.Plan(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// The mock repository returns newer snapshots too. Selection must use the full
// requested ID and prove host/tag ownership rather than trusting filtering alone.
func extractRepository(t *testing.T, in BackupExtractInput, mutate func(*dockertest.Container, string)) *dockertest.Server {
	t.Helper()
	fake := dockertest.New(t)
	// Exercise the same local Unix transport required by the operator, while all
	// Docker/storage behavior remains synthetic and in process.
	socketDir, err := os.MkdirTemp("", "hx-")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(socketDir, "d"))
	if err != nil {
		os.RemoveAll(socketDir)
		t.Fatal(err)
	}
	server := &http.Server{Handler: fake}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close(); os.RemoveAll(socketDir) })
	t.Setenv("DOCKER_HOST", "unix://"+filepath.Join(socketDir, "d"))

	fake.OnCreate = func(c dockertest.Container) {
		logs := ""
		switch c.Cmd[0] {
		case "snapshots":
			snapshots := []restic.Snapshot{
				{ID: strings.Repeat("b", 64), Hostname: in.App, Tags: []string{restic.Tag}, Paths: []string{restic.DataRoot}},
				{ID: in.Snapshot, Hostname: in.App, Tags: []string{restic.Tag}, Paths: []string{restic.DataRoot}},
			}
			body, _ := json.Marshal(snapshots)
			logs = string(body)
		case "stats":
			logs = `{"total_size":1234,"total_file_count":3}`
		case "restore":
			if c.Cmd[1] != in.Snapshot || !slices.Contains(c.Cmd, "--verify") {
				t.Errorf("restore lost exact identity/verification: %v", c.Cmd)
			}
			for _, selected := range in.Paths {
				if !slices.Contains(c.Cmd, selected) {
					t.Errorf("selection omitted: %s", selected)
				}
			}
			for _, bind := range c.HostConfig.Binds {
				src, dst, _ := strings.Cut(bind, ":")
				if dst == "/data" {
					for _, selected := range in.Paths {
						name := filepath.Join(src, strings.TrimPrefix(selected, "/data/"))
						if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
							t.Error(err)
						}
						if err := os.WriteFile(name, []byte("synthetic "+filepath.Base(name)), 0o644); err != nil {
							t.Error(err)
						}
					}
				}
			}
			// Deliberately misleading counters: only the actual tree proves completeness.
			logs = `{"message_type":"summary","total_files":1,"files_restored":99}`
		default:
			t.Errorf("unexpected storage command: %v", c.Cmd)
		}
		fake.Update(c.Name, func(ct *dockertest.Container) {
			ct.ExitAfter = 1
			ct.Logs = logs
			if mutate != nil {
				mutate(ct, filepath.Join(in.Destination, "payload"))
			}
		})
	}
	return fake
}

func TestBackupExtractValidatesExactInputs(t *testing.T) {
	_, base := extractFixture(t)
	for _, name := range []string{"latest", "prefix", "uppercase", "bad app", "no files", "duplicate", "traversal", "glob", "parent selection", "directory selection", "relative destination", "colon destination"} {
		t.Run(name, func(t *testing.T) {
			in := base
			in.Paths = slices.Clone(base.Paths)
			switch name {
			case "latest":
				in.Snapshot = "latest"
			case "prefix":
				in.Snapshot = in.Snapshot[:8]
			case "uppercase":
				in.Snapshot = strings.Repeat("A", 64)
			case "bad app":
				in.App = "../bedrock"
			case "no files":
				in.Paths = nil
			case "duplicate":
				in.Paths = append(in.Paths, in.Paths[0])
			case "traversal":
				in.Paths[0] = "/data/volumes/../secret"
			case "glob":
				in.Paths[0] = "/data/*"
			case "parent selection":
				in.Paths = append(in.Paths, "/data/volumes")
			case "directory selection":
				in.Paths[0] += "/"
			case "relative destination":
				in.Destination = "relative"
			case "colon destination":
				in.Destination += "x:y"
			}
			if validateExtractInput(in) == nil {
				t.Fatal("unsafe input accepted")
			}
		})
	}
	if err := validateExtractInput(base); err != nil {
		t.Fatal(err)
	}
}

func TestBackupExtractPlanBindsEveryInputWithoutStorageCalls(t *testing.T) {
	b, in := extractFixture(t)
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reg := kernel.Registry{}
	reg.Add(b)
	engine := kernel.New(store, reg, "extract-plan")
	digest := func(in BackupExtractInput) string {
		raw, _ := json.Marshal(in)
		view, err := engine.PlanOnly(context.Background(), b.Kind(), raw)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(view.Steps[0].Change, in.Snapshot) || !strings.Contains(view.Steps[0].Change, in.Destination) {
			t.Fatal("inputs not in Change")
		}
		return view.Digest
	}
	original := digest(in)
	for _, field := range []string{"app", "snapshot", "paths", "destination"} {
		changed := in
		changed.Paths = slices.Clone(in.Paths)
		switch field {
		case "app":
			changed.App = "other-app"
		case "snapshot":
			changed.Snapshot = strings.Repeat("d", 64)
		case "paths":
			changed.Paths[0] += ".other"
		case "destination":
			changed.Destination += "-other"
		}
		if digest(changed) == original {
			t.Errorf("%s omitted from digest", field)
		}
		if _, err := engine.RunExpecting(context.Background(), b.Kind(), mustExtractJSON(changed), original, func(kernel.Event) {}); !errors.Is(err, kernel.ErrPlanChanged) {
			t.Fatalf("%s changed input was not fenced by kernel: %v", field, err)
		}
	}
	if _, err := os.Lstat(in.Destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("plan created staging")
	}
	raw, _ := json.Marshal(in)
	raw = append(raw, []byte(" {}")...)
	if _, err := b.Plan(context.Background(), raw); err == nil {
		t.Fatal("trailing metadata accepted")
	}
}

func TestBackupExtractCopiesExactFilesWithoutTouchingLiveResources(t *testing.T) {
	b, in := extractFixture(t)
	roomToRestore(t)
	var helpers []dockertest.Container
	fake := extractRepository(t, in, func(c *dockertest.Container, _ string) { helpers = append(helpers, *c) })
	liveVolume := docker.VolumeName(in.App, "snapshots")
	fake.AddVolume(liveVolume, nil)
	if err := os.MkdirAll(fake.VolumeDir(liveVolume), 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(fake.VolumeDir(liveVolume), "live")
	if err := os.WriteFile(sentinel, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake.Add(dockertest.Container{Name: "bedrock-loom-vault-idle", Running: true})
	fake.Add(dockertest.Container{Name: "bedrock-loom-vault-backup-idle", Running: true})
	var out bytes.Buffer
	plan := extractPlan(t, b, in)
	if err := plan.Steps[0].Apply(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(in.Destination, "extraction.json"))
	if err != nil {
		t.Fatal(err)
	}
	var receipt extractReceipt
	if json.Unmarshal(body, &receipt) != nil || receipt.SchemaVersion != 1 || receipt.State != "extracted" || !receipt.Verified || receipt.Snapshot != in.Snapshot || receipt.App != in.App || len(receipt.Files) != 3 {
		t.Fatalf("invalid receipt: %s", body)
	}
	for _, file := range receipt.Files {
		content, err := os.ReadFile(filepath.Join(in.Destination, "payload", strings.TrimPrefix(file.Path, "/data/")))
		if err != nil {
			t.Fatal(err)
		}
		checksum := sha256.Sum256(content)
		if file.Size != int64(len(content)) || file.SHA256 != hex.EncodeToString(checksum[:]) {
			t.Fatal("receipt does not match retrieved bytes")
		}
		info, _ := os.Stat(filepath.Join(in.Destination, "payload", strings.TrimPrefix(file.Path, "/data/")))
		if info.Mode().Perm() != 0o600 {
			t.Fatal("retrieved file not protected")
		}
	}
	if strings.Contains(out.String(), "synthetic") || strings.Contains(out.String(), "target-storage-value") || strings.Contains(out.String(), "storage.example.test") {
		t.Fatal("private contents/settings leaked")
	}
	for _, helper := range helpers {
		if !slices.Contains(helper.Env, "RESTIC_REPOSITORY=b2:synthetic-"+in.App+":/") {
			t.Fatal("did not reuse app B2 repository")
		}
		for _, value := range helper.Env {
			if strings.Contains(value, "target-storage-value") || strings.Contains(value, "synthetic-restic-password") {
				t.Fatal("credential in Docker configuration")
			}
		}
		for _, bind := range helper.HostConfig.Binds {
			if bind != restic.DirMount(filepath.Join(in.Destination, "payload"), false) && bind != restic.CacheVolume+":/cache" && !strings.HasSuffix(bind, ":/run/bedrock-restic:ro") {
				t.Fatalf("unexpected helper mount: %s", bind)
			}
			if strings.Contains(bind, liveVolume) {
				t.Fatalf("live volume mounted: %s", bind)
			}
			if strings.HasSuffix(bind, ":/data") && bind != restic.DirMount(filepath.Join(in.Destination, "payload"), false) {
				t.Fatalf("nonstaging data mount: %s", bind)
			}
		}
	}
	for _, name := range []string{"bedrock-loom-vault-idle", "bedrock-loom-vault-backup-idle"} {
		c, ok := fake.Container(name)
		if !ok || !c.Running {
			t.Fatalf("live container changed: %s", name)
		}
	}
	content, _ := os.ReadFile(sentinel)
	if string(content) != "untouched" {
		t.Fatal("live data changed")
	}
	calls := len(fake.Calls())
	if err := plan.Steps[0].Apply(context.Background(), io.Discard); err == nil {
		t.Fatal("existing destination reused")
	}
	if len(fake.Calls()) != calls {
		t.Fatal("retry called Docker")
	}
}

func TestBackupExtractFencesIncompleteAndRedactsFailures(t *testing.T) {
	for _, failure := range []string{"wrong host", "wrong tag", "ambiguous", "repository", "missing", "extra", "link", "restore"} {
		t.Run(failure, func(t *testing.T) {
			b, in := extractFixture(t)
			roomToRestore(t)
			extractRepository(t, in, func(c *dockertest.Container, payload string) {
				if c.Cmd[0] == "snapshots" {
					var snapshots []restic.Snapshot
					_ = json.Unmarshal([]byte(c.Logs), &snapshots)
					switch failure {
					case "wrong host":
						snapshots[1].Hostname = "other-app"
					case "wrong tag":
						snapshots[1].Tags = nil
					case "ambiguous":
						snapshots = append(snapshots, snapshots[1])
					case "repository":
						c.Logs = "Fatal: target-storage-value at storage.example.test"
						c.ExitCode = 1
						return
					}
					body, _ := json.Marshal(snapshots)
					c.Logs = string(body)
				}
				if c.Cmd[0] == "restore" {
					name := filepath.Join(payload, strings.TrimPrefix(in.Paths[0], "/data/"))
					switch failure {
					case "missing":
						_ = os.Remove(name)
					case "extra":
						_ = os.WriteFile(filepath.Join(payload, "extra"), nil, 0o600)
					case "link":
						_ = os.Remove(name)
						_ = os.Symlink("/etc/passwd", name)
					case "restore":
						c.ExitCode = 1
						c.Logs = "Fatal: target-storage-value at storage.example.test"
					}
				}
			})
			err := extractPlan(t, b, in).Steps[0].Apply(context.Background(), io.Discard)
			if err == nil {
				t.Fatal("unsafe extraction succeeded")
			}
			if strings.Contains(err.Error(), "target-storage-value") || strings.Contains(err.Error(), "storage.example.test") {
				t.Fatalf("raw error leaked: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(in.Destination, "extraction.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed extraction has success receipt")
			}
			if slices.Contains([]string{"missing", "extra", "link", "restore"}, failure) {
				if _, err := os.Stat(filepath.Join(in.Destination, "incomplete.json")); err != nil {
					t.Fatal("ambiguity fence missing", err)
				}
				if _, err := b.Plan(context.Background(), mustExtractJSON(in)); err == nil {
					t.Fatal("incomplete destination can be retried")
				}
			}
		})
	}
}

func mustExtractJSON(in BackupExtractInput) json.RawMessage { body, _ := json.Marshal(in); return body }

func TestBackupExtractProtectsDestinationAndVolumeBoundaries(t *testing.T) {
	for _, failure := range []string{"existing", "public parent", "symlink parent", "state", "volume", "space"} {
		t.Run(failure, func(t *testing.T) {
			b, in := extractFixture(t)
			roomToRestore(t)
			fake := extractRepository(t, in, nil)
			switch failure {
			case "existing":
				_ = os.Mkdir(in.Destination, 0o700)
			case "public parent":
				_ = os.Chmod(filepath.Dir(in.Destination), 0o755)
			case "symlink parent":
				link := filepath.Join(filepath.Dir(in.Destination), "link")
				_ = os.Symlink(filepath.Dir(in.Destination), link)
				in.Destination = filepath.Join(link, "new")
			case "state":
				b.StateDir = filepath.Dir(in.Destination)
			case "volume":
				fake.AddVolume("bedrock-other-data", nil)
				_ = os.MkdirAll(fake.VolumeDir("bedrock-other-data"), 0o700)
				in.Destination = filepath.Join(fake.VolumeDir("bedrock-other-data"), "new")
			case "space":
				onDisks(t, func(string) (disk, error) { return disk{dev: 1, free: 1}, nil })
			}
			raw := mustExtractJSON(in)
			plan, err := b.Plan(context.Background(), raw)
			if err == nil {
				err = plan.Steps[0].Apply(context.Background(), io.Discard)
			}
			if err == nil {
				t.Fatal("unsafe destination accepted")
			}
			if _, err := os.Stat(filepath.Join(in.Destination, "extraction.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unsafe destination has receipt")
			}
		})
	}
}

func TestBackupExtractCancelledRestoreRemainsFenced(t *testing.T) {
	b, in := extractFixture(t)
	roomToRestore(t)
	helperIDs := map[string]bool{}
	fake := extractRepository(t, in, func(c *dockertest.Container, _ string) {
		helperIDs[c.ID] = true
		if c.Cmd[0] == "restore" {
			c.ExitAfter = 0
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := extractPlan(t, b, in).Steps[0].Apply(ctx, io.Discard); err == nil {
		t.Fatal("cancelled restore succeeded")
	}
	if _, err := os.Stat(filepath.Join(in.Destination, "incomplete.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(in.Destination, "extraction.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled restore has success receipt")
	}
	for _, call := range fake.Calls() {
		if strings.Contains(call, "/stop") && !helperIDs[strings.Split(call, "/")[2]] {
			t.Fatalf("stopped nonhelper: %s", call)
		}
	}
}

func TestBackupExtractVerifierRejectsHardlinksAndOversize(t *testing.T) {
	for _, kind := range []string{"hardlink", "oversize", "directory", "fifo", "missing"} {
		t.Run(kind, func(t *testing.T) {
			payload := t.TempDir()
			name := filepath.Join(payload, "file")
			if err := os.WriteFile(name, []byte("synthetic"), 0o600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "hardlink":
				if err := os.Link(name, filepath.Join(t.TempDir(), "alias")); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				f, _ := os.OpenFile(name, os.O_WRONLY, 0)
				if err := f.Truncate(extractMaxBytes + 1); err != nil {
					t.Fatal(err)
				}
				f.Close()
			case "directory":
				_ = os.Remove(name)
				_ = os.Mkdir(name, 0o700)
			case "fifo":
				_ = os.Remove(name)
				if err := unix.Mkfifo(name, 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				_ = os.Remove(name)
			}
			if _, err := verifyExtracted(context.Background(), payload, []string{"/data/file"}); err == nil {
				t.Fatal("unsafe/missing file accepted")
			}
		})
	}
}

func TestBackupExtractRejectsRemoteDockerBeforeContact(t *testing.T) {
	b, in := extractFixture(t)
	t.Setenv("DOCKER_HOST", "tcp://unreachable.example.test:2376")
	err := extractPlan(t, b, in).Steps[0].Apply(context.Background(), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "local Docker Unix socket") {
		t.Fatalf("remote Docker not rejected: %v", err)
	}
}

func TestBackupExtractVerifierRejectsSymlinkRoot(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyExtracted(context.Background(), link, []string{"/data/file"}); err == nil {
		t.Fatal("symlink root accepted")
	}
}

func TestBackupExtractVolumeBoundaryIncludesFilesystemRoot(t *testing.T) {
	for _, c := range []struct {
		candidate, root string
		inside          bool
	}{
		{"/private/staging", "/", true}, {"/private/staging", "/private", true},
		{"/private", "/private", true}, {"/private-other", "/private", false},
	} {
		if extractWithin(c.candidate, c.root) != c.inside {
			t.Fatalf("incorrect boundary for %s under %s", c.candidate, c.root)
		}
	}
}

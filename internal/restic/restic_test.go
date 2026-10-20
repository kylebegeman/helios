package restic

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/docker/dockertest"
)

const summary = `{"message_type":"summary"}` + "\n"

// runner is a Runner on the stand-in, with a password and credentials a
// shell would trip over if they were quoted wrong.
func runner(t *testing.T) Runner {
	t.Helper()
	e, err := docker.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return Runner{Engine: e, Owner: "test", Repo: Repo{Repository: "s3:http://store/lane-test", Password: "pa'ss word", Env: []string{"AWS_ACCESS_KEY_ID=id", "AWS_SECRET_ACCESS_KEY=s3cret"}}}
}

// polls counts how often the stand-in was asked about restic's container.
func polls(fake *dockertest.Server) int {
	n := 0
	for _, call := range fake.Calls() {
		if strings.HasPrefix(call, "GET /containers/bedrock-test-restic") && strings.HasSuffix(call, "/json") {
			n++
		}
	}
	return n
}

func TestRunReadsTheOutputAndRemovesTheContainerOnceAfterItExits(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		name := "after it exits"
		if cancelled {
			name = "when the wait is cancelled"
		}
		t.Run(name, func(t *testing.T) {
			fake := dockertest.New(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fake.OnCreate = func(c dockertest.Container) {
				fake.Update(c.Name, func(c *dockertest.Container) {
					c.Logs = summary
					if !cancelled {
						c.ExitAfter = 2
					}
				})
			}
			if cancelled {
				go func() {
					for polls(fake) < 2 {
						time.Sleep(10 * time.Millisecond)
					}
					cancel()
				}()
			}
			lines, err := runner(t).run(ctx, nil, "snapshots", "--json")
			if cancelled {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("a cancelled wait should say so: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(lines, strings.TrimSpace(summary)) {
				t.Fatalf("the container's output was not read: %q", lines)
			}
			deletes := 0
			for _, c := range fake.Calls() {
				if strings.HasPrefix(c, "DELETE ") {
					deletes++
				}
			}
			if deletes != 1 {
				t.Fatalf("the container was removed %d times: %v", deletes, fake.Calls())
			}
			poll := fake.Last(func(c string) bool { return strings.Contains(c, "/containers/") && strings.HasSuffix(c, "/json") })
			logs := fake.Last(func(c string) bool { return strings.HasSuffix(c, "/logs") })
			removal := fake.Last(func(c string) bool { return strings.HasPrefix(c, "DELETE ") })
			if !(poll < logs && logs < removal) {
				t.Fatalf("output read and removal must follow the last poll: %v", fake.Calls())
			}
		})
	}
}

func TestTheRepositoryPasswordNeverReachesTheContainersEnvironment(t *testing.T) {
	fake := dockertest.New(t)
	var created dockertest.Container
	var mounted string
	resticSaw := func(c dockertest.Container) {
		created = c
		for _, bind := range c.HostConfig.Binds {
			if src, dst, _ := strings.Cut(bind, ":"); strings.HasPrefix(dst, secretsInside) {
				data, err := os.ReadFile(filepath.Join(src, "env"))
				if err != nil {
					t.Errorf("the secrets file isn't there while the container is: %v", err)
				}
				mounted = src
				if info, err := os.Stat(filepath.Join(src, "env")); err == nil && info.Mode().Perm() != 0o600 {
					t.Errorf("the secrets file is %v, not 0600", info.Mode().Perm())
				}
				if !strings.Contains(string(data), "AWS_SECRET_ACCESS_KEY='s3cret'") {
					t.Errorf("the secrets file lacks the credentials: %q", data)
				}
			}
		}
	}
	fake.OnCreate = func(c dockertest.Container) {
		resticSaw(c)
		fake.Update(c.Name, func(c *dockertest.Container) { c.Logs, c.ExitAfter = summary, 1 })
	}
	lines, err := runner(t).run(context.Background(), nil, "snapshots", "--json")
	if err != nil {
		t.Fatalf("%v %q", err, lines)
	}
	for _, kv := range created.Env {
		if strings.Contains(kv, "pa'ss word") || strings.Contains(kv, "s3cret") {
			t.Fatalf("a secret is in the container's environment: %q", kv)
		}
	}
	if mounted == "" || created.Entrypoint[0] != "/bin/sh" {
		t.Fatalf("no secrets mount, or restic isn't started through the shell that reads it: %+v", created)
	}
	if _, err := os.Stat(mounted); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the secrets file outlived the run: %v", err)
	}
}

func TestTheSecretsFileGivesAShellTheValuesAsTheyWere(t *testing.T) {
	values := []string{"plain", "pa'ss word", `back\slash "and" $dollar`, "new\nline", "trailing'"}
	var pairs []string
	for i, v := range values {
		pairs = append(pairs, "V"+string(rune('A'+i))+"="+v)
	}
	dir, err := secretsFile(pairs)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	for i, want := range values {
		name := "V" + string(rune('A'+i))
		out, err := exec.Command("/bin/sh", "-c", `set -a && . "$1" && set +a && printf %s "$`+name+`"`, "sh", filepath.Join(dir, "env")).Output()
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != want {
			t.Fatalf("%s: the shell read %q, not %q", name, out, want)
		}
	}
}

func TestReleaseCheckpointTagsAreCapturedAndKeptByRetention(t *testing.T) {
	fake := dockertest.New(t)
	var commands [][]string
	fake.OnCreate = func(c dockertest.Container) {
		commands = append(commands, append([]string(nil), c.Cmd...))
		fake.Update(c.Name, func(c *dockertest.Container) {
			c.ExitAfter = 1
			if c.Cmd[0] == "backup" {
				c.Logs = `{"message_type":"summary","snapshot_id":"` + strings.Repeat("a", 64) + `"}`
			} else {
				c.Logs = `[]`
			}
		})
	}
	r := runner(t)
	r.BackupTags = []string{ReleaseCheckpointTag}
	if _, err := r.Backup(context.Background(), "site", nil, DataRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Forget(context.Background(), "site", Keep{Daily: 1}); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 3 {
		t.Fatalf("%v", commands)
	}
	hasPair := func(command []string, key, value string) bool {
		for i := 1; i < len(command); i++ {
			if command[i-1] == key && command[i] == value {
				return true
			}
		}
		return false
	}
	if !hasPair(commands[0], "--tag", ReleaseCheckpointTag) || !hasPair(commands[1], "--keep-tag", ReleaseCheckpointTag) {
		t.Fatalf("checkpoint could be pruned: %v", commands)
	}
}

func TestRestoreSizeCountsWhatARestoreWouldWrite(t *testing.T) {
	id := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name, snapshot, logs, wantError string
		code                            int
		want                            Size
		wantArgs                        []string
	}{
		{name: "a pinned snapshot", snapshot: id, logs: `{"total_size":96636764160,"total_file_count":120,"snapshots_count":1}`, want: Size{Bytes: 96636764160, Files: 120}, wantArgs: []string{"stats", id, "--mode", "restore-size", "--json"}},
		{name: "the latest of a host", snapshot: "latest", logs: `{"total_size":5,"total_file_count":1,"snapshots_count":1}`, want: Size{Bytes: 5, Files: 1}, wantArgs: []string{"stats", "latest", "--mode", "restore-size", "--json", "--host", "test", "--tag", Tag}},
		{name: "an empty snapshot", snapshot: id, logs: `{"total_size":0,"snapshots_count":1}`, want: Size{}, wantArgs: []string{"stats", id, "--mode", "restore-size", "--json"}},
		{name: "no count", snapshot: id, logs: `{"snapshots_count":1}`, wantError: "no restore size"},
		{name: "a negative count", snapshot: id, logs: `{"total_size":5,"total_file_count":-1}`, wantError: "in -1 files"},
		{name: "a failed count", snapshot: id, code: 1, logs: `Fatal: no matching ID found for prefix "aaaa"`, wantError: "no matching ID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := dockertest.New(t)
			var created dockertest.Container
			fake.OnCreate = func(c dockertest.Container) {
				created = c
				fake.Update(c.Name, func(c *dockertest.Container) {
					c.Logs, c.ExitCode, c.ExitAfter = tc.logs, tc.code, 1
				})
			}
			got, err := runner(t).RestoreSize(context.Background(), tc.snapshot, "test")
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("got %+v, %v; want an error with %q", got, err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("restore size %+v, want %+v", got, tc.want)
			}
			if !slices.Equal(created.Cmd, tc.wantArgs) {
				t.Errorf("restic ran %v, want %v", created.Cmd, tc.wantArgs)
			}
		})
	}
}

func TestRestoreRequiresVerifiedSuccessAndKeepsRawProgressCounters(t *testing.T) {
	for _, tc := range []struct {
		name      string
		logs      string
		code      int
		wantError string
		want      RestoreSummary
	}{
		{name: "included ancestors", logs: `{"message_type":"summary","total_files":6,"files_restored":8,"total_bytes":671,"bytes_restored":671}`, want: RestoreSummary{TotalFiles: 6, FilesRestored: 8, TotalBytes: 671, BytesRestored: 671}},
		{name: "already restored files", logs: `{"message_type":"summary","total_files":3,"files_restored":5,"files_skipped":3,"bytes_skipped":671}`, want: RestoreSummary{TotalFiles: 3, FilesRestored: 5}},
		{name: "partial restore", code: 3, logs: `{"message_type":"error","error":{"message":"file restore failed"}}` + "\n" + summary, wantError: "file restore failed"},
		{name: "verification failure", code: 1, logs: summary + `{"message_type":"exit_error","message":"verification failed"}`, wantError: "verification failed"},
		{name: "missing summary", logs: `{"message_type":"status"}`, wantError: "no summary"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := dockertest.New(t)
			var created dockertest.Container
			var secretsDir string
			fake.OnCreate = func(c dockertest.Container) {
				created = c
				for _, bind := range c.HostConfig.Binds {
					src, dst, _ := strings.Cut(bind, ":")
					if dst == secretsInside+":ro" {
						secretsDir = src
					}
				}
				fake.Update(c.Name, func(c *dockertest.Container) {
					c.Logs, c.ExitCode, c.ExitAfter = tc.logs, tc.code, 1
				})
			}
			got, err := runner(t).Restore(context.Background(), strings.Repeat("a", 64), "test", nil, "/data/app-data/notes")
			if !slices.Contains(created.Cmd, "--verify") {
				t.Errorf("restore must verify restored content: %v", created.Cmd)
			}
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) || got != nil {
					t.Errorf("failed restore returned a usable summary: %+v, %v", got, err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if *got != tc.want {
					t.Errorf("raw progress counters were changed: got %+v, want %+v", got, tc.want)
				}
			}
			if _, exists := fake.Container(created.Name); exists {
				t.Error("restore container outlived the completed run")
			}
			if secretsDir == "" {
				t.Error("restore had no credential mount")
			} else if _, err := os.Stat(secretsDir); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("restore credential file outlived the completed run: %v", err)
			}
		})
	}
}

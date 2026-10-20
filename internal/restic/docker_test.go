package restic

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
)

// TestResticRunsAgainstARealRepository drives the pinned restic image
// through a whole cycle against a repository on local disk: init, backup,
// list, forget and restore. It proves what the fake Docker cannot, that the
// shell entrypoint reads the password and credentials from the mounted file
// as restic needs them, including characters a shell would otherwise act
// on. It needs Docker and pulls the image, so it runs only when asked:
//
//	BEDROCK_DOCKER_TESTS=1 go test ./internal/restic -run RealRepository
func TestResticRunsAgainstARealRepository(t *testing.T) {
	if os.Getenv("BEDROCK_DOCKER_TESTS") == "" {
		t.Skip("set BEDROCK_DOCKER_TESTS=1 to run against Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	e, err := docker.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if exec.Command("docker", "volume", "inspect", CacheVolume).Run() != nil {
		t.Cleanup(func() { _ = exec.Command("docker", "volume", "rm", CacheVolume).Run() })
	}

	// The data sits in a volume, as an app's does. (Docker Desktop on a
	// Mac answers restic's reads of a bind-mounted file with an I/O error;
	// a Linux machine does not, but a volume works on both.)
	const volume = "bedrock-restic-test-data"
	for _, args := range [][]string{
		{"volume", "create", volume},
		{"run", "--rm", "-v", volume + ":/v", "alpine:3", "sh", "-c", "echo kept > /v/note.txt"},
	} {
		if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
			t.Fatalf("docker %v: %v %s", args, err, out)
		}
	}
	t.Cleanup(func() { _ = exec.Command("docker", "volume", "rm", volume).Run() })
	repo, restored := t.TempDir(), t.TempDir()
	password := `it's a "pass" $HOME ` + "`word`" + ` \ ; & | end`
	runner := func(password string) Runner {
		return Runner{Engine: e, Owner: "restic-test", Repo: Repo{
			Repository: "/repo", Password: password,
			// Unused by a local repository, but carried the same way.
			Env: []string{"AWS_ACCESS_KEY_ID=id", "AWS_SECRET_ACCESS_KEY=s'e\"c r$et"},
		}}
	}
	r := runner(password)
	repoMount := []string{repo + ":/repo"}
	withRepo := func(mounts ...string) []string { return append(append([]string{}, repoMount...), mounts...) }

	// Ensure runs without mounts in helios, against a bucket; a local
	// repository needs its directory, so init runs through run directly.
	if _, err := r.run(ctx, withRepo(), "init", "--json"); err != nil {
		t.Fatalf("init: %v", err)
	}
	lines, err := r.run(ctx, withRepo(), "init", "--json")
	if err == nil {
		t.Fatal("a second init must fail")
	}
	if !contains(lines, "already initialized") && !contains(lines, "already exists") {
		t.Fatalf("a second init must say the repository exists: %v", lines)
	}
	summary, err := r.Backup(ctx, "box", withRepo(VolumeMount(volume, "files", true)), DataRoot)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	if summary.SnapshotID == "" || summary.TotalFiles != 1 {
		t.Fatalf("summary: %+v", summary)
	}
	snaps, err := r.run(ctx, withRepo(), "snapshots", "--json", "--host", "box", "--tag", Tag)
	if err != nil || !contains(snaps, summary.SnapshotID) {
		t.Fatalf("snapshots: %v %v", err, snaps)
	}
	// Forget and its prune run through run directly for the same reason,
	// with the arguments Forget gives them.
	if _, err := r.run(ctx, withRepo(), "forget", "--json", "--host", "box", "--tag", Tag, "--keep-tag", ReleaseCheckpointTag, "--keep-daily", "7"); err != nil {
		t.Fatalf("forget: %v", err)
	}
	if _, err := r.run(ctx, withRepo(), "prune", "--max-repack-size", PruneMaxRepack); err != nil {
		t.Fatalf("prune: %v", err)
	}
	// RestoreSize runs without mounts too; this is its command, and the
	// count is the one file's five bytes.
	stats, err := r.run(ctx, withRepo(), "stats", summary.SnapshotID, "--mode", "restore-size", "--json")
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if size, err := restoreSize(stats); err != nil || size != int64(len("kept\n")) {
		t.Fatalf("restore size %d, %v from %v", size, err, stats)
	}
	if _, err := r.Restore(ctx, summary.SnapshotID, "box", withRepo(DirMount(restored, false))); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(restored, "volumes", "files", "note.txt"))
	if err != nil || string(got) != "kept\n" {
		t.Fatalf("restored %q %v", got, err)
	}
	// The password really is what opens it.
	if _, err := runner(password+"x").run(ctx, withRepo(), "snapshots", "--json"); err == nil {
		t.Fatal("a wrong password opened the repository")
	}
	// Nothing is left behind: no container, and no secrets on disk.
	infos, err := e.Owned(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range infos {
		if c.Labels[docker.LabelApp] == "restic-test" {
			t.Fatalf("container %s left behind", c.Name)
		}
	}
	leftovers, _ := filepath.Glob(filepath.Join(os.TempDir(), "bedrock-restic-*"))
	if len(leftovers) > 0 {
		t.Fatalf("secrets left on disk: %v", leftovers)
	}
}

func contains(lines []string, s string) bool {
	return strings.Contains(strings.Join(lines, "\n"), s)
}

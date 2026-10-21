package gitdeploy

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/manifest"
)

// MaxSource bounds both regular-file bytes and the uncompressed source
// archive, including headers, metadata and payloads that extraction skips.
const MaxSource int64 = 2 << 30

// BuildDir names the directory one deploy's source is written to, under
// the app's own, so PruneBuilds can keep the newest few.
func BuildDir(root, app, label string) string {
	return filepath.Join(root, app, fmt.Sprintf("%s-%d", label, time.Now().UnixNano()))
}

// NewBuildDir makes the directory one deploy's source is written to.
func NewBuildDir(root, app, label string) (string, error) {
	if !ValidApp(app) || label == "" || filepath.Base(label) != label || strings.ContainsAny(label, "\\\x00\r\n") {
		return "", errors.New("invalid source tree app or label")
	}
	parent := filepath.Join(root, app)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", err
	}
	return os.MkdirTemp(parent, fmt.Sprintf("%s-%d-", label, time.Now().UnixNano()))
}

// PruneBuilds keeps an app's newest few source trees: the images are in
// the registry, so older trees are only disk. Operation-bound deploy captures
// belong to the daemon and are collected only after their owning operation ends.
func PruneBuilds(root, app string, keep int) {
	if !ValidApp(app) || keep < 0 {
		return
	}
	entries, err := os.ReadDir(filepath.Join(root, app))
	if err != nil {
		return
	}
	type dir struct {
		name string
		at   time.Time
	}
	var dirs []dir
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "deploy-") {
			continue
		}
		if info, err := e.Info(); err == nil && e.IsDir() {
			dirs = append(dirs, dir{e.Name(), info.ModTime()})
		}
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].at.After(dirs[j].at) })
	for i := keep; i < len(dirs); i++ {
		_ = os.RemoveAll(filepath.Join(root, app, dirs[i].name))
	}
}

// ExportCommit writes a commit's tree into dest, as git archive gives it.
// In a pre-receive hook the pushed objects are still in quarantine, and
// git finds them through the hook's environment, which this inherits.
// Replace refs are ignored, so the tree written is the one the commit
// names, and the one its signature covers.
func ExportCommit(ctx context.Context, repoDir, commit, dest string) error {
	cmd := exec.CommandContext(ctx, "git", "--no-replace-objects", "-C", repoDir, "archive", "--format=tar", commit)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	extractErr := Extract(stdout, dest)
	// An extractor may reject the first header while git is still writing.
	// Closing its pipe releases the producer instead of waiting on a full pipe.
	if extractErr != nil {
		_ = stdout.Close()
	} else {
		// tar EOF can precede git's archive padding. Drain it so a valid
		// producer finishes without a broken pipe or a blocked final write.
		_, extractErr = io.Copy(io.Discard, stdout)
	}
	waitErr := cmd.Wait()
	if extractErr != nil {
		return extractErr
	}
	if waitErr != nil {
		return fmt.Errorf("git archive %s: %s", commit, strings.TrimSpace(stderr.String()))
	}
	return extractErr
}

// Extract unpacks a tar stream, gzipped or not, into dest. It writes
// regular files, directories and symlinks that stay inside dest, and
// nothing else.
func Extract(r io.Reader, dest string) error {
	return extract(r, dest, MaxSource)
}

func extract(r io.Reader, dest string, maxBytes int64) error {
	br := bufio.NewReader(r)
	var in io.Reader = br
	var gz *gzip.Reader
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		var err error
		gz, err = gzip.NewReader(br)
		if err != nil {
			return err
		}
		defer gz.Close()
		in = gz
	}
	root, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	bounded, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer bounded.Close()
	// The tar reader consumes padding, skipped payloads and PAX/GNU metadata
	// internally. Limit its input too, so empty entries and compressed skipped
	// data cannot bypass the regular-file budget. Each header consumes at
	// least 512 bytes, bounding entry count without a separate entry policy.
	archive := &io.LimitedReader{R: in, N: maxBytes + 1}
	tooLarge := func() error {
		return fmt.Errorf("the source is larger than %d GiB", MaxSource>>30)
	}
	tr := tar.NewReader(archive)
	var total int64
	for {
		h, err := tr.Next()
		if archive.N == 0 {
			return tooLarge()
		}
		if errors.Is(err, io.EOF) {
			if gz != nil {
				// tar stops at its end markers before gzip necessarily reads its
				// checksum and trailer. Close alone does not verify either.
				_, err := io.Copy(io.Discard, archive)
				if archive.N == 0 {
					return tooLarge()
				}
				if err != nil {
					return fmt.Errorf("the source archive: %w", err)
				}
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("the source archive: %w", err)
		}
		name := filepath.Clean(strings.TrimPrefix(h.Name, "./"))
		if name == "." {
			continue
		}
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
			return fmt.Errorf("the source archive has a path outside itself: %s", h.Name)
		}
		target := filepath.Join(root, name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := bounded.MkdirAll(name, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if h.Size > maxBytes-total {
				return tooLarge()
			}
			total += h.Size
			if err := bounded.MkdirAll(filepath.Dir(name), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(0o644)
			if h.Mode&0o111 != 0 {
				mode = 0o755
			}
			f, err := bounded.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(f, io.LimitReader(tr, h.Size))
			if archive.N == 0 {
				f.Close()
				return tooLarge()
			}
			if copyErr != nil {
				f.Close()
				return copyErr
			}
			if err := f.Close(); err != nil {
				return err
			}
		case tar.TypeSymlink:
			link := h.Linkname
			resolved := link
			if !filepath.IsAbs(link) {
				resolved = filepath.Join(filepath.Dir(target), link)
			}
			if filepath.IsAbs(link) || !strings.HasPrefix(filepath.Clean(resolved)+string(filepath.Separator), root+string(filepath.Separator)) {
				// A link out of the tree would let a build read the
				// machine; it is left out.
				continue
			}
			if err := bounded.MkdirAll(filepath.Dir(name), 0o755); err != nil {
				return err
			}
			_ = bounded.Remove(name)
			if err := bounded.Symlink(link, name); err != nil {
				return err
			}
		}
	}
}

// CheckSource makes sure a tree is the app it is deployed as: a real
// helios.yaml at its root naming that app.
func CheckSource(dir, app string) (*manifest.Manifest, error) {
	name, err := manifest.ResolveFileName(dir, "")
	if err != nil {
		return nil, err
	}
	m, err := manifest.Load(dir)
	if err != nil {
		return nil, err
	}
	if m.App != app {
		return nil, fmt.Errorf("%s says app: %s, but this is %s's remote", name, m.App, app)
	}
	return m, nil
}

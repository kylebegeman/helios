package gitdeploy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPruningUploadedSourcesPreservesOperationBoundCaptures(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"upload-1", "deploy-candidate", "deploy-candidate.tmp-operation"} {
		path := filepath.Join(root, "hello", name, "source")
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "evidence"), []byte("approved"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	PruneBuilds(root, "hello", 0)
	for _, name := range []string{"deploy-candidate", "deploy-candidate.tmp-operation"} {
		if got, err := os.ReadFile(filepath.Join(root, "hello", name, "source", "evidence")); err != nil || string(got) != "approved" {
			t.Errorf("operation-bound capture %s was pruned: %q %v", name, got, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "hello", "upload-1")); !os.IsNotExist(err) {
		t.Fatalf("old uploaded source was retained: %v", err)
	}
}

func TestExtractionChecksTheGzipTrailerBeforeAcceptingSource(t *testing.T) {
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(tarOf(t, [3]string{"file", "helios.yaml", helloYAML})); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	good := compressed.Bytes()
	corrupt := bytes.Clone(good)
	corrupt[len(corrupt)-8] ^= 0xff
	for name, data := range map[string][]byte{"checksum": corrupt, "truncated": good[:len(good)-4]} {
		t.Run(name, func(t *testing.T) {
			if err := Extract(bytes.NewReader(data), t.TempDir()); err == nil {
				t.Fatal("damaged gzip stream was accepted as deployment source")
			}
		})
	}
	if err := Extract(bytes.NewReader(good), t.TempDir()); err != nil {
		t.Fatalf("valid gzipped source was refused: %v", err)
	}
}

func TestArchiveSizeCannotOverflowItsSourceLimit(t *testing.T) {
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	if err := tw.WriteHeader(&tar.Header{Name: "first", Size: 1, Mode: 0600}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "enormous", Size: math.MaxInt64, Mode: 0600}); err != nil {
		t.Fatal(err)
	}
	// No payload is needed: the header alone must refuse the oversized tree.
	err := Extract(bytes.NewReader(archive.Bytes()), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversized header reached file copying instead of the source limit: %v", err)
	}
}

func TestArchiveKeepsARegularFileNamedPaxGlobalHeader(t *testing.T) {
	dir := t.TempDir()
	if err := Extract(bytes.NewReader(tarOf(t, [3]string{"file", "pax_global_header", "application data"})), dir); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "pax_global_header"))
	if err != nil || string(got) != "application data" {
		t.Fatalf("an ordinary source file was treated as tar metadata: %q %v", got, err)
	}
}

func TestSourceLimitIncludesEmptyEntriesAndSkippedPayloads(t *testing.T) {
	const limit = 4 << 10
	for _, kind := range []string{"directories", "symlinks", "skipped payload", "pax metadata"} {
		t.Run(kind, func(t *testing.T) {
			var archive bytes.Buffer
			tw := tar.NewWriter(&archive)
			for i := range 32 {
				h := &tar.Header{Name: fmt.Sprintf("entry-%d", i), Mode: 0755}
				switch kind {
				case "directories":
					h.Typeflag = tar.TypeDir
				case "symlinks":
					h.Typeflag, h.Linkname = tar.TypeSymlink, "target"
				case "skipped payload":
					h.Typeflag, h.Size = tar.TypeCont, limit/2
				case "pax metadata":
					h = &tar.Header{Typeflag: tar.TypeXGlobalHeader, PAXRecords: map[string]string{"comment": strings.Repeat("x", limit/2)}}
				}
				if err := tw.WriteHeader(h); err != nil {
					t.Fatal(err)
				}
				if h.Size > 0 {
					if _, err := tw.Write(make([]byte, h.Size)); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			for _, compressed := range []bool{false, true} {
				t.Run(fmt.Sprintf("gzip=%t", compressed), func(t *testing.T) {
					data := archive.Bytes()
					if compressed {
						var buf bytes.Buffer
						gz := gzip.NewWriter(&buf)
						if _, err := gz.Write(data); err != nil {
							t.Fatal(err)
						}
						if err := gz.Close(); err != nil {
							t.Fatal(err)
						}
						data = buf.Bytes()
					}
					dir := t.TempDir()
					err := extract(bytes.NewReader(data), dir, limit)
					if err == nil || !strings.Contains(err.Error(), "larger than") {
						t.Fatalf("oversized %s archive escaped the source budget: %v", kind, err)
					}
					entries, err := os.ReadDir(dir)
					if err != nil {
						t.Fatal(err)
					}
					// Every tar header consumes at least 512 bytes of this same
					// budget, including entries that have no regular-file data.
					if len(entries) > limit/512 {
						t.Fatalf("too many entries were created before refusing the archive: %d", len(entries))
					}
				})
			}
		})
	}
}

func TestSourceArchiveLimitAcceptsItsExactBoundary(t *testing.T) {
	data := tarOf(t, [3]string{"file", "payload", "data"})
	for _, compressed := range []bool{false, true} {
		t.Run(fmt.Sprintf("gzip=%t", compressed), func(t *testing.T) {
			input := data
			if compressed {
				var buf bytes.Buffer
				gz := gzip.NewWriter(&buf)
				if _, err := gz.Write(data); err != nil {
					t.Fatal(err)
				}
				if err := gz.Close(); err != nil {
					t.Fatal(err)
				}
				input = buf.Bytes()
			}
			if err := extract(bytes.NewReader(input), t.TempDir(), int64(len(data))); err != nil {
				t.Fatalf("valid archive at the exact byte limit was refused: %v", err)
			}
			if err := extract(bytes.NewReader(input), t.TempDir(), int64(len(data)-1)); err == nil || !strings.Contains(err.Error(), "larger than") {
				t.Fatalf("archive one byte over its budget was accepted: %v", err)
			}
		})
	}
}

func TestGzipTrailerDrainSharesTheArchiveBudget(t *testing.T) {
	const limit = 4 << 10
	data := tarOf(t, [3]string{"file", "payload", "data"})
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		t.Fatal(err)
	}
	if _, err := gz.Write(make([]byte, limit-len(data)+1)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	err := extract(bytes.NewReader(buf.Bytes()), t.TempDir(), limit)
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("gzip trailer verification reset the consumed archive budget: %v", err)
	}
}

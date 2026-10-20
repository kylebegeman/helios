package release

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// serve stands in for the release page: the asset, the sums beside it, and
// their signature by a release key this test pins. It returns the key's
// fingerprint.
func serve(t *testing.T, version string, body []byte, sums string) string {
	t.Helper()
	key, signer := newReleaseKey(t)
	publish(t, version, body, sums, sign(key, Namespace, []byte(sums)))
	return signer
}

// publish serves a release page with sig as its SHA256SUMS.sig, or with no
// signature when sig is nil. It returns how many times the build was asked
// for.
func publish(t *testing.T, version string, body []byte, sums string, sig []byte) *atomic.Int32 {
	t.Helper()
	asked := &atomic.Int32{}
	asset := AssetName(version, runtime.GOOS, runtime.GOARCH)
	mux := http.NewServeMux()
	prefix := "/releases/download/v" + version
	mux.HandleFunc(prefix+"/"+asset, func(w http.ResponseWriter, _ *http.Request) { asked.Add(1); w.Write(body) })
	mux.HandleFunc(prefix+"/SHA256SUMS", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, sums) })
	if sig != nil {
		mux.HandleFunc(prefix+"/SHA256SUMS.sig", func(w http.ResponseWriter, _ *http.Request) { w.Write(sig) })
	}
	srv := httptest.NewServer(mux)
	old := repo
	repo = srv.URL
	t.Cleanup(func() { repo = old; srv.Close() })
	return asked
}

func sumOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestFetchVerifiesAndMakesRunnable(t *testing.T) {
	body := []byte("#!/bin/sh\necho bedrock\n")
	asset := AssetName("0.7.4", runtime.GOOS, runtime.GOARCH)
	signer := serve(t, "0.7.4", body, sumOf(body)+"  "+asset+"\n")

	d, err := Fetch(context.Background(), "0.7.4", t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Signer != signer || d.Unsigned != "" {
		t.Fatalf("want signed by %s, got %+v", signer, d)
	}
	path := d.Path
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(body) {
		t.Fatalf("%v %q", err, got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("a verified binary has to be runnable")
	}
}

// The whole point of the checksum is that a wrong one stops the upgrade,
// and that nothing runnable is left behind when it does.
func TestFetchRefusesAndLeavesNothingWhenTheChecksumIsWrong(t *testing.T) {
	body := []byte("not the binary you asked for")
	asset := AssetName("0.7.4", runtime.GOOS, runtime.GOARCH)
	serve(t, "0.7.4", body, strings.Repeat("a", 64)+"  "+asset+"\n")

	dir := t.TempDir()
	if _, err := Fetch(context.Background(), "0.7.4", dir, ""); err == nil {
		t.Fatal("a mismatched checksum must refuse")
	}
	left, _ := os.ReadDir(dir)
	if len(left) != 0 {
		t.Fatalf("a refused download left %d file(s) behind", len(left))
	}
}

// A caller who pins a checksum from reviewed source must not have it
// silently replaced by whatever the release publishes.
func TestAPinnedChecksumIsTheOneThatCounts(t *testing.T) {
	body := []byte("the real binary")
	asset := AssetName("0.7.4", runtime.GOOS, runtime.GOARCH)
	// The published sums say something else entirely.
	serve(t, "0.7.4", body, strings.Repeat("b", 64)+"  "+asset+"\n")

	d, err := Fetch(context.Background(), "0.7.4", t.TempDir(), sumOf(body))
	if err != nil {
		t.Fatalf("the pinned checksum matches the bytes: %v", err)
	}
	// The signature is good, but it vouches for another build.
	if d.Signer != "" || d.Unsigned != "the signed SHA256SUMS doesn't list the pinned checksum" {
		t.Fatalf("the signature must not be credited to this build: %+v", d)
	}
	if _, err := Fetch(context.Background(), "0.7.4", t.TempDir(), strings.Repeat("c", 64)); err == nil {
		t.Fatal("a pinned checksum that does not match must refuse")
	}
}

func TestFetchRefusesWhatItCannotAskFor(t *testing.T) {
	body := []byte("x")
	serve(t, "0.7.4", body, sumOf(body)+"  "+AssetName("0.7.4", runtime.GOOS, runtime.GOARCH)+"\n")
	for _, version := range []string{"", "latest", "v0.7.4", "0.7.4-dev", "../../etc"} {
		if _, err := Fetch(context.Background(), version, t.TempDir(), ""); err == nil {
			t.Fatalf("%q must be refused", version)
		}
	}
	if _, err := Fetch(context.Background(), "0.7.4", t.TempDir(), "nonsense"); err == nil {
		t.Fatal("a checksum that isn't one must be refused")
	}
}

// A release that has no build for this machine should say so, rather than
// failing later on a 404 body written to disk.
func TestFetchSaysWhenTheReleaseHasNoBuildForThisMachine(t *testing.T) {
	serve(t, "0.7.4", []byte("x"), "deadbeef  bedrock_0.7.4_plan9_mips\n")
	_, err := Fetch(context.Background(), "0.7.4", t.TempDir(), "")
	if err == nil || !strings.Contains(err.Error(), "lists no") {
		t.Fatalf("want a clear missing-asset error, got %v", err)
	}
}

func TestFetchSaysWhenTheVersionIsNotPublished(t *testing.T) {
	serve(t, "0.7.4", []byte("x"), "")
	_, err := Fetch(context.Background(), "0.9.9", t.TempDir(), "")
	if err == nil || !strings.Contains(err.Error(), "not published") {
		t.Fatalf("want a not-published error, got %v", err)
	}
}

func TestFetchDoesNotFollowAnExistingAssetSymlink(t *testing.T) {
	body := []byte("new binary")
	serve(t, "0.7.4", body, "")
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "keep")
	if err := os.WriteFile(victim, []byte("keep these bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	asset := filepath.Join(dir, AssetName("0.7.4", runtime.GOOS, runtime.GOARCH))
	if err := os.Symlink(victim, asset); err != nil {
		t.Fatal(err)
	}
	if _, err := Fetch(context.Background(), "0.7.4", dir, sumOf(body)); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(victim)
	if err != nil || string(got) != "keep these bytes" {
		t.Fatalf("download overwrote symlink target: %q %v", got, err)
	}
}
func TestFailedFetchPreservesPreviousVerifiedAsset(t *testing.T) {
	serve(t, "0.7.4", []byte("wrong bytes"), "")
	dir := t.TempDir()
	asset := filepath.Join(dir, AssetName("0.7.4", runtime.GOOS, runtime.GOARCH))
	if err := os.WriteFile(asset, []byte("previous verified binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Fetch(context.Background(), "0.7.4", dir, strings.Repeat("c", 64)); err == nil {
		t.Fatal("checksum mismatch accepted")
	}
	got, err := os.ReadFile(asset)
	if err != nil || string(got) != "previous verified binary" {
		t.Fatalf("failed download destroyed previous asset: %q %v", got, err)
	}
}

func TestHeliosCanFetchHistoricalBedrockAssetsWithPublishedOrPinnedChecksums(t *testing.T) {
	for _, pinned := range []bool{false, true} {
		t.Run(fmt.Sprint(pinned), func(t *testing.T) {
			body := []byte("historical verified binary")
			asset := fmt.Sprintf("bedrock_%s_%s_%s", "0.7.10", runtime.GOOS, runtime.GOARCH)
			key, signer := newReleaseKey(t)
			sums := sumOf(body) + "  " + asset + "\n"
			mux := http.NewServeMux()
			mux.HandleFunc("/releases/download/v0.7.10/"+asset, func(w http.ResponseWriter, r *http.Request) { w.Write(body) })
			// Pinned downloads need no published checksum file.
			if !pinned {
				mux.HandleFunc("/releases/download/v0.7.10/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, sums) })
				mux.HandleFunc("/releases/download/v0.7.10/SHA256SUMS.sig", func(w http.ResponseWriter, r *http.Request) { w.Write(sign(key, Namespace, []byte(sums))) })
			}
			srv := httptest.NewServer(mux)
			defer srv.Close()
			previous := repo
			repo = srv.URL
			defer func() { repo = previous }()
			pin := ""
			if pinned {
				pin = sumOf(body)
			}
			d, err := Fetch(context.Background(), "0.7.10", t.TempDir(), pin)
			if err != nil {
				t.Fatal(err)
			}
			if pinned && (d.Signer != "" || !strings.Contains(d.Unsigned, "not published")) || !pinned && d.Signer != signer {
				t.Fatalf("pinned %v: %+v", pinned, d)
			}
			path := d.Path
			if filepath.Base(path) != asset {
				t.Fatalf("unexpected asset: %s", path)
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != string(body) {
				t.Fatalf("download changed: %q %v", got, err)
			}
		})
	}
}

func TestAHeliosChecksumFailureCannotFallBackToAnotherAsset(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden, http.StatusInternalServerError} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			mux := http.NewServeMux()
			legacyRequested := false
			mux.HandleFunc("/releases/download/v0.7.11/"+AssetName("0.7.11", runtime.GOOS, runtime.GOARCH), func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status); fmt.Fprint(w, "wrong candidate") })
			mux.HandleFunc("/releases/download/v0.7.11/SHA256SUMS", http.NotFound)
			mux.HandleFunc("/releases/download/v0.7.11/SHA256SUMS.sig", http.NotFound)
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				legacyRequested = true
				fmt.Fprint(w, "fallback must not run")
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()
			previous := repo
			repo = srv.URL
			defer func() { repo = previous }()
			dir := t.TempDir()
			if _, err := Fetch(context.Background(), "0.7.11", dir, sumOf([]byte("the approved binary"))); err == nil {
				t.Fatal("failed candidate accepted")
			}
			if legacyRequested {
				t.Fatal("failure was bypassed through a different asset")
			}
			files, err := os.ReadDir(dir)
			if err != nil || len(files) != 0 {
				t.Fatalf("failed download left files: %v %v", files, err)
			}
		})
	}
}

// A release signed by ssh-keygen, as scripts/build-release.sh signs one,
// installs and names its signer.
func TestASignedReleaseInstallsAndNamesItsSigner(t *testing.T) {
	pin(t, strings.TrimSpace(string(fixture(t, "release.pub"))))
	body := fixture(t, "build")
	publish(t, "0.7.99", body, string(fixture(t, "SHA256SUMS")), fixture(t, "SHA256SUMS.sig"))
	d, err := Fetch(context.Background(), "0.7.99", t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Signer != fixtureSigner {
		t.Fatalf("signer %q", d.Signer)
	}
	if got, err := os.ReadFile(d.Path); err != nil || string(got) != string(body) {
		t.Fatalf("%q %v", got, err)
	}
}

// Without a pinned checksum, only a pinned release key's signature makes
// the published checksum count. Anything else stops before the build is
// downloaded, so nothing unverified is ever written or run.
func TestAReleaseWithoutAGoodSignatureIsRefusedBeforeItsBuildIsFetched(t *testing.T) {
	body := []byte("#!/bin/sh\necho helios\n")
	sums := sumOf(body) + "  " + AssetName("0.7.4", runtime.GOOS, runtime.GOARCH) + "\n"
	_, stranger, _ := ed25519.GenerateKey(nil)
	for _, c := range []struct {
		name, want string
		sig        func(ed25519.PrivateKey) []byte
	}{
		{"no signature", "v0.7.4 publishes no SHA256SUMS.sig; pin its checksum to install it unsigned", func(ed25519.PrivateKey) []byte { return nil }},
		{"tampered sums", "SHA256SUMS doesn't match the signature", func(k ed25519.PrivateKey) []byte {
			return sign(k, Namespace, []byte(strings.Repeat("a", 64)+"  "+AssetName("0.7.4", runtime.GOOS, runtime.GOARCH)+"\n"))
		}},
		{"another key", "which isn't a Helios release key", func(ed25519.PrivateKey) []byte { return sign(stranger, Namespace, []byte(sums)) }},
		{"another namespace", `was made for "git", not for helios-release`, func(k ed25519.PrivateKey) []byte { return sign(k, "git", []byte(sums)) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			key, _ := newReleaseKey(t)
			asked := publish(t, "0.7.4", body, sums, c.sig(key))
			dir := t.TempDir()
			_, err := Fetch(context.Background(), "0.7.4", dir, "")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error saying %q, got %v", c.want, err)
			}
			if asked.Load() != 0 {
				t.Fatal("the build was downloaded before its checksum was trusted")
			}
			if left, _ := os.ReadDir(dir); len(left) != 0 {
				t.Fatalf("a refused release left %d file(s) behind", len(left))
			}
		})
	}
}

// Releases before 0.7.16 publish no signature. Kyle can still install one
// by pinning its checksum, and the upgrade says it is unsigned.
func TestAPinnedChecksumInstallsAnUnsignedReleaseAndSaysSo(t *testing.T) {
	newReleaseKey(t)
	body := []byte("helios 0.7.15")
	publish(t, "0.7.15", body, sumOf(body)+"  "+AssetName("0.7.15", runtime.GOOS, runtime.GOARCH)+"\n", nil)
	d, err := Fetch(context.Background(), "0.7.15", t.TempDir(), sumOf(body))
	if err != nil {
		t.Fatal(err)
	}
	if d.Signer != "" || d.Unsigned != "v0.7.15 publishes no SHA256SUMS.sig" {
		t.Fatalf("%+v", d)
	}
}

func TestAPinnedChecksumStillNamesTheReleaseKeyThatSignedIt(t *testing.T) {
	body := []byte("helios 0.7.16")
	signer := serve(t, "0.7.16", body, sumOf(body)+"  "+AssetName("0.7.16", runtime.GOOS, runtime.GOARCH)+"\n")
	d, err := Fetch(context.Background(), "0.7.16", t.TempDir(), sumOf(body))
	if err != nil {
		t.Fatal(err)
	}
	if d.Signer != signer || d.Unsigned != "" {
		t.Fatalf("want signed by %s, got %+v", signer, d)
	}
}

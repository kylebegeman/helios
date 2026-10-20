// Package release fetches a published helios build for this machine.
//
// A machine that can upgrade itself is a machine that downloads something
// and then executes it, so nothing here is trusted on the strength of where
// it came from. The checksums published beside a build count only when a
// pinned release key signed them (see trust.go). A downloaded binary is
// written to a private directory, checksummed, and only made executable
// once the checksum matches.
package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Repo is the canonical release channel. Historical Bedrock URLs redirect here.
const Repo = "https://github.com/kylebegeman/helios"

// repo is Repo, except in tests, which serve a release of their own.
var repo = Repo

// maxAsset bounds a download. The binary is about 15 MB; anything an order
// of magnitude past that is not the thing we asked for.
const maxAsset = 256 << 20

var versionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

// CheckVersion refuses anything that isn't a published release number, so a
// caller can say no before it creates directories or opens the network.
func CheckVersion(version string) error {
	if !versionPattern.MatchString(version) {
		return fmt.Errorf("%q isn't a release version such as 0.7.4", version)
	}
	return nil
}

// AssetName is what a release calls the build for an operating system and
// architecture, as build-release.sh names it.
func AssetName(version, goos, goarch string) string {
	return fmt.Sprintf("helios_%s_%s_%s", version, goos, goarch)
}

// Download is a build fetched for a machine and checked, and what vouched
// for it.
type Download struct {
	Path string
	// Signer is the fingerprint of the release key whose signature on the
	// release's SHA256SUMS lists this build's checksum.
	Signer string
	// Unsigned says why there is no signer, when a pinned checksum vouched
	// for the build alone.
	Unsigned string
}

// Fetch downloads the given version's build for this machine into dir.
//
// The build's checksum comes from the SHA256SUMS published beside it, and
// counts only when SHA256SUMS.sig is a pinned release key's signature of
// it: anyone who can replace a build can replace the sums beside it, but
// not sign them. sha256Hex pins the checksum instead, from reviewed
// source; then a release with no signature, such as one from before
// releases were signed, still installs, and the Download says why it is
// unsigned.
func Fetch(ctx context.Context, version, dir, sha256Hex string) (Download, error) {
	return FetchPlatform(ctx, version, dir, sha256Hex, runtime.GOOS, runtime.GOARCH)
}

// FetchPlatform downloads for the target platform rather than the client OS.
func FetchPlatform(ctx context.Context, version, dir, sha256Hex, goos, goarch string) (Download, error) {
	if (goos != "linux" && goos != "darwin") || (goarch != "amd64" && goarch != "arm64") {
		return Download{}, fmt.Errorf("unsupported release platform %s/%s", goos, goarch)
	}
	if err := CheckVersion(version); err != nil {
		return Download{}, err
	}
	asset := AssetName(version, goos, goarch)
	legacy := fmt.Sprintf("bedrock_%s_%s_%s", version, goos, goarch)
	base := fmt.Sprintf("%s/releases/download/v%s", repo, version)
	want := strings.ToLower(strings.TrimSpace(sha256Hex))
	sums, signer, sumsErr := signedSums(ctx, base, version)
	var d Download
	if want == "" {
		switch {
		case errors.Is(sumsErr, errUnsigned):
			return Download{}, fmt.Errorf("%w; pin its checksum to install it unsigned", sumsErr)
		case errors.Is(sumsErr, errNotPublished):
			return Download{}, sumsErr
		case sumsErr != nil:
			return Download{}, fmt.Errorf("refusing helios %s: %w", version, sumsErr)
		}
		var err error
		want, err = sumFor(sums, asset)
		if err != nil {
			want, err = sumFor(sums, legacy)
			if err != nil {
				return Download{}, err
			}
			asset = legacy
		}
		d.Signer = signer
	} else {
		// The pin is what counts. A signature is still checked, so the
		// upgrade can name the release key that vouches for the build too.
		switch {
		case sumsErr != nil:
			d.Unsigned = sumsErr.Error()
		case lists(sums, asset, want) || lists(sums, legacy, want):
			d.Signer = signer
		default:
			d.Unsigned = "the signed SHA256SUMS doesn't list the pinned checksum"
		}
	}
	if decoded, err := hex.DecodeString(want); err != nil || len(decoded) != sha256.Size {
		return Download{}, fmt.Errorf("%q isn't a sha256 checksum", want)
	}
	path, err := fetchAsset(ctx, base, asset, dir, want)
	// Pinned callers need no published checksum file. A 404 for the new name
	// alone permits trying the historical filename with the identical pin.
	if sha256Hex != "" && errors.Is(err, errNotPublished) && asset != legacy {
		path, err = fetchAsset(ctx, base, legacy, dir, want)
	}
	if err != nil {
		return Download{}, err
	}
	d.Path = path
	return d, nil
}

// errUnsigned is a release that publishes no signature, as every release
// before 0.7.16 does.
var errUnsigned = errors.New("publishes no SHA256SUMS.sig")

// signedSums fetches a release's SHA256SUMS and the signature beside it,
// and returns the sums only once the signature verifies, with the
// signer's fingerprint.
func signedSums(ctx context.Context, base, version string) (string, string, error) {
	sums, err := get(ctx, base+"/SHA256SUMS", 1<<20)
	if err != nil {
		return "", "", fmt.Errorf("SHA256SUMS for %s: %w", version, err)
	}
	sig, err := get(ctx, base+"/SHA256SUMS.sig", 64<<10)
	if errors.Is(err, errNotPublished) {
		return "", "", fmt.Errorf("v%s %w", version, errUnsigned)
	}
	if err != nil {
		return "", "", fmt.Errorf("SHA256SUMS.sig for %s: %w", version, err)
	}
	signer, err := VerifySums(sums, sig)
	if err != nil {
		return "", "", err
	}
	return string(sums), signer, nil
}

func fetchAsset(ctx context.Context, base, asset, dir, want string) (string, error) {
	// Not executable yet: a file that has not been checked must not be
	// runnable, even for the moment between writing and verifying it.
	path := filepath.Join(dir, asset)
	f, err := os.CreateTemp(dir, ".bedrock-download-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	defer f.Close()
	sum := sha256.New()
	body, err := open(ctx, base+"/"+asset)
	if err != nil {
		f.Close()
		return "", fmt.Errorf("%s: %w", asset, err)
	}
	n, err := io.Copy(io.MultiWriter(f, sum), io.LimitReader(body, maxAsset))
	body.Close()
	closeErr := f.Close()
	switch {
	case err != nil:
		return "", fmt.Errorf("%s: %w", asset, err)
	case closeErr != nil:
		return "", closeErr
	case n >= maxAsset:
		return "", fmt.Errorf("%s is larger than %d bytes", asset, int64(maxAsset))
	}
	if got := hex.EncodeToString(sum.Sum(nil)); got != want {
		return "", fmt.Errorf("%s does not match its checksum: got %s, want %s", asset, got, want)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return path, nil
}

// sumFor reads one asset's checksum out of a SHA256SUMS file.
func sumFor(sums, asset string) (string, error) {
	for _, line := range strings.Split(sums, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == asset {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("SHA256SUMS lists no %s; this release may not build for %s/%s", asset, runtime.GOOS, runtime.GOARCH)
}

// lists reports whether sums gives asset the checksum want.
func lists(sums, asset, want string) bool {
	listed, err := sumFor(sums, asset)
	return err == nil && listed == want
}

var errNotPublished = errors.New("not published")

func open(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%w at %s", errNotPublished, url)
		}
		return nil, fmt.Errorf("%s answered %s", url, resp.Status)
	}
	return resp.Body, nil
}

func get(ctx context.Context, url string, limit int64) ([]byte, error) {
	body, err := open(ctx, url)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return io.ReadAll(io.LimitReader(body, limit))
}

package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// RegistryContainer runs the local registry. Host setup starts it.
const RegistryContainer = "bedrock-registry"

// registryConfig and registryData are where the registry's image keeps its
// configuration and what is pushed to it.
const (
	registryConfig = "/etc/distribution/config.yml"
	registryData   = "/var/lib/registry"
)

// manifestTypes are an image and a list of images, in their OCI and Docker
// forms. A registry offers an index only to a client that accepts one.
var manifestTypes = strings.Join([]string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}, ", ")

// RegistryClient speaks the HTTP API of a registry on this machine.
type RegistryClient struct {
	addr string
	http *http.Client
}

// NewRegistryClient talks to the registry at addr, such as Registry.
func NewRegistryClient(addr string) *RegistryClient {
	return &RegistryClient{addr: addr, http: &http.Client{Timeout: time.Minute}}
}

// RegistryManifest is a manifest's digest and the digests of the manifests
// it lists, when it is an index.
type RegistryManifest struct {
	Digest    string
	Manifests []string
}

// Repositories lists every repository in the registry.
func (r *RegistryClient) Repositories(ctx context.Context) ([]string, error) {
	var all []string
	err := r.pages(ctx, "/v2/_catalog?n=100", func(body []byte) error {
		var page struct {
			Repositories []string `json:"repositories"`
		}
		err := json.Unmarshal(body, &page)
		all = append(all, page.Repositories...)
		return err
	})
	return all, err
}

// Tags lists a repository's tags.
func (r *RegistryClient) Tags(ctx context.Context, repo string) ([]string, error) {
	var all []string
	err := r.pages(ctx, "/v2/"+repo+"/tags/list?n=100", func(body []byte) error {
		var page struct {
			Tags []string `json:"tags"`
		}
		err := json.Unmarshal(body, &page)
		all = append(all, page.Tags...)
		return err
	})
	return all, err
}

// Manifest looks up a tag or digest in a repository. One the registry does
// not have comes back with no digest.
func (r *RegistryClient) Manifest(ctx context.Context, repo, ref string) (RegistryManifest, error) {
	body, header, err := r.call(ctx, http.MethodGet, "/v2/"+repo+"/manifests/"+ref)
	if err != nil || body == nil {
		return RegistryManifest{}, err
	}
	var listing struct {
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(body, &listing); err != nil {
		return RegistryManifest{}, fmt.Errorf("manifest %s:%s: %w", repo, ref, err)
	}
	m := RegistryManifest{Digest: header.Get("Docker-Content-Digest")}
	if m.Digest == "" {
		sum := sha256.Sum256(body)
		m.Digest = "sha256:" + hex.EncodeToString(sum[:])
	}
	for _, listed := range listing.Manifests {
		m.Manifests = append(m.Manifests, listed.Digest)
	}
	return m, nil
}

// Delete removes a tag, or a manifest by its digest along with every tag on
// it. One already gone is fine.
func (r *RegistryClient) Delete(ctx context.Context, repo, ref string) error {
	_, _, err := r.call(ctx, http.MethodDelete, "/v2/"+repo+"/manifests/"+ref)
	return err
}

// pages gets a listing and every page its Link headers lead to.
func (r *RegistryClient) pages(ctx context.Context, path string, page func([]byte) error) error {
	for path != "" {
		body, header, err := r.call(ctx, http.MethodGet, path)
		if err != nil || body == nil {
			return err
		}
		if err := page(body); err != nil {
			return fmt.Errorf("registry %s: %w", path, err)
		}
		path = nextPage(header.Get("Link"))
	}
	return nil
}

// nextPage reads the path of the next page out of a Link header such as
// </v2/_catalog?last=site%2Fweb&n=100>; rel="next".
func nextPage(link string) string {
	target, params, ok := strings.Cut(link, ";")
	if !ok || !strings.Contains(params, `rel="next"`) {
		return ""
	}
	next, err := url.Parse(strings.Trim(strings.TrimSpace(target), "<>"))
	if err != nil {
		return ""
	}
	return next.RequestURI()
}

// call makes one request. A 404 comes back as no body and no error.
func (r *RegistryClient) call(ctx context.Context, method, path string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://"+r.addr+path, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", manifestTypes)
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("the local registry on %s isn't answering: start it with docker start %s, or run helios host setup if it is missing (%w)", r.addr, RegistryContainer, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	switch {
	case err != nil:
		return nil, nil, fmt.Errorf("registry %s %s: %w", method, path, err)
	case resp.StatusCode == http.StatusNotFound:
		return nil, resp.Header, nil
	case resp.StatusCode/100 != 2:
		return nil, nil, fmt.Errorf("registry %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(body)))
	}
	return body, resp.Header, nil
}

// CollectRegistry deletes the local registry's blobs that no manifest in
// it refers to and returns how many bytes that freed. Untagged manifests
// stay: an image pushed by hand can be deployed by digest after its tag has
// moved on, so only what was deleted by digest is reclaimed.
func CollectRegistry(ctx context.Context) (int64, error) {
	before, err := registryUsage(ctx)
	if err != nil {
		return 0, err
	}
	// A push from outside helios while this runs can lose blobs; helios's own operations never overlap it.
	if _, err := cliOutput(ctx, nil, "docker", "exec", RegistryContainer, "registry", "garbage-collect", registryConfig); err != nil {
		return 0, fmt.Errorf("registry garbage-collect: %w", err)
	}
	after, err := registryUsage(ctx)
	if err != nil {
		return 0, err
	}
	// The registry caches which blobs it has, and until it restarts would let a push skip one just deleted.
	if _, err := cliOutput(ctx, nil, "docker", "restart", RegistryContainer); err != nil {
		return max(before-after, 0), fmt.Errorf("the registry must restart before the next push, so run docker restart %s: %w", RegistryContainer, err)
	}
	return max(before-after, 0), nil
}

// registryUsage is how many bytes the local registry's storage takes.
func registryUsage(ctx context.Context) (int64, error) {
	out, err := cliOutput(ctx, nil, "docker", "exec", RegistryContainer, "du", "-sk", registryData)
	if err != nil {
		return 0, fmt.Errorf("measure the local registry: %w", err)
	}
	if fields := strings.Fields(out); len(fields) > 0 {
		if kib, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
			return kib << 10, nil
		}
	}
	return 0, fmt.Errorf("measure the local registry: du said %q", out)
}

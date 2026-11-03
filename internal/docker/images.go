package docker

import (
	"context"
	"fmt"
	"math"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/client"
	"github.com/moby/moby/client/pkg/versions"
)

// Image is an image on this machine.
type Image struct {
	ID      string
	Tags    []string
	Digests []string
	Labels  map[string]string
	Size    int64
}

// Describe names an image the way a person reads it.
func (i Image) Describe() string {
	if len(i.Tags) > 0 {
		return i.Tags[0]
	}
	id := strings.TrimPrefix(i.ID, "sha256:")
	return id[:min(12, len(id))]
}

// OwnedImages lists the images helios built.
func (e *Engine) OwnedImages(ctx context.Context) ([]Image, error) {
	res, err := e.cli.ImageList(ctx, client.ImageListOptions{})
	if err != nil {
		return nil, err
	}
	var out []Image
	for _, img := range res.Items {
		if img.Labels[LabelOwner] != OwnerValue {
			continue
		}
		var tags []string
		for _, t := range img.RepoTags {
			if t != "<none>:<none>" {
				tags = append(tags, t)
			}
		}
		out = append(out, Image{ID: img.ID, Tags: tags, Digests: img.RepoDigests, Labels: img.Labels, Size: img.Size})
	}
	return out, nil
}

// LocalImage describes the image ref names on this machine, or is nil when
// there is none.
func (e *Engine) LocalImage(ctx context.Context, ref string) (*Image, error) {
	res, err := e.cli.ImageInspect(ctx, ref)
	if IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect image %s: %w", ref, err)
	}
	img := &Image{ID: res.ID, Size: res.Size}
	if res.Config != nil {
		img.Labels = res.Config.Labels
	}
	for _, name := range res.RepoTags {
		if !strings.HasPrefix(name, "<none>") {
			img.Tags = append(img.Tags, name)
		}
	}
	for _, name := range res.RepoDigests {
		if !strings.HasPrefix(name, "<none>") {
			img.Digests = append(img.Digests, name)
		}
	}
	return img, nil
}

// ImagesInUse is the set of IDs of the images containers were created from,
// running or stopped, helios's or not.
func (e *Engine) ImagesInUse(ctx context.Context) (map[string]bool, error) {
	res, err := e.cli.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return nil, err
	}
	used := map[string]bool{}
	for _, c := range res.Items {
		used[c.ImageID] = true
	}
	return used, nil
}

// UntagAndRemove removes an image without force: each of its names, then
// the image itself if it is still there. Names in ref's repository go last,
// so ref finds the image until it is gone. Docker refuses an image a
// container uses; whatever is already gone is fine.
func (e *Engine) UntagAndRemove(ctx context.Context, img Image, ref string) error {
	var names, last []string
	for _, name := range slices.Concat(img.Tags, img.Digests) {
		if repository(name) == repository(ref) {
			last = append(last, name)
		} else {
			names = append(names, name)
		}
	}
	for _, name := range append(names, last...) {
		if err := e.RemoveImage(ctx, name); err != nil {
			return fmt.Errorf("untag %s: %w", name, err)
		}
	}
	left, err := e.LocalImage(ctx, img.ID)
	if err != nil || left == nil {
		return err
	}
	if err := e.RemoveImage(ctx, img.ID); err != nil {
		return fmt.Errorf("remove image %s: %w", img.ID, err)
	}
	return nil
}

// manifestsAPIVersion is the first Engine API version that lists an
// image's manifests.
const manifestsAPIVersion = "1.48"

// ArchiveSizes estimates, image by image, the room docker image save takes.
// The containerd image store streams the compressed content it keeps, which
// its manifests count; the size it reports for an image can include the
// unpacked snapshots too, about four times as much. A graph driver store
// lists no manifests and saves each layer unpacked, near the reported
// size, but first writes the whole archive into a temporary directory
// under its data root, so a save there takes twice the reported size while
// it runs. A daemon too old to list manifests is counted the same way.
// Each image counts all of its own content, so layers images share count
// once for each, though a save of them together writes them once.
func (e *Engine) ArchiveSizes(ctx context.Context, ids []string) ([]int64, error) {
	// Settle the API version before deciding whether to ask for manifests.
	if _, err := e.cli.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true}); err != nil {
		return nil, err
	}
	var opts []client.ImageInspectOption
	if !versions.LessThan(e.cli.ClientVersion(), manifestsAPIVersion) {
		opts = append(opts, client.ImageInspectWithManifests(true))
	}
	sizes := make([]int64, 0, len(ids))
	for _, id := range ids {
		res, err := e.cli.ImageInspect(ctx, id, opts...)
		if err != nil {
			return nil, err
		}
		var size int64
		if len(res.Manifests) > 0 {
			// Every manifest's content, available or not: Content counts
			// only what is present, and save copies all of that.
			for _, m := range res.Manifests {
				if m.Size.Content < 0 {
					return nil, fmt.Errorf("docker reported %d bytes of content for %s", m.Size.Content, id)
				}
				size = addBytes(size, m.Size.Content)
			}
		} else {
			if res.Size < 0 {
				return nil, fmt.Errorf("docker reported %d bytes for %s", res.Size, id)
			}
			// The temporary copy and the archive itself.
			size = addBytes(res.Size, res.Size)
		}
		sizes = append(sizes, size)
	}
	return sizes, nil
}

// addBytes adds two non-negative sizes, saturating rather than wrapping.
func addBytes(a, b int64) int64 {
	if b > math.MaxInt64-a {
		return math.MaxInt64
	}
	return a + b
}

// PruneBuildCache drops build cache older than age, then trims whatever
// remains down to keep bytes, evicting least-recently-used entries first.
//
// Age alone cannot bound this. A machine that rebuilds a large source tree
// several times in one day holds every one of those caches, all of them
// younger than any sensible age limit, so an age rule reclaims nothing
// exactly when there is most to reclaim. The ceiling is what actually holds
// the disk; the age pass just keeps stale entries from occupying it.
//
// Both passes take --all: without it BuildKit skips every record whose layers
// an image also holds, which on the containerd image store is most of the cache.
func PruneBuildCache(ctx context.Context, age time.Duration, keep int64) (int64, error) {
	reclaimed := int64(0)
	prune := func(args ...string) error {
		cmd := exec.CommandContext(ctx, "docker", append([]string{"builder", "prune", "--force", "--all"}, args...)...)
		result, err := cmd.CombinedOutput()
		text := strings.TrimSpace(string(result))
		if err != nil {
			return fmt.Errorf("builder prune: %v: %s", err, text)
		}
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "Total:") || strings.HasPrefix(line, "Total reclaimed space") {
				reclaimed += parseReclaimed(line)
			}
		}
		return nil
	}
	if err := prune("--filter", fmt.Sprintf("until=%dh", int(age.Hours()))); err != nil {
		return reclaimed, err
	}
	if keep > 0 {
		// --reserved-space is a floor, not this ceiling; a daemon too old for
		// --max-used-space still answers to --keep-storage.
		err := prune("--max-used-space", fmt.Sprintf("%d", keep))
		if err != nil && strings.Contains(err.Error(), "unknown flag") {
			err = prune("--keep-storage", fmt.Sprintf("%d", keep))
		}
		if err != nil {
			return reclaimed, err
		}
	}
	return reclaimed, nil
}

// parseReclaimed reads the byte count out of docker's "Total reclaimed
// space: 1.23GB" line. An unreadable line counts as nothing rather than
// failing a prune that already succeeded.
func parseReclaimed(line string) int64 {
	m := regexp.MustCompile(`([0-9.]+)\s*([KMGT]?B)`).FindStringSubmatch(line)
	if m == nil {
		return 0
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0
	}
	switch m[2] {
	case "KB":
		return int64(n * 1e3)
	case "MB":
		return int64(n * 1e6)
	case "GB":
		return int64(n * 1e9)
	case "TB":
		return int64(n * 1e12)
	}
	return int64(n)
}

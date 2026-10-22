package docker

import (
	"archive/tar"
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// Nobody is who a workload runs as when its image would run it as root
// and its manifest doesn't say otherwise.
const (
	NobodyUID = 65534
	NobodyGID = 65534
)

// User is a resolved user: numeric ids, and the name when the image has one.
type User struct {
	UID  int
	GID  int
	Name string
}

// Root reports whether the user is root.
func (u User) Root() bool { return u.UID == 0 }

// Spec is the user as Docker takes it: always numeric, so the group is
// never left to chance.
func (u User) Spec() string { return fmt.Sprintf("%d:%d", u.UID, u.GID) }

// String names the user for people.
func (u User) String() string {
	if u.Name != "" {
		return fmt.Sprintf("%s (%d)", u.Name, u.UID)
	}
	return strconv.Itoa(u.UID)
}

// rootish reports whether an image's configured user means root.
func rootish(user string) bool {
	who, _, _ := strings.Cut(strings.TrimSpace(user), ":")
	if who == "" || who == "root" {
		return true
	}
	uid, err := strconv.Atoi(who)
	return err == nil && uid == 0
}

// accounts are an image's /etc/passwd and /etc/group.
type accounts struct {
	users  map[string]User // by name
	byUID  map[int]User
	groups map[string]int // by name
}

var (
	accountsMu    sync.Mutex
	accountsCache = map[string]*accounts{}
)

// imageAccounts reads an image's /etc/passwd and /etc/group by copying
// them out of a container that is never started. An image without them
// (scratch, distroless) has no names to look up. The answer is kept by
// the image's ID, not its reference: a tag that moves is another image.
func (e *Engine) imageAccounts(ctx context.Context, image string) (*accounts, error) {
	inspected, err := e.cli.ImageInspect(ctx, image)
	if err != nil {
		return nil, fmt.Errorf("read the users of %s: %w", image, err)
	}
	key := inspected.ID
	accountsMu.Lock()
	if a, ok := accountsCache[key]; ok {
		accountsMu.Unlock()
		return a, nil
	}
	accountsMu.Unlock()
	name := fmt.Sprintf("bedrock-probe-%d", time.Now().UnixNano())
	created, err := e.cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name:       name,
		Config:     &container.Config{Image: image, Entrypoint: []string{"/nonexistent"}, Labels: map[string]string{LabelOwner: OwnerValue}},
		HostConfig: &container.HostConfig{NetworkMode: "none"},
	})
	if err != nil {
		return nil, fmt.Errorf("read the users of %s: %w", image, err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = e.cli.ContainerRemove(cleanup, created.ID, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
	}()
	a := &accounts{users: map[string]User{}, byUID: map[int]User{}, groups: map[string]int{}}
	if text, err := e.copyFile(ctx, created.ID, "/etc/passwd"); err == nil {
		sc := bufio.NewScanner(strings.NewReader(text))
		for sc.Scan() {
			f := strings.Split(sc.Text(), ":")
			if len(f) < 4 {
				continue
			}
			uid, err1 := strconv.Atoi(f[2])
			gid, err2 := strconv.Atoi(f[3])
			if err1 != nil || err2 != nil {
				continue
			}
			u := User{UID: uid, GID: gid, Name: f[0]}
			a.users[f[0]] = u
			if _, seen := a.byUID[uid]; !seen {
				a.byUID[uid] = u
			}
		}
	}
	if text, err := e.copyFile(ctx, created.ID, "/etc/group"); err == nil {
		sc := bufio.NewScanner(strings.NewReader(text))
		for sc.Scan() {
			f := strings.Split(sc.Text(), ":")
			if len(f) < 3 {
				continue
			}
			if gid, err := strconv.Atoi(f[2]); err == nil {
				a.groups[f[0]] = gid
			}
		}
	}
	accountsMu.Lock()
	accountsCache[key] = a
	accountsMu.Unlock()
	return a, nil
}

// copyFile reads one small file out of a container.
func (e *Engine) copyFile(ctx context.Context, containerID, path string) (string, error) {
	res, err := e.cli.CopyFromContainer(ctx, containerID, client.CopyFromContainerOptions{SourcePath: path})
	if err != nil {
		return "", err
	}
	defer res.Content.Close()
	tr := tar.NewReader(res.Content)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return "", fmt.Errorf("%s not in the archive", path)
		}
		if err != nil {
			return "", err
		}
		if h.Typeflag == tar.TypeReg {
			b, err := io.ReadAll(io.LimitReader(tr, 1<<20))
			return string(b), err
		}
	}
}

// ResolveUser turns a user as Docker takes it (name, uid, name:group or
// uid:gid) into numeric ids, looking names up in the image.
func (e *Engine) ResolveUser(ctx context.Context, image, user string) (User, error) {
	user = strings.TrimSpace(user)
	who, group, hasGroup := strings.Cut(user, ":")
	var a *accounts
	lookup := func() (*accounts, error) {
		if a != nil {
			return a, nil
		}
		var err error
		a, err = e.imageAccounts(ctx, image)
		return a, err
	}
	var u User
	if rootish(user) {
		u = User{UID: 0, GID: 0, Name: "root"}
	} else if uid, err := strconv.Atoi(who); err == nil {
		u = User{UID: uid, GID: uid}
		if acc, err := lookup(); err == nil {
			if known, ok := acc.byUID[uid]; ok {
				u = known
			}
		}
	} else {
		acc, err := lookup()
		if err != nil {
			return User{}, err
		}
		known, ok := acc.users[who]
		if !ok {
			return User{}, fmt.Errorf("the image %s has no user named %s", image, who)
		}
		u = known
	}
	if hasGroup {
		if group == "root" && u.Root() {
			u.GID = 0
		} else if gid, err := strconv.Atoi(group); err == nil {
			u.GID = gid
		} else {
			acc, err := lookup()
			if err != nil {
				return User{}, err
			}
			gid, ok := acc.groups[group]
			if !ok {
				return User{}, fmt.Errorf("the image %s has no group named %s", image, group)
			}
			u.GID = gid
		}
	}
	return u, nil
}

// EffectiveUser decides who a workload runs as: the manifest's user when
// it names one (root included), the image's own user when that isn't
// root, and nobody otherwise.
func (e *Engine) EffectiveUser(ctx context.Context, image, manifestUser string) (User, error) {
	if manifestUser != "" {
		return e.ResolveUser(ctx, image, manifestUser)
	}
	imageUser, err := e.ImageUser(ctx, image)
	if err != nil {
		return User{}, err
	}
	if rootish(imageUser) {
		return User{UID: NobodyUID, GID: NobodyGID, Name: "nobody"}, nil
	}
	u, err := e.ResolveUser(ctx, image, imageUser)
	if err == nil && u.Root() {
		return User{UID: NobodyUID, GID: NobodyGID, Name: "nobody"}, nil
	}
	return u, err
}

// EnsureVolumeOwner gives a volume to a user when it belongs to root,
// as a fresh volume or an unpacked archive does. A volume someone else
// owns is left alone. It reports whether it changed anything.
func (e *Engine) EnsureVolumeOwner(ctx context.Context, volume string, u User) (bool, error) {
	if u.Root() {
		return false, nil
	}
	if err := e.ensureHelper(ctx); err != nil {
		return false, err
	}
	script := fmt.Sprintf(`if [ "$(stat -c %%u /v)" = 0 ]; then chown -R %d:%d /v && echo changed; fi`, u.UID, u.GID)
	out, err := cliOutput(ctx, nil, "docker", "run", "--rm", "--network", "none", "-v", volume+":/v", HelperImage, "sh", "-c", script)
	if err != nil {
		return false, fmt.Errorf("give %s to %s: %w", volume, u, err)
	}
	return strings.Contains(out, "changed"), nil
}

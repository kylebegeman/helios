package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/secrets"
)

// Names the data services use.
const (
	postgresWorkload = "postgres"
	// DatabaseURLName is the secret every workload of an app with a
	// database receives.
	DatabaseURLName = "DATABASE_URL"
	// postgresPasswordName is the internal secret the database container
	// itself is started with.
	postgresPasswordName = "BEDROCK_POSTGRES_PASSWORD"
)

// PostgresPasswordName is the secret holding the database superuser's
// password, for helios's own commands.
const PostgresPasswordName = postgresPasswordName

// PostgresContainer names an app's database container. It carries no
// revision: the database outlives every revision.
func PostgresContainer(app string) string { return "bedrock-" + app + "-" + postgresWorkload }

// postgresName turns an app name into a database and role name.
func postgresName(app string) string { return strings.ReplaceAll(app, "-", "_") }

// Restore says what to load into an app's data before its first start.
type Restore struct {
	// Postgres is a pg_dump custom-format file on this machine.
	Postgres string `json:"postgres,omitempty"`
	// Volumes maps a volume name to a .tar.gz on this machine.
	Volumes map[string]string `json:"volumes,omitempty"`
}

// ensureData brings up the app's volumes, database and object store,
// restoring into them when asked and they are empty. initDir holds the
// database's first-run scripts, when the manifest has them.
func ensureData(ctx context.Context, e *docker.Engine, store *secrets.Store, m *manifest.Manifest, initDir string, restore Restore, out io.Writer) error {
	if m.Data == nil {
		return nil
	}
	for _, name := range m.DataVolumes() {
		vol := docker.VolumeName(m.App, name)
		if err := e.EnsureVolume(ctx, vol); err != nil {
			return err
		}
		tarball, wanted := restore.Volumes[name]
		if !wanted {
			continue
		}
		empty, err := e.VolumeEmpty(ctx, vol)
		if err != nil {
			return err
		}
		if !empty {
			return fmt.Errorf("volume %s already has files; a restore is for an empty volume", name)
		}
		if err := e.RestoreVolume(ctx, vol, tarball); err != nil {
			return err
		}
		fmt.Fprintf(out, "volume %s restored from %s\n", name, tarball)
	}
	for name := range restore.Volumes {
		if !slices.Contains(m.DataVolumes(), name) {
			return fmt.Errorf("no volume named %s in the manifest", name)
		}
	}
	if version := m.PostgresVersion(); version != "" {
		if err := ensurePostgres(ctx, e, store, m, initDir, restore.Postgres, out); err != nil {
			return err
		}
	} else if restore.Postgres != "" {
		return errors.New("the manifest declares no database to restore into")
	}
	if m.HasObjects() {
		if err := ensureObjects(ctx, e, store, m, out); err != nil {
			return err
		}
	}
	return nil
}

// ensureServiceCredentials makes the passwords the data services start
// with, before anything derives from them: the database superuser's, the
// DATABASE_URL workloads get unless the manifest says otherwise, and the
// object store's root user and password.
func ensureServiceCredentials(store *secrets.Store, m *manifest.Manifest, out io.Writer) error {
	values, _, err := store.LoadCurrent(m.App)
	if err != nil {
		return err
	}
	changes := map[string]*string{}
	set := func(name, value string) {
		v := value
		changes[name] = &v
		values[name] = v
	}
	if m.PostgresVersion() != "" {
		if values[postgresPasswordName] == "" {
			set(postgresPasswordName, randomHex(24))
		}
		if m.InjectsDatabaseURL() && values[DatabaseURLName] == "" {
			user, database := m.PostgresIdentity()
			set(DatabaseURLName, fmt.Sprintf("postgres://%s:%s@%s:5432/%s?sslmode=disable", user, values[postgresPasswordName], PostgresContainer(m.App), database))
		}
	}
	if m.HasObjects() {
		if values[ObjectsUserName] == "" {
			set(ObjectsUserName, m.App+"-root")
		}
		if values[ObjectsPasswordName] == "" {
			set(ObjectsPasswordName, randomHex(24))
		}
	}
	if len(changes) == 0 {
		return nil
	}
	if _, err := store.SetAll(m.App, changes); err != nil {
		return err
	}
	fmt.Fprintf(out, "data service credentials made: %s\n", strings.Join(sortedKeys(changes), ", "))
	return nil
}

// ensureAppSecrets makes the secrets the manifest asks helios to generate
// and derives the rest. Values never reach the output, only names.
func ensureAppSecrets(store *secrets.Store, m *manifest.Manifest, out io.Writer) error {
	if err := ensureServiceCredentials(store, m, out); err != nil {
		return err
	}
	if m.Secrets == nil {
		return nil
	}
	values, _, err := store.LoadCurrent(m.App)
	if err != nil {
		return err
	}
	changes := map[string]*string{}
	var made, changed []string
	for _, name := range sortedKeys(m.Secrets.Generate) {
		if _, ok := values[name]; ok {
			continue
		}
		f, err := manifest.ParseSecretFormat(m.Secrets.Generate[name])
		if err != nil {
			return err
		}
		v, err := f.Make()
		if err != nil {
			return err
		}
		changes[name], values[name] = &v, v
		made = append(made, name)
	}
	derived, err := manifest.Derive(m.Secrets.Derive, values, map[string]string{"postgres": PostgresContainer(m.App), "objects": ObjectsContainer(m.App)})
	if err != nil {
		return err
	}
	for _, name := range sortedKeys(derived) {
		if old, ok := values[name]; ok && old == derived[name] {
			continue
		}
		v := derived[name]
		changes[name] = &v
		changed = append(changed, name)
	}
	if len(changes) == 0 {
		fmt.Fprintln(out, "every secret the manifest asks for is there")
		return nil
	}
	version, err := store.SetAll(m.App, changes)
	if err != nil {
		return err
	}
	if len(made) > 0 {
		fmt.Fprintf(out, "made %s\n", strings.Join(made, ", "))
	}
	if len(changed) > 0 {
		fmt.Fprintf(out, "derived %s\n", strings.Join(changed, ", "))
	}
	fmt.Fprintf(out, "secrets version %d\n", version)
	return nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// pgService is a Postgres container: the app's own, or a drill's.
type pgService struct {
	Container, Image, User, Database, Password string
	Volume, Network                            string
	Labels                                     map[string]string
	// Env reaches the container, for its first-run scripts.
	Env []string
	// InitDir is mounted where the image runs first-run scripts.
	InitDir string
	Aliases []string
}

// postgresService describes the app's own database.
func postgresService(m *manifest.Manifest, values map[string]string, initDir string) (pgService, error) {
	user, database := m.PostgresIdentity()
	pg := m.Data.Postgres
	image := pg.Image
	if image == "" {
		image = "postgres:" + m.PostgresVersion() + "-alpine"
	}
	svc := pgService{
		Container: PostgresContainer(m.App), Image: image, User: user, Database: database,
		Password: values[postgresPasswordName], Volume: docker.VolumeName(m.App, postgresWorkload),
		Network: docker.AppNetwork(m.App), InitDir: initDir,
		Labels: map[string]string{docker.LabelApp: m.App, docker.LabelWorkload: postgresWorkload},
	}
	for _, k := range sortedKeys(pg.Env) {
		svc.Env = append(svc.Env, k+"="+pg.Env[k])
	}
	for _, name := range pg.Secrets {
		v, ok := values[name]
		if !ok {
			return svc, fmt.Errorf("the database wants the secret %s, which %s doesn't have", name, m.App)
		}
		svc.Env = append(svc.Env, name+"="+v)
	}
	return svc, nil
}

// start runs the database and waits until it accepts connections.
func (p pgService) start(ctx context.Context, e *docker.Engine, out io.Writer) error {
	if !e.HasImage(ctx, p.Image) {
		if err := e.Pull(ctx, p.Image, out); err != nil {
			return err
		}
	}
	if err := e.EnsureVolume(ctx, p.Volume); err != nil {
		return err
	}
	mounts := []string{p.Volume + ":/var/lib/postgresql/data"}
	if p.InitDir != "" {
		mounts = append(mounts, p.InitDir+":/docker-entrypoint-initdb.d:ro")
	}
	env := append([]string{"POSTGRES_USER=" + p.User, "POSTGRES_DB=" + p.Database, "POSTGRES_PASSWORD=" + p.Password, "PGDATA=/var/lib/postgresql/data/pgdata"}, p.Env...)
	err := e.Run(ctx, docker.Spec{
		Name: p.Container, Image: p.Image, Env: env, Labels: p.Labels,
		Networks: []string{p.Network}, Aliases: p.Aliases, Mounts: mounts, Restart: true,
		Isolated: true, Capabilities: []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"},
	})
	if err != nil {
		return err
	}
	// The first start runs the init scripts and restarts the server, so
	// wait for a steady answer, not the first one.
	deadline := time.Now().Add(3 * time.Minute)
	steady := 0
	for {
		if _, err := e.Exec(ctx, p.Container, nil, "pg_isready", "-h", "127.0.0.1", "-U", p.User, "-d", p.Database); err == nil {
			steady++
			if steady >= 2 {
				return nil
			}
		} else {
			steady = 0
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("postgres didn't become ready in 3m; see docker logs %s", p.Container)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// exec runs a command in the database container as its superuser,
// with the password in the environment for servers that ask for one.
func (p pgService) exec(ctx context.Context, e *docker.Engine, stdin io.Reader, args ...string) (string, error) {
	return e.ExecEnv(ctx, p.Container, map[string]string{"PGPASSWORD": p.Password}, stdin, args...)
}

// keepsOwners reports whether a dump's ownership and grants are restored:
// when the database's first-run scripts make the roles a dump names.
// Otherwise everything belongs to the app's own user.
func keepsOwners(m *manifest.Manifest) bool {
	return m.PostgresVersion() != "" && m.Data.Postgres.Init != ""
}

func ensurePostgres(ctx context.Context, e *docker.Engine, store *secrets.Store, m *manifest.Manifest, initDir, dump string, out io.Writer) error {
	values, _, err := store.LoadCurrent(m.App)
	if err != nil {
		return err
	}
	if values[postgresPasswordName] == "" {
		if err := ensureServiceCredentials(store, m, out); err != nil {
			return err
		}
		if values, _, err = store.LoadCurrent(m.App); err != nil {
			return err
		}
	}
	svc, err := postgresService(m, values, initDir)
	if err != nil {
		return err
	}
	if err := svc.start(ctx, e, out); err != nil {
		return err
	}
	fmt.Fprintf(out, "postgres %s ready as %s\n", m.PostgresVersion(), svc.Container)
	if dump == "" {
		return nil
	}
	tables, err := restoreDump(ctx, e, svc, dump, keepsOwners(m))
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "database restored from %s: %s tables\n", dump, tables)
	return nil
}

// Object store names.
const (
	objectsWorkload = "objects"
	// ObjectsImage is helios's MinIO, pinned by digest.
	ObjectsImage = "quay.io/minio/minio@sha256:a1ea29fa28355559ef137d71fc570e508a214ec84ff8083e39bc5428980b015e"
	// ObjectsUserName and ObjectsPasswordName are the object store's root
	// credentials in the app's secrets.
	ObjectsUserName     = "MINIO_ROOT_USER"
	ObjectsPasswordName = "MINIO_ROOT_PASSWORD"
)

// ObjectsContainer names an app's object store.
func ObjectsContainer(app string) string { return "bedrock-" + app + "-" + objectsWorkload }

// objectsService describes an object store container.
type objectsService struct {
	Container, Image, Volume, Network, User, Password string
	Labels                                            map[string]string
	Aliases                                           []string
}

func objectsServiceFor(m *manifest.Manifest, values map[string]string) objectsService {
	image := m.Data.Objects.Image
	if image == "" {
		image = ObjectsImage
	}
	return objectsService{
		Container: ObjectsContainer(m.App), Image: image, Volume: docker.VolumeName(m.App, objectsWorkload),
		Network: docker.AppNetwork(m.App), User: values[ObjectsUserName], Password: values[ObjectsPasswordName],
		Labels: map[string]string{docker.LabelApp: m.App, docker.LabelWorkload: objectsWorkload},
	}
}

// start runs the object store and waits until it answers.
func (o objectsService) start(ctx context.Context, e *docker.Engine, out io.Writer) error {
	if !e.HasImage(ctx, o.Image) {
		if err := e.Pull(ctx, o.Image, out); err != nil {
			return err
		}
	}
	if err := e.EnsureVolume(ctx, o.Volume); err != nil {
		return err
	}
	err := e.Run(ctx, docker.Spec{
		Name: o.Container, Image: o.Image, Cmd: []string{"server", "/data", "--console-address", ":9001"},
		Env:    []string{ObjectsUserName + "=" + o.User, ObjectsPasswordName + "=" + o.Password},
		Labels: o.Labels, Networks: []string{o.Network}, Aliases: o.Aliases,
		Mounts: []string{o.Volume + ":/data"}, Restart: true, Isolated: true,
	})
	if err != nil {
		return err
	}
	deadline := time.Now().Add(90 * time.Second)
	for {
		if info, err := e.Inspect(ctx, o.Container); err == nil {
			if ip := containerIP(info); ip != "" {
				resp, err := (&http.Client{Timeout: 3 * time.Second}).Get("http://" + ip + ":9000/minio/health/ready")
				if err == nil {
					resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						return nil
					}
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the object store didn't answer in 90s; see docker logs %s", o.Container)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func ensureObjects(ctx context.Context, e *docker.Engine, store *secrets.Store, m *manifest.Manifest, out io.Writer) error {
	values, _, err := store.LoadCurrent(m.App)
	if err != nil {
		return err
	}
	if values[ObjectsPasswordName] == "" {
		return errors.New("the object store has no credentials yet; they are made at the secrets step")
	}
	o := objectsServiceFor(m, values)
	if err := o.start(ctx, e, out); err != nil {
		return err
	}
	fmt.Fprintf(out, "object store ready as %s\n", o.Container)
	return nil
}

// InitDir is where an app's database first-run scripts are kept for
// its container to mount.
func InitDir(stateDir, app string) string {
	return filepath.Join(stateDir, "apps", app, "postgres-init")
}

// prepareInit copies the database's first-run scripts from the source to
// the directory the database container mounts, and returns it. Only
// plain files inside the source are copied: the source may come from a
// push, and this runs as root. Without a source (a rollback) the copy
// the last deploy made is used.
func prepareInit(m *manifest.Manifest, source, stateDir string) (string, error) {
	if m.PostgresVersion() == "" || m.Data.Postgres.Init == "" {
		return "", nil
	}
	dir := InitDir(stateDir, m.App)
	if source == "" {
		if dirExists(dir) {
			return dir, nil
		}
		return "", nil
	}
	root, err := filepath.EvalSymlinks(source)
	if err != nil {
		return "", err
	}
	from, err := filepath.EvalSymlinks(filepath.Join(source, m.Data.Postgres.Init))
	if err != nil {
		return "", fmt.Errorf("data.postgres.init: %w", err)
	}
	relative, err := filepath.Rel(root, from)
	if err != nil || !filepath.IsLocal(relative) {
		return "", fmt.Errorf("data.postgres.init: %s leads outside the source", m.Data.Postgres.Init)
	}
	info, err := os.Lstat(from)
	if err != nil {
		return "", fmt.Errorf("data.postgres.init: %w", err)
	}
	var files []string
	switch {
	case info.Mode().IsRegular():
		files = []string{from}
	case info.IsDir():
		entries, err := os.ReadDir(from)
		if err != nil {
			return "", err
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.Type().IsRegular() && (strings.HasSuffix(name, ".sql") || strings.HasSuffix(name, ".sh") || strings.HasSuffix(name, ".sql.gz")) {
				files = append(files, filepath.Join(from, name))
			}
		}
	default:
		return "", fmt.Errorf("data.postgres.init: %s is neither a file nor a directory", m.Data.Postgres.Init)
	}
	if len(files) == 0 {
		return "", fmt.Errorf("data.postgres.init: %s holds no .sql or .sh files", m.Data.Postgres.Init)
	}
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(f)), data, 0o644); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// restoreDump loads a pg_dump custom-format file into a database that
// has no tables yet, and returns how many it has afterwards. With keep,
// ownership and grants are restored too, for a database whose first-run
// scripts made the roles they name.
func restoreDump(ctx context.Context, e *docker.Engine, p pgService, dump string, keep bool) (string, error) {
	tables, err := tableCount(ctx, e, p)
	if err != nil {
		return "", err
	}
	if tables > 0 {
		return "", fmt.Errorf("the database already has %d tables; a restore is for an empty database", tables)
	}
	f, err := os.Open(dump)
	if err != nil {
		return "", err
	}
	defer f.Close()
	args := []string{"pg_restore", "--single-transaction", "-h", "127.0.0.1", "-U", p.User, "-d", p.Database}
	if !keep {
		args = append(args, "--no-owner", "--no-privileges")
	}
	if output, err := p.exec(ctx, e, f, args...); err != nil {
		return "", fmt.Errorf("pg_restore: %w\n%s", err, tail(output, 5))
	}
	tables, err = tableCount(ctx, e, p)
	if err != nil {
		return "", err
	}
	return strconv.Itoa(tables), nil
}

// tableCount counts the tables outside the system schemas.
func tableCount(ctx context.Context, e *docker.Engine, p pgService) (int, error) {
	out, err := scalar(ctx, e, p, "select count(*) from pg_tables where schemaname not in ('pg_catalog', 'information_schema')")
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(out)
}

// scalar runs a query that returns one value.
func scalar(ctx context.Context, e *docker.Engine, p pgService, query string) (string, error) {
	out, err := p.exec(ctx, e, nil, "psql", "-h", "127.0.0.1", "-U", p.User, "-d", p.Database, "-tAc", query)
	if err != nil {
		return "", fmt.Errorf("query: %w", err)
	}
	return strings.TrimSpace(out), nil
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

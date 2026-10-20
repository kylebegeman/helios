package watch

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kylebegeman/helios/internal/api"
	"github.com/kylebegeman/helios/internal/app"
	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/manifest"
	"github.com/kylebegeman/helios/internal/state"
)

// What the prober considers wrong.
const (
	// DiskFreeMin is the least free space on the root filesystem before
	// the disk is a problem; DiskFreePercentMin the same, as a share.
	DiskFreeMin        = 5 << 30
	DiskFreePercentMin = 10.0
	// ForecastLongWindow is how far back the disk's trend reads the
	// hourly samples the signals sampler keeps, and ForecastLongPoints how
	// many it needs; ForecastShortWindow and ForecastShortPoints the same
	// for the minute samples the prober keeps in memory.
	ForecastLongWindow  = 7 * 24 * time.Hour
	ForecastLongPoints  = 48
	ForecastShortWindow = 6 * time.Hour
	ForecastShortPoints = 60
	// ForecastShortRecent is the newest stretch of the minute samples,
	// and ForecastShortRecentPoints how many it needs, that must still
	// climb before the short trend pages. The 6 hour trend keeps reading
	// a download that finished hours ago as growth; the last hour says
	// whether it goes on. Half the hour's minutes leaves room for missed
	// rounds and still gives the fit enough points to see past noise.
	ForecastShortRecent       = time.Hour
	ForecastShortRecentPoints = 30
	// DiskFullWarn and DiskFullCritical are how soon the long trend may
	// fill the disk before it is a warning and a critical problem.
	// DiskFullFast is how soon the short trend may fill it, such as a
	// runaway log, before it is critical.
	DiskFullWarn     = 14 * 24 * time.Hour
	DiskFullCritical = 48 * time.Hour
	DiskFullFast     = 6 * time.Hour
	// DiskShiftPercentMin and DiskShiftMax size the smallest step in
	// usage, across all its samples, the trends may set aside as a
	// one-off, such as a cleanup or a large download: 1% of the
	// filesystem, but no more than 1 GiB, so a 9 GB cleanup on a 1 TB
	// disk still counts. Smaller changes, such as quiet noise on a flat
	// disk, are left to the fit.
	DiskShiftPercentMin = 1.0
	DiskShiftMax        = 1 << 30
	// MemoryAvailableMin is the smallest share of memory that may be
	// available.
	MemoryAvailableMin = 5.0
	// CertificateWarn is how close to expiry a certificate may get.
	CertificateWarn = 14 * 24 * time.Hour
	// OriginPullWarn is how close to expiry an origin-pull CA may get,
	// longer than CertificateWarn because nothing renews it: a person
	// mints a new one and uploads it at Cloudflare.
	OriginPullWarn = 30 * 24 * time.Hour
	// BackupStale is how old the last good backup may be.
	BackupStale = 36 * time.Hour
	// DataCheckEvery is how often a workload's volumes are walked for
	// files it can't write. A walk reads every entry, so rounds between
	// walks reuse the last answer.
	DataCheckEvery = time.Hour
	// EdgeAddress is where the machine's own edge answers TLS.
	EdgeAddress = "127.0.0.1:443"
	// OperationLockStale is how long one operation may hold the machine's
	// operation lock before it is a problem. It is a heuristic, not an upper
	// bound on healthy work: an app backup's bounded repository calls add
	// up to about 3 h 25 min, plus up to two minutes of cleanup for each
	// call that is stopped, while a machine backup also copies each data
	// app's pinned snapshot in (up to 2 h each) and archives the workload
	// images (up to 1 h). A slow machine backup on a host with several
	// data apps can cross it.
	OperationLockStale = 4 * time.Hour
	// RetentionDeferredStale is how long every backup of a repository may
	// defer its retention before the growing repository is a problem.
	RetentionDeferredStale = 72 * time.Hour
	// SkippedDrillStale is how old the last good drill may be when the
	// drill after a skipped one runs, before the skip is a problem.
	SkippedDrillStale = 14 * 24 * time.Hour
	// HoldEndingSoon is how near its end a cron hold warns, so whoever
	// placed it can extend it before the workload runs again.
	HoldEndingSoon = 24 * time.Hour
	// BackupPauseGrace is how long past app.BackupPauseLimit a backup's
	// pause may stand, for its writers to start again, before it is a
	// problem.
	BackupPauseGrace = 5 * time.Minute
)

// Prober looks at the machine and its apps and reports what is wrong.
type Prober struct {
	Store *state.Store
	Now   func() time.Time
	// Connect opens Docker; the default is the real one.
	Connect func(ctx context.Context) (*docker.Engine, error)
	// Root is the filesystem whose free space matters.
	Root string
	// Disk reads a filesystem's free and total bytes; nil means DiskFree.
	Disk func(path string) (free, total uint64, ok bool)
	// CheckSecrets loads only the revision-bound credentials used by checks.
	CheckSecrets func(app string, version int) (map[string]string, error)
	// OriginPullTrust reads the CAs the edge's origin-pull hosts trust;
	// nil leaves origin pull unwatched.
	OriginPullTrust func() (edge.OriginPullTrust, error)
	// OperationLockStale overrides how long the operation lock may be
	// held; zero means OperationLockStale.
	OperationLockStale time.Duration

	// mu keeps rounds from overlapping.
	mu sync.Mutex
	// restartsMu guards restarts, which one goroutine per app writes in a
	// round.
	restartsMu sync.Mutex
	restarts   map[string]int
	// dataMu guards data, the last walk of each container's volumes.
	dataMu sync.Mutex
	data   map[string]dataScan
	// minutes holds the bytes in use on Root at each round of the last
	// ForecastShortWindow, at most minutesKept of them. A restart starts
	// it empty.
	minutes []Point
}

// minutesKept bounds the minute ring, whose fit takes time and memory
// that grow with the square of its length. Rounds come once a minute, so
// twice the window's minutes leaves room for extra rounds.
const minutesKept = 2 * int(ForecastShortWindow/time.Minute)

// dataScan is one walk of one volume a container mounts.
type dataScan struct {
	at      time.Time
	problem string
}

// NewProber returns a prober for this machine.
func NewProber(store *state.Store) *Prober {
	return &Prober{Store: store, Now: func() time.Time { return time.Now().UTC() }, Connect: docker.Connect, Root: "/", restarts: map[string]int{}}
}

// Observe takes one look at everything and returns the conditions that
// hold right now. The host, each app and each watched URL get at most
// one condition each.
func (p *Prober) Observe(ctx context.Context) []Condition {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.restarts == nil {
		p.restarts = map[string]int{}
	}
	p.forgetOldScans(p.Now())
	var conditions []Condition
	conditions = append(conditions, p.host(ctx)...)
	conditions = append(conditions, p.operationLock(ctx)...)
	conditions = append(conditions, p.operatorHolds(ctx)...)
	conditions = append(conditions, p.originPull(ctx)...)
	conditions = append(conditions, p.alertTest()...)
	if why := p.retentionProblem(ctx, manifest.ReservedApp, p.Now()); why != "" {
		conditions = append(conditions, Condition{Key: "host:backup-retention", Subject: "machine backups", Severity: state.SeverityWarning, Message: why})
	}
	if why := p.machineBackupProblem(ctx, p.Now()); why != "" {
		conditions = append(conditions, Condition{Key: "host:machine-backup", Subject: "machine backups", Severity: state.SeverityWarning, Message: why})
	}

	e, err := p.Connect(ctx)
	if err != nil {
		conditions = append(conditions, Condition{Key: "host:docker", Subject: "docker", Severity: state.SeverityCritical, Message: "docker isn't answering: " + err.Error()})
		conditions = append(conditions, p.unobservedIncidents(ctx)...)
		return append(conditions, p.watches(ctx)...)
	}
	defer e.Close()
	if info, err := e.Inspect(ctx, edge.Container); err != nil || !info.Running {
		conditions = append(conditions, Condition{Key: "host:edge", Subject: "the edge", Severity: state.SeverityCritical, Message: "the edge (bedrock-edge) isn't running; no site is reachable"})
	}

	active, err := p.Store.ActiveRevisions(ctx)
	if err != nil {
		conditions = append(conditions, p.unobservedIncidents(ctx)...)
		return append(conditions, Condition{Key: "host:state", Subject: "the state store", Severity: state.SeverityCritical, Message: err.Error()})
	}
	currentContainers := map[string]bool{}
	for _, rev := range active {
		for _, container := range rev.Containers {
			currentContainers[container] = true
		}
	}
	p.restartsMu.Lock()
	for container := range p.restarts {
		if !currentContainers[container] {
			delete(p.restarts, container)
		}
	}
	p.restartsMu.Unlock()
	type finding struct {
		app      string
		severity string
		problems []string
	}
	findings := make([]finding, len(active))
	var wg sync.WaitGroup
	for i, rev := range active {
		wg.Add(1)
		go func(i int, rev state.Revision) {
			defer wg.Done()
			f := finding{app: rev.App}
			f.severity, f.problems = p.app(ctx, e, rev)
			findings[i] = f
		}(i, rev)
	}
	wg.Wait()
	for _, f := range findings {
		if len(f.problems) > 0 {
			conditions = append(conditions, Condition{Key: "app:" + f.app, Subject: f.app, Severity: f.severity, Message: strings.Join(f.problems, "; ")})
		}
	}
	return append(conditions, p.watches(ctx)...)
}

// Missing observations during an infrastructure outage cannot certify that
// an existing app or edge incident recovered.
func (p *Prober) unobservedIncidents(ctx context.Context) []Condition {
	incidents, err := p.Store.OpenIncidents(ctx)
	if err != nil {
		return nil
	}
	var conditions []Condition
	for _, incident := range incidents {
		if strings.HasPrefix(incident.Key, "app:") || incident.Key == "host:edge" {
			conditions = append(conditions, Condition{Key: incident.Key, Unknown: true})
		}
	}
	return conditions
}

// Operator holds are their own subjects, so a skipped drill or a held cron
// workload never reads as the app's health.
func drillSkipKey(appName string) string          { return "skip:" + appName }
func cronHoldKey(appName, workload string) string { return "hold:" + appName + "/" + workload }

func operatorKey(key string) bool {
	return strings.HasPrefix(key, "skip:") || strings.HasPrefix(key, "hold:")
}

// operatorHolds reports each skipped drill and each held cron workload as a
// notice naming the operator's reason and when it ends. A skip warns when
// the drill after it would find the last good drill too old, and a hold
// warns when it is about to end.
func (p *Prober) operatorHolds(ctx context.Context) []Condition {
	now := p.Now()
	active, err := p.Store.ActiveRevisions(ctx)
	if err != nil {
		return p.unobserved(ctx, "skip:", "hold:")
	}
	var conditions []Condition
	for _, rev := range active {
		var m manifest.Manifest
		if err := json.Unmarshal(rev.Manifest, &m); err != nil {
			continue
		}
		if m.BackedUp() {
			if c, ok := p.drillSkip(ctx, rev.App, m.DrillSchedule()); ok {
				conditions = append(conditions, c)
			}
		}
		for _, name := range m.WorkloadNames() {
			if m.Workloads[name].Kind != manifest.Cron {
				continue
			}
			key := cronHoldKey(rev.App, name)
			hold, err := app.ActiveCronHold(ctx, p.Store, rev.App, name, now)
			if err != nil {
				conditions = append(conditions, Condition{Key: key, Unknown: true})
				continue
			}
			if hold == nil {
				continue
			}
			c := Condition{Key: key, Subject: rev.App + "/" + name + " cron", Severity: state.SeverityNotice,
				Message: fmt.Sprintf("held until %s: %s", app.OperatorTime(hold.FinishedAt), hold.Output)}
			if left := hold.FinishedAt.Sub(now); left <= HoldEndingSoon {
				c.Severity = state.SeverityWarning
				c.Message += fmt.Sprintf("; the hold ends in %s and the workload runs again on its schedule", ago(now, hold.FinishedAt))
			}
			conditions = append(conditions, c)
		}
	}
	return conditions
}

// unobserved holds open each incident whose key starts with one of
// prefixes, for subjects that couldn't be looked at this round.
func (p *Prober) unobserved(ctx context.Context, prefixes ...string) []Condition {
	incidents, err := p.Store.OpenIncidents(ctx)
	if err != nil {
		return nil
	}
	var out []Condition
	for _, incident := range incidents {
		for _, prefix := range prefixes {
			if strings.HasPrefix(incident.Key, prefix) {
				out = append(out, Condition{Key: incident.Key, Unknown: true})
				break
			}
		}
	}
	return out
}

// drillSkip is the condition of an app whose drill an operator skipped.
func (p *Prober) drillSkip(ctx context.Context, appName, schedule string) (Condition, bool) {
	key := drillSkipKey(appName)
	skip, err := app.ActiveDrillSkip(ctx, p.Store, appName)
	if err != nil {
		return Condition{Key: key, Unknown: true}, true
	}
	if skip == nil {
		return Condition{}, false
	}
	next, err := app.NextDrill(ctx, p.Store, appName, schedule)
	if err != nil {
		return Condition{Key: key, Unknown: true}, true
	}
	good, err := p.Store.LastGoodBackupRun(ctx, appName, state.BackupRunDrill)
	if err != nil {
		return Condition{Key: key, Unknown: true}, true
	}
	c := Condition{Key: key, Subject: appName + " restore drill", Severity: state.SeverityNotice,
		Message: fmt.Sprintf("the drill due %s is skipped by operator: %s; the next drill is due %s", app.OperatorTime(skip.StartedAt), skip.Detail, app.OperatorTime(next))}
	switch {
	case good == nil:
		c.Severity = state.SeverityWarning
		c.Message += "; no drill has passed yet, so no restore of its backups is proven"
	case next.Sub(good.StartedAt) > SkippedDrillStale:
		c.Severity = state.SeverityWarning
		c.Message += fmt.Sprintf("; by then the last good drill will be %s old", ago(good.StartedAt, next))
	}
	return c, true
}

// app looks at one app's containers, health, checks, certificates and
// backups and returns the worst severity and every problem.
func (p *Prober) app(ctx context.Context, e *docker.Engine, rev state.Revision) (string, []string) {
	fenced, err := app.MigrationSourceFenced(p.Store.Path(), rev.App)
	if err != nil {
		return state.SeverityCritical, []string{"its migration fence cannot be read: " + err.Error()}
	}
	if fenced {
		// Final capture deliberately stops this source and suspends its
		// checks and scheduled backups. Host probes remain independent.
		return "", nil
	}
	var m manifest.Manifest
	if err := json.Unmarshal(rev.Manifest, &m); err != nil {
		return state.SeverityWarning, []string{"its manifest can't be read: " + err.Error()}
	}
	now := p.Now()
	var problems []string
	severity := ""
	worse := func(s string) {
		if severity == "" || s == state.SeverityCritical {
			severity = s
		}
	}
	// A backup stops the app's writers so it copies their data whole, for
	// at most app.BackupPauseLimit. Only a pause that outlives it is news.
	pause, err := app.ReadBackupPause(p.Store.Path(), rev.App)
	if err != nil {
		problems = append(problems, "its backup pause can't be read: "+err.Error())
		worse(state.SeverityCritical)
	} else if pause != nil && now.Sub(pause.Since) > app.BackupPauseLimit+BackupPauseGrace {
		problems = append(problems, fmt.Sprintf("it has been paused for a backup for %d minutes", int(now.Sub(pause.Since).Minutes())))
		worse(state.SeverityCritical)
	}
	for _, name := range m.WorkloadNames() {
		w := m.Workloads[name]
		if !w.LongRunning() {
			continue
		}
		container := rev.Containers[name]
		info, err := e.Inspect(ctx, container)
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf("%s has no container", name))
			worse(state.SeverityCritical)
			continue
		case !info.Running && w.Singleton && p.deploying(ctx, rev.App):
			// A deploy stopped it to start its successor.
			continue
		case !info.Running && pause != nil && pause.Holds(info.ID, container):
			// The backup's pause is reported once, above, if it ran long.
			continue
		case !info.Running:
			since := ""
			if !info.FinishedAt.IsZero() {
				since = " " + ago(info.FinishedAt, now) + " ago"
			}
			problems = append(problems, fmt.Sprintf("%s isn't running (%s%s, exit code %d)", name, info.Status, since, info.ExitCode))
			worse(state.SeverityCritical)
			continue
		}
		p.restartsMu.Lock()
		last, seen := p.restarts[container]
		p.restarts[container] = info.Restarts
		p.restartsMu.Unlock()
		if seen && info.Restarts > last {
			problems = append(problems, fmt.Sprintf("%s keeps restarting (%d restarts)", name, info.Restarts))
			worse(state.SeverityCritical)
		}
		if w.Health != nil && len(w.Health.Command) > 0 {
			if err := app.HealthCommand(ctx, e, container, w.Health.Command); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", name, err))
				worse(state.SeverityCritical)
			}
		} else if w.Health != nil && w.Health.Path != "" && w.Serves() {
			if why := healthProblem(ctx, info, w); why != "" {
				problems = append(problems, fmt.Sprintf("%s's %s %s", name, w.Health.Path, why))
				worse(state.SeverityCritical)
			}
		}
		// A workload that answers can still be unable to save anything.
		for _, why := range p.dataProblems(rev.App, name, info, now) {
			problems = append(problems, why)
			worse(state.SeverityCritical)
		}
	}
	values := map[string]string{}
	if len(app.CheckSecretNames(&m)) > 0 {
		if p.CheckSecrets == nil {
			problems = append(problems, "check credentials cannot be loaded")
			worse(state.SeverityCritical)
		} else if loaded, err := p.CheckSecrets(rev.App, rev.SecretsVersion); err != nil {
			problems = append(problems, "check credentials cannot be loaded")
			worse(state.SeverityCritical)
		} else {
			values = loaded
		}
	}
	// An app's checks can't pass while its writers are paused.
	if pause == nil {
		for _, err := range app.RunAppChecks(ctx, e, &m, rev.Containers, values) {
			problems = append(problems, strings.TrimPrefix(err.Error(), "check "))
			worse(state.SeverityCritical)
		}
	}
	for _, host := range m.Hosts() {
		ready, why, expiry, found := edge.Certificate(ctx, host, EdgeAddress)
		if !found {
			continue // the edge condition covers a dead edge
		}
		if !ready {
			problems = append(problems, fmt.Sprintf("%s has no valid certificate: %s", host, why))
			worse(state.SeverityCritical)
			continue
		}
		if left := expiry.Sub(now); left < CertificateWarn {
			problems = append(problems, fmt.Sprintf("the certificate for %s expires in %d days and hasn't renewed", host, int(left.Hours()/24)))
			worse(state.SeverityWarning)
		}
	}
	if m.BackedUp() {
		if why := p.backupProblem(ctx, rev.App, now); why != "" {
			problems = append(problems, why)
			worse(state.SeverityWarning)
		}
		if why := p.retentionProblem(ctx, rev.App, now); why != "" {
			problems = append(problems, why)
			worse(state.SeverityWarning)
		}
		if last, err := p.Store.LastBackupRun(ctx, rev.App, state.BackupRunDrill); err == nil && last != nil && last.Finished() && !last.OK {
			problems = append(problems, "the last restore drill failed: "+last.Error)
			worse(state.SeverityWarning)
		}
	}
	return severity, problems
}

// dataProblems walks the volumes a running workload mounts for files and
// directories its user can't write, at most once per DataCheckEvery for
// each volume. Root, or a user helios didn't set, needs no walk; a
// volume that can't be walked says nothing rather than something wrong.
func (p *Prober) dataProblems(appName, workload string, info *docker.Info, now time.Time) []string {
	u, ok := docker.ParseUser(info.User)
	if !ok || u.Root() {
		return nil
	}
	var out []string
	for _, v := range info.Volumes {
		if !v.RW || v.Source == "" {
			continue
		}
		key := info.Name + " " + v.Name
		p.dataMu.Lock()
		scan, seen := p.data[key]
		p.dataMu.Unlock()
		if !seen || now.Sub(scan.at) >= DataCheckEvery {
			scan = dataScan{at: now}
			if x, err := docker.UnwritableBy(v.Source, u); err == nil {
				scan.problem = x.Problem(workload, u, docker.AppVolume(appName, v.Name))
			}
			p.dataMu.Lock()
			if p.data == nil {
				p.data = map[string]dataScan{}
			}
			p.data[key] = scan
			p.dataMu.Unlock()
		}
		if scan.problem != "" {
			out = append(out, scan.problem+"; helios doctor says how to give them back")
		}
	}
	return out
}

// forgetOldScans drops walks of containers that are gone, which stop
// being refreshed once a deploy replaces them.
func (p *Prober) forgetOldScans(now time.Time) {
	p.dataMu.Lock()
	defer p.dataMu.Unlock()
	for key, scan := range p.data {
		if now.Sub(scan.at) > 2*DataCheckEvery {
			delete(p.data, key)
		}
	}
}

// deploying reports whether a deploy or rollback of the app is under way.
func (p *Prober) deploying(ctx context.Context, appName string) bool {
	ops, err := p.Store.List(ctx, 20)
	if err != nil {
		return false
	}
	for _, op := range ops {
		// The target is the app; before 0.7.8 it was "app revision".
		if (op.Kind == app.DeployKind || op.Kind == app.RollbackKind) && !op.Status.Final() && (op.Target == appName || strings.HasPrefix(op.Target, appName+" ")) {
			return true
		}
	}
	return false
}

// backupProblem says when an app's last good backup is too old, giving a
// new app time for its first one.
func (p *Prober) backupProblem(ctx context.Context, appName string, now time.Time) string {
	last, err := p.Store.LastGoodBackupRun(ctx, appName, state.BackupRunBackup)
	if err != nil {
		return ""
	}
	if last != nil {
		if age := now.Sub(last.StartedAt); age > BackupStale {
			return fmt.Sprintf("no successful backup for %s (the last was %s)", ago(last.StartedAt, now), last.StartedAt.Format("2006-01-02 15:04"))
		}
		return ""
	}
	first, err := p.Store.FirstRevisionCreatedAt(ctx, appName)
	if err != nil {
		return ""
	}
	if now.Sub(first) > BackupStale {
		return fmt.Sprintf("never backed up, deployed %s ago", ago(first, now))
	}
	return ""
}

// machineBackupProblem says when the machine's own backup hasn't
// succeeded for too long, and why the last one that finished failed. A
// machine that has never tried one says nothing; machine backups wait
// for the storage integration. backupProblem doesn't fit: with no good
// backup it counts from the app's first deploy, and the machine has none.
func (p *Prober) machineBackupProblem(ctx context.Context, now time.Time) string {
	good, err := p.Store.LastGoodBackupRun(ctx, manifest.ReservedApp, state.BackupRunBackup)
	if err != nil || good != nil && now.Sub(good.StartedAt) <= BackupStale {
		return ""
	}
	// The last run to finish, not the last to start: a retry still
	// running hasn't recovered anything, and mustn't read as if it had.
	runs, err := p.Store.BackupRuns(ctx, manifest.ReservedApp, state.BackupRunBackup, 50)
	if err != nil {
		return ""
	}
	var last *state.BackupRun
	for i := range runs {
		if runs[i].Finished() {
			last = &runs[i]
			break
		}
	}
	// A recovery imports the source's runs, with the one that captured the
	// machine closed as interrupted there, though it never failed here. So
	// until a backup finishes here, a recovered machine gets BackupStale
	// from its import, as a new app gets it from its first deploy. One that
	// fails here ends that at once: what it says is this machine's own. A
	// good backup imported fresh still keeps it quiet, as on any machine.
	if last != nil {
		imported, err := p.Store.LastMachineRecoveryImportedAt(ctx)
		if err != nil {
			return ""
		}
		if !last.FinishedAt.After(imported) && now.Sub(imported) <= BackupStale {
			return ""
		}
	}
	failed := last != nil && !last.OK
	var why string
	switch {
	case good != nil:
		why = fmt.Sprintf("no successful machine backup for %s (the last was %s)", ago(good.StartedAt, now), good.StartedAt.Format("2006-01-02 15:04"))
	case failed:
		why = "no machine backup has succeeded yet"
	default:
		return "" // none has finished yet
	}
	if failed && last.Error != "" {
		line, _, _ := strings.Cut(last.Error, "\n")
		why += fmt.Sprintf("; the last one, started %s, failed: %s", last.StartedAt.Format("2006-01-02 15:04"), line)
	}
	return why
}

// retentionProblem says when every good backup of a repository has
// deferred its retention for too long. Each deferral still keeps a good
// snapshot, so backups look fresh while old snapshots stay and the
// repository grows.
func (p *Prober) retentionProblem(ctx context.Context, appName string, now time.Time) string {
	runs, err := p.Store.BackupRuns(ctx, appName, state.BackupRunBackup, 50)
	if err != nil {
		return ""
	}
	var since time.Time
	var reason string
	for _, run := range runs {
		if !run.OK {
			continue
		}
		_, why, deferred := strings.Cut(run.Detail, app.RetentionDeferred+": ")
		if !deferred {
			break
		}
		if reason == "" {
			reason = why
		}
		since = run.StartedAt
	}
	if since.IsZero() || now.Sub(since) < RetentionDeferredStale {
		return ""
	}
	return fmt.Sprintf("every backup since %s (%s ago) deferred retention, so old snapshots stay and the repository keeps growing; the last said: %s", since.Format("2006-01-02 15:04"), ago(since, now), reason)
}

// healthProblem asks a workload's health path directly.
func healthProblem(ctx context.Context, info *docker.Info, w manifest.Workload) string {
	ip := info.IPs[docker.EdgeNetwork]
	if ip == "" {
		for _, v := range info.IPs {
			ip = v
		}
	}
	if ip == "" {
		return "can't be reached: no address"
	}
	port := w.Port
	if w.Kind == manifest.Static {
		port, _ = strconv.Atoi(docker.StaticPort)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(ip, strconv.Itoa(port))+w.Health.Path, nil)
	if err != nil {
		return err.Error()
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "doesn't answer: " + trimURLError(err.Error())
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "answers " + resp.Status
	}
	return ""
}

func trimURLError(s string) string {
	if i := strings.LastIndex(s, ": "); i >= 0 {
		return s[i+2:]
	}
	return s
}

// watches checks the URLs this machine watches from the outside.
func (p *Prober) watches(ctx context.Context) []Condition {
	watches, err := p.Store.Watches(ctx)
	if err != nil || len(watches) == 0 {
		return nil
	}
	conditions := make([]Condition, len(watches))
	var wg sync.WaitGroup
	for i, w := range watches {
		wg.Add(1)
		go func(i int, url string) {
			defer wg.Done()
			if err := app.RunCheck(ctx, manifest.Check{URL: url}); err != nil {
				conditions[i] = Condition{Key: "watch:" + url, Subject: url, Severity: state.SeverityCritical, Message: strings.TrimPrefix(err.Error(), "check ")}
			}
		}(i, w.URL)
	}
	wg.Wait()
	var out []Condition
	for _, c := range conditions {
		if c.Key != "" {
			out = append(out, c)
		}
	}
	return out
}

// host looks at disk and memory.
func (p *Prober) host(ctx context.Context) []Condition {
	var out []Condition
	read := p.Disk
	if read == nil {
		read = DiskFree
	}
	if free, total, ok := read(p.Root); ok && total > 0 && free <= total {
		now := p.Now()
		// Samples after now come from before the wall clock stepped
		// back. They would never age out of the window, so they go.
		for len(p.minutes) > 0 && p.minutes[len(p.minutes)-1].At.After(now) {
			p.minutes = p.minutes[:len(p.minutes)-1]
		}
		p.minutes = append(p.minutes, Point{At: now, Used: float64(total - free)})
		kept := max(0, len(p.minutes)-minutesKept)
		for kept < len(p.minutes) && !p.minutes[kept].At.After(now.Add(-ForecastShortWindow)) {
			kept++
		}
		p.minutes = append(p.minutes[:0], p.minutes[kept:]...)
		disk, forecast := diskConditions(p.Root, free, total, p.hourlyDisk(ctx, now), p.minutes)
		if forecast != nil {
			forecast.Message += p.fastestGrowing(ctx, now)
			out = append(out, *forecast)
		}
		if disk != nil {
			out = append(out, *disk)
		}
	}
	if available, total, ok := Memory(); ok {
		pct := float64(available) / float64(total) * 100
		if pct < MemoryAvailableMin {
			out = append(out, Condition{Key: "host:memory", Subject: "memory", Severity: state.SeverityWarning, Message: fmt.Sprintf("only %s of %s available (%.0f%%)", app.HumanBytes(int64(available)), app.HumanBytes(int64(total)), pct)})
		}
	}
	return out
}

// diskConditions judges the root filesystem from its free space now and
// the bytes in use at each hour of the last ForecastLongWindow and each
// round of the last ForecastShortWindow. Under DiskFreeMin is critical.
// Under DiskFreePercentMin is critical too, unless the long trend has
// enough points and says the disk lasts beyond DiskFullWarn, or isn't
// filling: then it is a warning. The forecast is a problem of its own,
// for how soon either trend fills the disk, the short one only while
// usage still climbs over the last ForecastShortRecent.
func diskConditions(root string, free, total uint64, hourly, minutes []Point) (disk, forecast *Condition) {
	// A lone cleanup or download moves every sample after it; set aside,
	// only the steady growth around it counts.
	floor := math.Min(float64(total)*DiskShiftPercentMin/100, DiskShiftMax)
	long, longOK := Forecast(WithoutShifts(hourly, floor), ForecastLongPoints, free)
	minutes = WithoutShifts(minutes, floor)
	short, shortOK := Forecast(minutes, ForecastShortPoints, free)
	// The short trend pages only while usage still climbs.
	shortOK = shortOK && StillClimbing(minutes, ForecastShortRecent, ForecastShortRecentPoints, short.PerSecond)
	longDays := fmt.Sprintf("%d day", int(ForecastLongWindow/(24*time.Hour)))
	shortHours := fmt.Sprintf("%d hour", int(ForecastShortWindow/time.Hour))

	pct := float64(free) / float64(total) * 100
	low := fmt.Sprintf("only %s free of %s (%.0f%%) on %s", app.HumanBytes(int64(free)), app.HumanBytes(int64(total)), pct, root)
	switch {
	case free < DiskFreeMin:
		disk = &Condition{Key: "host:disk", Subject: "disk", Severity: state.SeverityCritical, Message: low}
	case pct < DiskFreePercentMin && len(hourly) >= ForecastLongPoints && !longOK:
		disk = &Condition{Key: "host:disk", Subject: "disk", Severity: state.SeverityWarning, Message: fmt.Sprintf("%s, but the %s trend isn't growing", low, longDays)}
	case pct < DiskFreePercentMin && longOK && long.Full > DiskFullWarn:
		disk = &Condition{Key: "host:disk", Subject: "disk", Severity: state.SeverityWarning, Message: fmt.Sprintf("%s, which lasts %s at %s a day (%s trend)", low, lasting(long.Full), app.HumanBytes(int64(long.PerSecond*86400)), longDays)}
	case pct < DiskFreePercentMin:
		disk = &Condition{Key: "host:disk", Subject: "disk", Severity: state.SeverityCritical, Message: low}
	}

	if longOK && long.Full <= DiskFullWarn {
		severity := state.SeverityWarning
		if long.Full <= DiskFullCritical {
			severity = state.SeverityCritical
		}
		forecast = &Condition{Key: "host:disk-forecast", Subject: "free disk space", Severity: severity,
			Message: fmt.Sprintf("fills in %s at %s a day (%s trend), %s free", lasting(long.Full), app.HumanBytes(int64(long.PerSecond*86400)), longDays, app.HumanBytes(int64(free)))}
	}
	if shortOK && short.Full <= DiskFullFast && (forecast == nil || forecast.Severity != state.SeverityCritical || short.Full < long.Full) {
		forecast = &Condition{Key: "host:disk-forecast", Subject: "free disk space", Severity: state.SeverityCritical,
			Message: fmt.Sprintf("fills in %s at %s an hour (%s trend), %s free", lasting(short.Full), app.HumanBytes(int64(short.PerSecond*3600)), shortHours, app.HumanBytes(int64(free)))}
	}
	return disk, forecast
}

// lasting says how long a forecast gives, roughly.
func lasting(d time.Duration) string {
	switch {
	case d > 365*24*time.Hour:
		return "over a year"
	case d >= 48*time.Hour:
		return fmt.Sprintf("about %d days", int(math.Round(d.Hours()/24)))
	case d >= 2*time.Hour:
		return fmt.Sprintf("about %d hours", int(math.Round(d.Hours())))
	case d >= 90*time.Second:
		return fmt.Sprintf("about %d minutes", int(math.Round(d.Minutes())))
	default:
		return "about a minute"
	}
}

// hourlyDisk reads the largest bytes in use on the root filesystem in each
// hour of the last ForecastLongWindow, as the signals sampler kept them.
func (p *Prober) hourlyDisk(ctx context.Context, now time.Time) []Point {
	rows, err := p.Store.Signals(ctx, manifest.ReservedApp, now.Add(-ForecastLongWindow))
	if err != nil {
		return nil
	}
	var points []Point
	for _, r := range rows {
		if r.Key == state.SignalHostDiskRoot && r.Metric == state.SignalHostDiskUsed {
			points = append(points, Point{At: r.Hour, Used: r.Value})
		}
	}
	return points
}

// fastestGrowing names the deployed app whose volumes and database grew
// most over the last ForecastLongWindow, from their hourly disk samples,
// or says nothing when none grew.
func (p *Prober) fastestGrowing(ctx context.Context, now time.Time) string {
	active, err := p.Store.ActiveRevisions(ctx)
	if err != nil {
		return ""
	}
	deployed := map[string]bool{}
	for _, rev := range active {
		deployed[rev.App] = true
	}
	rows, err := p.Store.MetricSignals(ctx, state.SignalDiskBytes, now.Add(-ForecastLongWindow))
	if err != nil {
		return ""
	}
	first, last := map[string]state.Signal{}, map[string]state.Signal{}
	for _, r := range rows {
		if !deployed[r.App] {
			continue
		}
		if _, seen := first[r.App]; !seen {
			first[r.App] = r
		}
		last[r.App] = r
	}
	names := make([]string, 0, len(first))
	for name := range first {
		names = append(names, name)
	}
	sort.Strings(names)
	best, grew := "", 0.0
	for _, name := range names {
		if d := last[name].Value - first[name].Value; d > grew {
			best, grew = name, d
		}
	}
	if best == "" {
		return ""
	}
	return fmt.Sprintf("; of the apps, %s grew most, by %s in %s", best, app.HumanBytes(int64(grew)), lasting(last[best].Hour.Sub(first[best].Hour)))
}

// operationLock reports the machine's operation lock when one operation has
// held it too long. Everything else that changes the machine waits behind
// it, so a stuck holder silently stops backups and deploys.
func (p *Prober) operationLock(ctx context.Context) []Condition {
	limit := p.OperationLockStale
	if limit <= 0 {
		limit = OperationLockStale
	}
	lock, held, err := api.HeldOperationLock(p.Store.Path())
	now := p.Now()
	// An undated lock comes from a release that didn't record when it
	// took it; it can't be judged, and is gone after the upgrade.
	if err != nil || !held || lock.AcquiredAt.IsZero() || now.Sub(lock.AcquiredAt) < limit {
		return nil
	}
	msg := fmt.Sprintf("the machine's operation lock has been held for %s, since %s", ago(lock.AcquiredAt, now), lock.AcquiredAt.UTC().Format("2006-01-02 15:04 UTC"))
	if ops, err := p.Store.ListFiltered(ctx, state.OperationFilter{Limit: 20}); err == nil {
		var running []string
		for _, op := range ops {
			if !op.Status.Final() {
				running = append(running, fmt.Sprintf("%s %s (%s)", op.Kind, op.Target, op.ID))
			}
		}
		if len(running) > 0 {
			msg += " by " + strings.Join(running, ", ")
		}
	}
	msg += "; scheduled backups, drills and deploys wait until it is released"
	return []Condition{{Key: "host:operations", Subject: "machine operations", Severity: state.SeverityWarning, Message: msg}}
}

// DiskFree reports free and total bytes on a filesystem.
func DiskFree(path string) (free, total uint64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, false
	}
	return st.Bavail * uint64(st.Bsize), st.Blocks * uint64(st.Bsize), true
}

// Memory reads available and total memory from /proc/meminfo.
func Memory() (available, total uint64, ok bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		kb, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			total = kb * 1024
		case "MemAvailable:":
			available = kb * 1024
		}
	}
	return available, total, total > 0
}

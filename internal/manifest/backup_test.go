package manifest

import (
	"strings"
	"testing"
)

const withDataApp = `app: dragon-writer
workloads:
  web:
    kind: web
    image: local/dw:1
    port: 3000
    routes:
      - host: dragonwriter.begam.in
data:
  postgres:
    version: "16"
  volumes:
    uploads: {}
`

func TestBackupsDefaultForAnAppWithData(t *testing.T) {
	m, err := Parse([]byte(withDataApp))
	if err != nil {
		t.Fatal(err)
	}
	if !m.HasData() || !m.BackedUp() {
		t.Fatal("an app with data is backed up by default")
	}
	if m.BackupSchedule() != DefaultBackupSchedule || m.DrillSchedule() != DefaultDrillSchedule || m.KeepPolicy() != DefaultKeep {
		t.Fatalf("defaults: %s %s %+v", m.BackupSchedule(), m.DrillSchedule(), m.KeepPolicy())
	}
	if sql, _ := m.VerifyQuery(); sql != "" {
		t.Fatal("no verify query by default")
	}
	m2, err := Parse([]byte(withDataApp + `backup:
  schedule: "*/2 * * * *"
  drill: "0 5 * * 1"
  keep: {daily: 3, weekly: 1}
  verify:
    sql: select count(*) from story_chapters
    at_least: 30
`))
	if err != nil {
		t.Fatal(err)
	}
	if m2.BackupSchedule() != "*/2 * * * *" || m2.DrillSchedule() != "0 5 * * 1" || m2.KeepPolicy().Monthly != 0 || m2.KeepPolicy().Daily != 3 {
		t.Fatalf("%+v", m2.Backup)
	}
	if sql, atLeast := m2.VerifyQuery(); !strings.HasPrefix(sql, "select count") || atLeast != 30 {
		t.Fatalf("%q %d", sql, atLeast)
	}
	off, err := Parse([]byte(withDataApp + "backup:\n  off: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if off.BackedUp() {
		t.Fatal("off means off")
	}
}

func TestBackupSectionIsValidated(t *testing.T) {
	cases := []struct{ yaml, want string }{
		{withDataApp + "backup:\n  schedule: often\n", "backup.schedule"},
		{withDataApp + "backup:\n  drill: \"99 * * * *\"\n", "backup.drill"},
		{withDataApp + "backup:\n  keep: {daily: 0}\n", "at least one"},
		{withDataApp + "backup:\n  verify:\n    sql: \"  \"\n", "sql is required"},
		{strings.Replace(withDataApp, "  postgres:\n    version: \"16\"\n", "", 1) + "backup:\n  verify:\n    sql: select 1\n", "needs a database"},
		{`app: site
workloads:
  pages:
    kind: static
    dir: public
    routes:
      - host: site.example
backup:
  schedule: "0 3 * * *"
`, "keeps no data"},
		{strings.Replace(withDataApp, "app: dragon-writer", "app: helios", 1), "a name helios uses for itself"},
	}
	for _, c := range cases {
		_, err := Parse([]byte(c.yaml))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("want %q, got %v", c.want, err)
		}
	}
}

const optOutApp = `app: notes
workloads:
  web:
    kind: web
    image: example.test/notes:1
    port: 3000
    routes:
      - host: notes.example.com
data:
  volumes:
    state: {}
    scratch:
      backup: false
`

// A volume marked backup: false is left out of the app's backups; every
// other volume, and the object store's, stays in.
func TestAVolumeMarkedBackupFalseIsLeftOutOfBackups(t *testing.T) {
	m, err := Parse([]byte(optOutApp))
	if err != nil {
		t.Fatal(err)
	}
	if got := m.BackedUpVolumes(); strings.Join(got, ",") != "state" {
		t.Fatalf("backed up volumes are %v, want state", got)
	}
	if got := m.VolumesOutOfBackups(); strings.Join(got, ",") != "scratch" {
		t.Fatalf("volumes out of backups are %v, want scratch", got)
	}
	if got := m.DataVolumes(); strings.Join(got, ",") != "scratch,state" {
		t.Fatalf("data volumes are %v, want both", got)
	}
	if !m.Data.Volumes["state"].InBackups() || m.Data.Volumes["scratch"].InBackups() {
		t.Fatal("only scratch is out of backups")
	}
	withObjects, err := Parse([]byte(optOutApp + "  objects: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := withObjects.BackedUpVolumes(); strings.Join(got, ",") != "objects,state" {
		t.Fatalf("backed up volumes with an object store are %v", got)
	}
	explicit, err := Parse([]byte(strings.Replace(optOutApp, "state: {}", "state:\n      backup: true", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if got := explicit.BackedUpVolumes(); strings.Join(got, ",") != "state" {
		t.Fatalf("backup: true keeps a volume in backups: %v", got)
	}
}

// The database is always backed up, and a backup that would hold nothing
// is backup.off by another name.
func TestLeavingTheDatabaseOrEveryVolumeOutOfBackupsFailsValidation(t *testing.T) {
	for _, c := range []struct {
		name, manifest, want string
	}{
		{"the database's volume", strings.Replace(optOutApp, "data:\n", "data:\n  postgres: {}\n", 1) + "    postgres:\n      backup: false\n",
			"data.volumes.postgres.backup: helios always backs up the app's database; it can't be left out"},
		{"every volume", strings.Replace(optOutApp, "state: {}", "state:\n      backup: false", 1),
			"data.volumes.scratch.backup: false leaves no data in the app's backups; to back up none of it, set backup.off: true instead"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse([]byte(c.manifest)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
	for _, c := range []struct {
		name, manifest string
	}{
		{"every volume of an app with a database", strings.Replace(strings.Replace(optOutApp, "state: {}", "state:\n      backup: false", 1), "data:\n", "data:\n  postgres: {}\n", 1)},
		{"every volume of an app whose backups are off", strings.Replace(optOutApp, "state: {}", "state:\n      backup: false", 1) + "backup:\n  off: true\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse([]byte(c.manifest)); err != nil {
				t.Fatalf("%s is valid: %v", c.name, err)
			}
		})
	}
}

package secrets

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

func TestTransfersPreservePresentEmptyValues(t *testing.T) {
	for _, mode := range []string{"single", "bundle", "copy"} {
		t.Run(mode, func(t *testing.T) {
			source, target, recipient := twoMachines(t)
			if _, err := source.Set("notes", "EMPTY", ""); err != nil {
				t.Fatal(err)
			}
			var err error
			switch mode {
			case "single":
				var sealed string
				sealed, err = source.Export("notes", "EMPTY", "notes", recipient)
				if err == nil {
					_, err = target.Import("notes", "EMPTY", strings.NewReader(sealed))
				}
			case "bundle":
				var sealed string
				sealed, err = source.ExportBundle("notes", recipient)
				if err == nil {
					_, err = target.ImportBundle("notes", strings.NewReader(sealed))
				}
			case "copy":
				target = source
				_, err = source.CopyAll("notes", "preview")
			}
			if err != nil {
				t.Fatal(err)
			}
			app := "notes"
			if mode == "copy" {
				app = "preview"
			}
			values, _, err := target.LoadCurrent(app)
			if err != nil {
				t.Fatal(err)
			}
			if value, present := values["EMPTY"]; !present || value != "" {
				t.Fatalf("empty secret lost: %v", values)
			}
		})
	}
}

func TestBundleImportValidatesBeforeAnyMutation(t *testing.T) {
	_, target, recipient := twoMachines(t)
	data, err := json.Marshal(secretBundle{App: "notes", Values: map[string]string{"ALLOWED": "new", "invalid": "secret"}, Expires: timeNow().Add(transferLife)})
	if err != nil {
		t.Fatal(err)
	}
	r, err := parseRecipient(recipient)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := seal(data, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.ImportBundle("notes", strings.NewReader(sealed)); err == nil {
		t.Fatal("invalid bundle accepted")
	}
	if version, err := target.Current("notes"); err != nil || version != 0 {
		t.Fatalf("failed import mutated store: version %d, err %v", version, err)
	}
}

func TestBundleImportWritesOneVersion(t *testing.T) {
	source, target, recipient := twoMachines(t)
	a, b := "a", "b"
	if _, err := source.SetAll("notes", map[string]*string{"A": &a, "B": &b}); err != nil {
		t.Fatal(err)
	}
	sealed, err := source.ExportBundle("notes", recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.ImportBundle("notes", strings.NewReader(sealed)); err != nil {
		t.Fatal(err)
	}
	if version, err := target.Current("notes"); err != nil || version != 1 {
		t.Fatalf("bundle split across versions: %d, %v", version, err)
	}
}

func TestConcurrentRepeatedTransfersDoNotChurnVersions(t *testing.T) {
	for _, mode := range []string{"single", "bundle", "copy"} {
		t.Run(mode, func(t *testing.T) {
			source, target, recipient := twoMachines(t)
			if _, err := source.Set("notes", "TOKEN", "fixture"); err != nil {
				t.Fatal(err)
			}
			var sealed string
			var err error
			app := "notes"
			switch mode {
			case "single":
				sealed, err = source.Export("notes", "TOKEN", app, recipient)
			case "bundle":
				sealed, err = source.ExportBundle(app, recipient)
			case "copy":
				target = source
				app = "preview"
			}
			if err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			var workers sync.WaitGroup
			for range 8 {
				workers.Go(func() {
					<-start
					var err error
					switch mode {
					case "single":
						_, err = target.Import(app, "TOKEN", strings.NewReader(sealed))
					case "bundle":
						_, err = target.ImportBundle(app, strings.NewReader(sealed))
					case "copy":
						_, err = source.CopyAll("notes", app)
					}
					if err != nil {
						t.Error(err)
					}
				})
			}
			close(start)
			workers.Wait()
			if version, err := target.Current(app); err != nil || version != 1 {
				t.Fatalf("repeated transfer created version %d, want one: %v", version, err)
			}
		})
	}
}

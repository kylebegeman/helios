package integration

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/kylebegeman/helios/internal/secrets"
)

const TransferVersion = 1

var transferNow = time.Now

const transferDuration = 10 * time.Minute

type transferBundle struct {
	Version int                          `json:"version"`
	Kind    string                       `json:"kind"`
	Expires time.Time                    `json:"expires"`
	Names   []string                     `json:"names"`
	Values  map[string]map[string]string `json:"values"`
}

func transferNames(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, errors.New("name at least one integration to transfer")
	}
	out := append([]string{}, names...)
	sort.Strings(out)
	for i, n := range out {
		if _, ok := Lookup(n); !ok {
			return nil, fmt.Errorf("unknown integration %q", n)
		}
		if i > 0 && n == out[i-1] {
			return nil, fmt.Errorf("integration %s named twice", n)
		}
	}
	return out, nil
}
func validateTransferFields(name string, values map[string]string) error {
	def, ok := Lookup(name)
	if !ok {
		return errors.New("unknown integration in configuration")
	}
	known := map[string]bool{}
	for _, f := range def.Fields {
		known[f.Name] = true
		v := values[f.Name]
		if v == "" && !f.Optional {
			return fmt.Errorf("%s needs field %s", name, f.Name)
		}
		if len(f.Choices) > 0 && v != "" {
			found := false
			for _, c := range f.Choices {
				found = found || v == c
			}
			if !found {
				return fmt.Errorf("invalid %s.%s", name, f.Name)
			}
		}
	}
	for field := range values {
		if !known[field] {
			return fmt.Errorf("unknown field in %s configuration", name)
		}
	}
	if name == StorageName && values["password"] == "" {
		return errors.New("storage transfer must include the existing backup password")
	}
	if err := validate(name, values); err != nil {
		return fmt.Errorf("%s configuration failed validation", name)
	}
	return nil
}

// Export seals exactly the named integration definitions to a target recipient.
// It retains the existing storage password and excludes app deploy/hook keys.
func Export(store *secrets.Store, names []string, recipient string) (string, error) {
	selected, err := transferNames(names)
	if err != nil {
		return "", err
	}
	values := map[string]map[string]string{}
	for _, name := range selected {
		v, err := Get(store, name)
		if err != nil {
			return "", fmt.Errorf("cannot transfer %s: %w", name, err)
		}
		if err := validateTransferFields(name, v); err != nil {
			return "", err
		}
		values[name] = v
	}
	data, err := json.Marshal(transferBundle{Version: TransferVersion, Kind: "bedrock.integration-transfer", Expires: transferNow().Add(transferDuration), Names: selected, Values: values})
	if err != nil {
		return "", errors.New("cannot encode integration transfer")
	}
	return secrets.SealDocument(recipient, data)
}

// Import validates all fields before atomically updating one sealed version.
// Existing values require explicit replacement unless they are identical.
func Import(store *secrets.Store, names []string, input io.Reader, replace bool) ([]string, error) {
	selected, err := transferNames(names)
	if err != nil {
		return nil, err
	}
	data, err := store.OpenDocument(input)
	if err != nil {
		return nil, err
	}
	var b transferBundle
	if json.Unmarshal(data, &b) != nil || b.Version != TransferVersion || b.Kind != "bedrock.integration-transfer" {
		return nil, errors.New("invalid integration transfer document")
	}
	now := transferNow()
	if !b.Expires.After(now) || b.Expires.After(now.Add(transferDuration+time.Minute)) {
		return nil, errors.New("integration transfer expired or has an invalid lifetime")
	}
	if !reflect.DeepEqual(selected, b.Names) || len(b.Values) != len(selected) {
		return nil, errors.New("integration transfer does not match the requested scope")
	}
	for _, name := range selected {
		if err := validateTransferFields(name, b.Values[name]); err != nil {
			return nil, err
		}
	}
	return applyValues(store, b.Values, replace, false)
}
func applyValues(store *secrets.Store, values map[string]map[string]string, replace, preserve bool) ([]string, error) {
	current, _, err := store.LoadCurrent(App)
	if err != nil {
		return nil, err
	}
	changes := map[string]*string{}
	var changed []string
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		def, ok := Lookup(name)
		if !ok {
			return nil, errors.New("unknown integration")
		}
		fields := values[name]
		if err := validateTransferFields(name, fields); err != nil {
			return nil, err
		}
		existing, existingErr := Get(store, name)
		if existingErr != nil && !errors.Is(existingErr, ErrNotSet) {
			return nil, existingErr
		}
		if preserve && existingErr == nil {
			continue
		}
		diff := false
		for _, f := range def.Fields {
			if current[def.key(f.Name)] != fields[f.Name] {
				diff = true
			}
		}
		if !diff {
			continue
		}
		if existingErr == nil && !replace {
			return nil, fmt.Errorf("%s already holds different configuration; use --replace after reviewing the target", name)
		}
		_ = existing
		changed = append(changed, name)
		for _, f := range def.Fields {
			v := fields[f.Name]
			if v == "" {
				changes[def.key(f.Name)] = nil
			} else {
				copy := v
				changes[def.key(f.Name)] = &copy
			}
		}
	}
	if len(changes) > 0 {
		if _, err := store.SetAll(App, changes); err != nil {
			return nil, err
		}
	}
	return changed, nil
}

// RecoverMissing restores missing non-storage integrations and operational keys,
// among them the CAs the edge's origin-pull hosts trust. The source store has
// already been resealed to the target identity by recovery. Target storage,
// configured integrations, existing hook/deploy keys and origin-pull trust
// prevail.
func RecoverMissing(target, source *secrets.Store) ([]string, error) {
	raw, _, err := source.LoadCurrent(App)
	if err != nil {
		return nil, err
	}
	values := map[string]map[string]string{}
	for _, def := range Definitions {
		if def.Name == StorageName {
			continue
		}
		fields := map[string]string{}
		present := false
		for _, f := range def.Fields {
			if v, ok := raw[def.key(f.Name)]; ok {
				fields[f.Name] = v
				present = true
			}
		}
		if present {
			values[def.Name] = fields
		}
	}
	// Validate the entire source configuration before making a target change.
	for name, v := range values {
		if err := validateTransferFields(name, v); err != nil {
			return nil, err
		}
	}
	current, _, err := target.LoadCurrent(App)
	if err != nil {
		return nil, err
	}
	keys := map[string]*string{}
	for name, value := range raw {
		if !secrets.ValidName(name) {
			return nil, errors.New("invalid operational secret name in recovery")
		}
		if strings.HasPrefix(name, "WEBHOOK_SECRET_") || strings.HasPrefix(name, "DEPLOY_KEY_") || name == OriginPullName {
			if current[name] == "" {
				v := value
				keys[name] = &v
			}
		}
	}
	changed, err := applyValues(target, values, false, true)
	if err != nil {
		return nil, err
	}
	if len(keys) > 0 {
		if _, err := target.SetAll(App, keys); err != nil {
			return changed, err
		}
		changed = append(changed, "operational-keys")
	}
	return changed, nil
}

// ValidateVersion checks selected definitions in a pinned source secret version.
func ValidateVersion(store *secrets.Store, names []string, version int) error {
	selected, err := transferNames(names)
	if err != nil {
		return err
	}
	raw, err := store.Load(App, version)
	if err != nil {
		return err
	}
	for _, name := range selected {
		def, _ := Lookup(name)
		fields := map[string]string{}
		for _, f := range def.Fields {
			fields[f.Name] = raw[def.key(f.Name)]
		}
		if err := validateTransferFields(name, fields); err != nil {
			return err
		}
	}
	return nil
}

// ExportVersion seals a pinned source version, so interrupted bootstrap remains reproducible.
func ExportVersion(store *secrets.Store, names []string, recipient string, version int) (string, error) {
	if err := ValidateVersion(store, names, version); err != nil {
		return "", err
	}
	selected, _ := transferNames(names)
	raw, err := store.Load(App, version)
	if err != nil {
		return "", err
	}
	values := map[string]map[string]string{}
	for _, name := range selected {
		def, _ := Lookup(name)
		fields := map[string]string{}
		for _, f := range def.Fields {
			fields[f.Name] = raw[def.key(f.Name)]
		}
		values[name] = fields
	}
	data, err := json.Marshal(transferBundle{Version: TransferVersion, Kind: "bedrock.integration-transfer", Expires: transferNow().Add(transferDuration), Names: selected, Values: values})
	if err != nil {
		return "", errors.New("cannot encode integration transfer")
	}
	return secrets.SealDocument(recipient, data)
}

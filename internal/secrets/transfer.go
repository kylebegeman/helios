package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// MaxTransferBytes bounds one sealed secret; MaxBundleBytes a whole app's.
// An app with more than that is not moving its configuration, it is
// moving its data, and data belongs in a volume.
const (
	MaxTransferBytes = 64 * 1024
	MaxBundleBytes   = 1 << 20
)

// transferLife is how long a sealed transfer stays readable. It is meant
// to be produced and consumed in the same sitting, not kept.
const transferLife = 10 * time.Minute

// timeNow is the clock transfers are stamped and checked by, so a test can
// prove one stops working rather than waiting ten minutes to find out.
var timeNow = time.Now

// transfer is one secret sealed for another machine.
type transfer struct {
	App     string    `json:"app"`
	Name    string    `json:"name"`
	Value   string    `json:"value"`
	Expires time.Time `json:"expires"`
}

// secretBundle is every secret an app holds, sealed for another machine.
type secretBundle struct {
	App     string            `json:"app"`
	Values  map[string]string `json:"values"`
	Expires time.Time         `json:"expires"`
}

// transferable reports whether an app's secrets may leave the store this
// way: any app's but helios's own, whose integration credentials belong
// to the machine.
func transferable(app string) bool { return appPattern.MatchString(app) && app != reservedApp }

// fresh reports whether a transfer's stamp is within its life: not yet
// expired, and not from further ahead than any clock could honestly be.
func fresh(expires time.Time) bool {
	now := timeNow()
	return expires.After(now) && !expires.After(now.Add(transferLife+time.Minute))
}

// Export seals exactly one secret for another machine. Only ciphertext
// leaves this store; the receiver must also name the expected app and
// secret.
func (s *Store) Export(from, name, to, recipient string) (string, error) {
	if !transferable(from) || !transferable(to) {
		return "", errors.New("integration credentials cannot be transferred")
	}
	if !ValidName(name) {
		return "", errors.New("invalid secret name")
	}
	r, err := parseRecipient(recipient)
	if err != nil {
		return "", err
	}
	values, _, err := s.LoadCurrent(from)
	if err != nil {
		return "", err
	}
	value, ok := values[name]
	if !ok {
		return "", fmt.Errorf("%s has no secret named %s", from, name)
	}
	data, err := json.Marshal(transfer{App: to, Name: name, Value: value, Expires: timeNow().Add(transferLife)})
	if err != nil {
		return "", errors.New("cannot encode secret transfer")
	}
	if len(data) > MaxTransferBytes/2 {
		return "", errors.New("secret is too large to transfer")
	}
	return seal(data, r)
}

// Import accepts only authenticated ciphertext for this machine and the
// named destination. Parse failures deliberately never include decrypted
// bytes.
func (s *Store) Import(app, name string, input io.Reader) (int, error) {
	if !transferable(app) || !ValidName(name) {
		return 0, errors.New("invalid secret transfer destination")
	}
	data, err := s.unseal(input, MaxTransferBytes, "transfer")
	if err != nil {
		return 0, err
	}
	var t transfer
	if json.Unmarshal(data, &t) != nil || t.App != app || t.Name != name || !fresh(t.Expires) {
		return 0, errors.New("secret transfer is expired or does not match the destination")
	}
	_, version, err := s.mergeValues(app, map[string]string{name: t.Value})
	return version, err
}

// ExportBundle seals every secret an app holds for another machine, so an
// app can be moved without opening the sealed store by hand.
//
// A moved app must arrive with the secrets it left with. Its database was
// restored from a snapshot and still holds the role password the source
// generated, so a target that generated its own would be handed a database
// it cannot open. Sealing to the target's recipient is what lets that
// travel without the values passing through a terminal, a log or a shell
// history on the way.
func (s *Store) ExportBundle(app, recipient string) (string, error) {
	if !transferable(app) {
		return "", errors.New("integration credentials cannot be transferred")
	}
	r, err := parseRecipient(recipient)
	if err != nil {
		return "", err
	}
	values, _, err := s.LoadCurrent(app)
	if err != nil {
		return "", err
	}
	if len(values) == 0 {
		return "", fmt.Errorf("%s holds no secrets", app)
	}
	data, err := json.Marshal(secretBundle{App: app, Values: values, Expires: timeNow().Add(transferLife)})
	if err != nil {
		return "", errors.New("cannot encode secret bundle")
	}
	if len(data) > MaxBundleBytes/2 {
		return "", fmt.Errorf("%s's secrets are too large to transfer", app)
	}
	return seal(data, r)
}

// ImportBundle accepts only authenticated ciphertext sealed for this
// machine and naming this app. It returns the names it stored, never the
// values, and parse failures deliberately never include decrypted bytes.
//
// A name already holding the same value is left alone rather than written
// again, so importing twice does not churn the version history.
func (s *Store) ImportBundle(app string, input io.Reader) ([]string, error) {
	if !transferable(app) {
		return nil, errors.New("invalid secret transfer destination")
	}
	data, err := s.unseal(input, MaxBundleBytes, "bundle")
	if err != nil {
		return nil, err
	}
	var b secretBundle
	if json.Unmarshal(data, &b) != nil || b.App != app || !fresh(b.Expires) {
		return nil, errors.New("secret bundle is expired or does not match the destination")
	}
	stored, _, err := s.mergeValues(app, b.Values)
	return stored, err
}

// CopyAll copies every secret an app holds to another app on this
// machine, and returns the names it wrote.
//
// This is for a preview, which runs the parent app's code and so needs
// the hand-set values that code expects. Anything the target already holds
// with the same value is left alone, so running it again writes no new
// version.
//
// It stays on one machine and never touches helios's own integration
// credentials, which belong to the machine rather than to any app.
func (s *Store) CopyAll(from, to string) ([]string, error) {
	if !transferable(from) || !transferable(to) {
		return nil, errors.New("integration credentials cannot be copied")
	}
	if from == to {
		return nil, errors.New("an app already has its own secrets")
	}
	values, _, err := s.LoadCurrent(from)
	if err != nil {
		return nil, err
	}
	stored, _, err := s.mergeValues(to, values)
	return stored, err
}

// mergeValues compares and writes against one locked destination snapshot, so
// simultaneous copies and imports retain their idempotency.
func (s *Store) mergeValues(app string, values map[string]string) ([]string, int, error) {
	names := make([]string, 0, len(values))
	for name := range values {
		if !ValidName(name) {
			return nil, 0, errors.New("source contains an invalid secret name")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	var stored []string
	version, err := s.Update(app, func(current map[string]string) (map[string]*string, error) {
		changes := map[string]*string{}
		for _, name := range names {
			value := values[name]
			if existing, present := current[name]; present && existing == value {
				continue
			}
			changes[name] = &value
			stored = append(stored, name)
		}
		return changes, nil
	})
	if err != nil {
		return nil, 0, err
	}
	return stored, version, nil
}

func parseRecipient(recipient string) (age.Recipient, error) {
	r, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return nil, errors.New("invalid receiving machine recipient")
	}
	return r, nil
}

// seal encrypts data to a recipient and armors it: the one form that
// leaves the store.
func seal(data []byte, r age.Recipient) (string, error) {
	var buf bytes.Buffer
	armored := armor.NewWriter(&buf)
	w, err := age.Encrypt(armored, r)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(data); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	if err := armored.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// unseal reads at most limit bytes of armored ciphertext sealed to this
// machine and returns what it held, itself at most limit bytes. What is
// wrong with a rejected input is never said in terms of its contents.
func (s *Store) unseal(input io.Reader, limit int, what string) ([]byte, error) {
	id, err := s.identity()
	if err != nil {
		return nil, err
	}
	encrypted, err := io.ReadAll(io.LimitReader(input, int64(limit)+1))
	if err != nil || len(encrypted) > limit {
		return nil, fmt.Errorf("invalid or oversized secret %s", what)
	}
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(encrypted)), id)
	if err != nil {
		return nil, fmt.Errorf("secret %s is not sealed for this machine", what)
	}
	data, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil || len(data) > limit {
		return nil, fmt.Errorf("invalid secret %s", what)
	}
	return data, nil
}

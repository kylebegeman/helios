package integration

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/kylebegeman/helios/internal/secrets"
)

func newStore(t *testing.T) *secrets.Store {
	t.Helper()
	dir := t.TempDir()
	s := &secrets.Store{Dir: filepath.Join(dir, "secrets"), KeyPath: filepath.Join(dir, "key")}
	if _, _, _, err := s.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStorageIsStoredUnderHeliosAndListedWithoutSecrets(t *testing.T) {
	s := newStore(t)
	version, generated, err := Set(s, StorageName, map[string]string{"kind": "s3", "endpoint": "http://127.0.0.1:9000", "key_id": "id", "key": "k", "bucket_prefix": "lane"})
	if err != nil {
		t.Fatal(err)
	}
	if version != 1 || generated["password"] == "" || len(generated["password"]) != 48 {
		t.Fatalf("version %d generated %v", version, generated)
	}
	st, err := LoadStorage(s)
	if err != nil {
		t.Fatal(err)
	}
	if st.Repository(st.Bucket("hello")) != "s3:http://127.0.0.1:9000/lane-hello" || st.Password != generated["password"] {
		t.Fatalf("%+v", st)
	}
	if env := st.Env(); env[0] != "AWS_ACCESS_KEY_ID=id" || env[1] != "AWS_SECRET_ACCESS_KEY=k" {
		t.Fatalf("env %v", env)
	}
	list, err := List(s)
	if err != nil {
		t.Fatal(err)
	}
	if list[0].Name != StorageName || !list[0].Set || list[0].Fields["key"] != "(set)" || list[0].Fields["password"] != "(set)" || list[0].Fields["bucket_prefix"] != "lane" || list[0].At.IsZero() {
		t.Fatalf("%+v", list[0])
	}
	if list[1].Set {
		t.Fatal("email shouldn't be set")
	}
	// The values live under helios's own name and never leak into an app.
	names, _, _ := s.Names(App)
	if strings.Join(names, ",") != "STORAGE_BUCKET_PREFIX,STORAGE_ENDPOINT,STORAGE_KEY,STORAGE_KEY_ID,STORAGE_KIND,STORAGE_PASSWORD" {
		t.Fatalf("names %v", names)
	}
	// Setting it again with a password keeps that password; the endpoint
	// has to be cleared by name now that unnamed fields keep their values.
	if _, generated, err := Set(s, StorageName, map[string]string{"kind": "b2", "endpoint": "", "key_id": "id2", "key": "k2", "bucket_prefix": "kb", "password": "mine"}); err != nil || len(generated) != 0 {
		t.Fatalf("%v %v", err, generated)
	}
	st, _ = LoadStorage(s)
	if st.Repository(st.Bucket("dragon-writer")) != "b2:kb-dragon-writer:/" || st.Password != "mine" || st.Endpoint != "" {
		t.Fatalf("%+v", st)
	}
	if _, err := Remove(s, StorageName); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStorage(s); err == nil {
		t.Fatal("still set after remove")
	}
}

func TestFieldsAreValidated(t *testing.T) {
	s := newStore(t)
	cases := []struct {
		name   string
		values map[string]string
		want   string
	}{
		{StorageName, map[string]string{"kind": "s3", "key_id": "a", "key": "b", "bucket_prefix": "lane"}, "endpoint"},
		{StorageName, map[string]string{"kind": "b2", "key_id": "a", "key": "b", "bucket_prefix": "Lane"}, "bucket_prefix"},
		{StorageName, map[string]string{"kind": "gcs", "key_id": "a", "key": "b", "bucket_prefix": "lane"}, "one of b2, s3"},
		{StorageName, map[string]string{"kind": "b2", "key": "b", "bucket_prefix": "lane"}, "needs key_id"},
		{EmailName, map[string]string{"smtp_host": "h", "smtp_port": "x", "from": "a@b", "to": "c@d"}, "smtp_port"},
		{EmailName, map[string]string{"smtp_host": "h", "from": "nobody", "to": "c@d"}, "isn't an address"},
		{EmailName, map[string]string{"smtp_host": "h", "from": "a@b\r\nBcc: x@y", "to": "c@d"}, "isn't an address"},
		{EmailName, map[string]string{"smtp_host": "h", "smtp_user": "u", "from": "a@b", "to": "c@d"}, "both smtp_user and smtp_password"},
		{"slack", map[string]string{}, "no integration named"},
		{EmailName, map[string]string{"colour": "blue"}, "no field named"},
	}
	for _, c := range cases {
		_, _, err := Set(s, c.name, c.values)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %v: got %v, want %q", c.name, c.values, err, c.want)
		}
	}
	if _, _, err := Set(s, EmailName, map[string]string{"smtp_host": "127.0.0.1", "smtp_port": "1025", "from": "bedrock@lane", "to": "kyle@lane, olive@lane"}); err != nil {
		t.Fatal(err)
	}
	e, err := LoadEmail(s)
	if err != nil || e.Port != 1025 || len(e.To) != 2 || e.To[1] != "olive@lane" || e.User != "" {
		t.Fatalf("%+v %v", e, err)
	}
}

func TestSettingAnIntegrationAgainKeepsWhatIsNotNamed(t *testing.T) {
	s := newStore(t)
	if _, generated, err := Set(s, StorageName, map[string]string{"kind": "s3", "endpoint": "http://127.0.0.1:9000", "key_id": "id", "key": "k", "bucket_prefix": "lane"}); err != nil || generated["password"] == "" {
		t.Fatalf("%v %v", err, generated)
	}
	first, err := LoadStorage(s)
	if err != nil {
		t.Fatal(err)
	}
	version, generated, err := Set(s, StorageName, map[string]string{"key": "k2"})
	if err != nil || len(generated) != 0 || version != 2 {
		t.Fatalf("version %d generated %v err %v", version, generated, err)
	}
	again, err := LoadStorage(s)
	if err != nil {
		t.Fatal(err)
	}
	if again.Key != "k2" || again.KeyID != "id" || again.Endpoint != first.Endpoint || again.BucketPrefix != "lane" || again.Password != first.Password {
		t.Fatalf("after naming one field: %+v, was %+v", again, first)
	}
	// A blank password keeps the one the repositories were made with.
	if _, generated, err := Set(s, StorageName, map[string]string{"password": ""}); err != nil || len(generated) != 0 {
		t.Fatalf("%v %v", err, generated)
	}
	if again, _ = LoadStorage(s); again.Password != first.Password {
		t.Fatal("a blank password made a new one")
	}
	// The first time, what is required still has to be given.
	if _, _, err := Set(s, EmailName, map[string]string{"smtp_host": "h"}); err == nil || !strings.Contains(err.Error(), "needs from") {
		t.Fatalf("a first set with fields missing: %v", err)
	}
}

func TestEmailAddressesLoadAsSMTPEnvelopeMailboxes(t *testing.T) {
	store := newStore(t)
	if _, _, err := Set(store, EmailName, map[string]string{
		"smtp_host": "smtp.example.com",
		"from":      "Helios Alerts <helios@example.com>",
		"to":        `"Doe, Jane" <jane@example.com>, Team <ops@example.com>`,
	}); err != nil {
		t.Fatal(err)
	}
	email, err := LoadEmail(store)
	if err != nil {
		t.Fatal(err)
	}
	if email.FromName != "Helios Alerts" {
		t.Fatalf("email sender display name was lost: %q", email.FromName)
	}
	if email.From != "helios@example.com" || len(email.To) != 2 || email.To[0] != "jane@example.com" || email.To[1] != "ops@example.com" {
		t.Fatalf("email did not load plain envelope mailboxes: from=%q to=%q", email.From, email.To)
	}
}

func TestEmailRejectsMultipleEnvelopeSenders(t *testing.T) {
	store := newStore(t)
	if _, _, err := Set(store, EmailName, map[string]string{"smtp_host": "smtp.example.com", "from": "first@example.com, second@example.com", "to": "ops@example.com"}); err == nil {
		t.Fatal("multiple SMTP envelope senders were accepted")
	}
	if version, err := store.Current(App); err != nil || version != 0 {
		t.Fatalf("invalid email configuration was committed: version %d, %v", version, err)
	}
}

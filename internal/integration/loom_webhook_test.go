package integration

import (
	"errors"
	"strings"
	"testing"
)

const (
	testHookURL    = "https://relay.example.test/v1/hooks/0123456789abcdef/task-1/tok_example-not-real"
	testHookSecret = "example-signing-secret-not-real"
)

// The webhook URL carries the task's token, so both values are sealed, and
// it is set once as the relay's shape or not at all.
func TestALoomWebhookIsTheRelaysURLAndASecretNeitherShown(t *testing.T) {
	s := newStore(t)
	if _, err := LoadLoomWebhook(s); !errors.Is(err, ErrNotSet) {
		t.Fatalf("nothing set: %v", err)
	}
	if _, _, err := Set(s, LoomWebhookName, map[string]string{"url": testHookURL, "secret": testHookSecret}); err != nil {
		t.Fatal(err)
	}
	hook, err := LoadLoomWebhook(s)
	if err != nil || hook.URL != testHookURL || hook.Secret != testHookSecret {
		t.Fatalf("%+v, %v", hook, err)
	}
	names, _, _ := s.Names(App)
	if strings.Join(names, ",") != "LOOM_WEBHOOK_SECRET,LOOM_WEBHOOK_URL" {
		t.Fatalf("names %v", names)
	}
	list, err := List(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range list {
		if st.Name == LoomWebhookName && (!st.Set || st.Fields["url"] != "(set)" || st.Fields["secret"] != "(set)") {
			t.Fatalf("%+v", st)
		}
	}
}

// Anything but a task's URL on the relay is refused, Loom's direct route
// included, and the refusal never shows what was typed.
func TestALoomWebhookIsRefusedWithoutShowingIt(t *testing.T) {
	const hidden = "do-not-show"
	base := "https://relay.example.test/v1/hooks/0123456789abcdef/task-1/"
	cases := []struct {
		url, secret, want string
	}{
		{"relay.example.test/v1/hooks/0123456789abcdef/task-1/" + hidden, testHookSecret, "loom_webhook.url: URL must start with https://"},
		{"http://relay.example.test/v1/hooks/0123456789abcdef/task-1/" + hidden, testHookSecret, "loom_webhook.url: URL must start with https://"},
		{"https://user:" + hidden + "@relay.example.test/v1/hooks/0123456789abcdef/task-1/tok", testHookSecret, "must not contain credentials"},
		{base + hidden + "?sig=1", testHookSecret, "must not have a query or a fragment"},
		{base + hidden + "?", testHookSecret, "must not have a query or a fragment"},
		{base + hidden + "#", testHookSecret, "must not have a query or a fragment"},
		{"https://loom.example.test/api/hooks/task-1/" + hidden, testHookSecret, "must be the task's relay webhook URL"},
		{"https://relay.example.test/v2/hooks/0123456789abcdef/task-1/" + hidden, testHookSecret, "must be the task's relay webhook URL"},
		{"https://relay.example.test/v1/hook/0123456789abcdef/task-1/" + hidden, testHookSecret, "must be the task's relay webhook URL"},
		{"https://relay.example.test/v1/hooks/0123456789ABCDEF/task-1/" + hidden, testHookSecret, "16 hex digit endpoint"},
		{"https://relay.example.test/v1/hooks/0123456789abcde/task-1/" + hidden, testHookSecret, "16 hex digit endpoint"},
		{"https://relay.example.test/v1/hooks/0123456789abcdef/" + hidden, testHookSecret, "must be the task's relay webhook URL"},
		{"https://relay.example.test/v1/hooks/0123456789abcdef//" + hidden, testHookSecret, "must be the task's relay webhook URL"},
		{base + hidden + "/", testHookSecret, "must be the task's relay webhook URL"},
		{"https://relay.example.test/base/v1/hooks/0123456789abcdef/task-1/" + hidden, testHookSecret, "must be the task's relay webhook URL"},
		{testHookURL, hidden + "-abc", "loom_webhook.secret must be 16 to 512 printable ASCII characters"},
		{testHookURL, hidden + "-and-ünïcode", "loom_webhook.secret must be 16 to 512"},
		{testHookURL, hidden + "\tand-a-tab", "loom_webhook.secret must be 16 to 512"},
		{testHookURL, hidden + strings.Repeat("x", 513-len(hidden)), "loom_webhook.secret must be 16 to 512"},
	}
	s := newStore(t)
	for _, c := range cases {
		_, _, err := Set(s, LoomWebhookName, map[string]string{"url": c.url, "secret": c.secret})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q, %q: got %v, want %q", c.url, c.secret, err, c.want)
			continue
		}
		if strings.Contains(err.Error(), hidden) {
			t.Errorf("%q: the error shows the value: %v", c.url, err)
		}
	}
	for _, ok := range []struct{ url, secret string }{
		{"https://127.0.0.1:8443/v1/hooks/0123456789abcdef/task-1/tok%2Fwith-a-slash", strings.Repeat("s", 16)},
		{testHookURL, "a passphrase with spaces " + strings.Repeat("x", 487)},
	} {
		if err := validate(LoomWebhookName, map[string]string{"url": ok.url, "secret": ok.secret}); err != nil {
			t.Errorf("%q: %v", ok.url, err)
		}
	}
}

// Every integration's values sit side by side in helios's own secrets, so
// no two fields may be stored under one name: loom's verify_url beside
// loom_webhook's url, for one.
func TestNoTwoIntegrationFieldsShareASecretName(t *testing.T) {
	seen := map[string]string{}
	for _, d := range Definitions {
		for _, f := range d.Fields {
			key := d.key(f.Name)
			if other, ok := seen[key]; ok {
				t.Errorf("%s.%s and %s are both stored as %s", d.Name, f.Name, other, key)
			}
			seen[key] = d.Name + "." + f.Name
		}
	}
}

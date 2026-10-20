package integration

import (
	"strings"
	"testing"
)

const (
	testAppToken = "azGDORePK8gMaC0QOYAMyEEuzJnyUi"
	testUserKey  = "uQiRzpo4DXghDmr9QzzfQu27cmVRsG"
	testTopicURL = "https://ntfy.example.test/a-long-unguessable-topic"
)

// The alert integrations hold credentials, and a topic URL is one, so a
// value that is refused is never shown back.
func TestAlertIntegrationsAreValidatedWithoutShowingValues(t *testing.T) {
	s := newStore(t)
	cases := []struct {
		name   string
		values map[string]string
		want   string
	}{
		{PushoverName, map[string]string{"app_token": "short-secret-token", "user_key": testUserKey}, "pushover.app_token must be the 30 letters and digits"},
		{PushoverName, map[string]string{"app_token": testAppToken, "user_key": testUserKey + "x"}, "pushover.user_key must be"},
		{NtfyName, map[string]string{"topic_url": "ntfy.example.test/secret-topic"}, "ntfy.topic_url: URL must start with https://"},
		{NtfyName, map[string]string{"topic_url": "https://ntfy.example.test/"}, "must end in a topic"},
		{NtfyName, map[string]string{"topic_url": "https://ntfy.example.test/secret.topic"}, "must end in a topic"},
		{NtfyName, map[string]string{"topic_url": "https://ntfy.example.test/a%2Fsecret-topic"}, "must end in a topic"},
		{NtfyName, map[string]string{"topic_url": "https://ntfy.example.test/secret-topic?auth=secret"}, "must not have a query"},
		{NtfyName, map[string]string{"topic_url": "https://user:secret@ntfy.example.test/topic"}, "must not contain credentials"},
		{NtfyName, map[string]string{"topic_url": testTopicURL, "token": "tk_secret token"}, "ntfy.token must be one word"},
		{Email2Name, map[string]string{"smtp_host": "h", "smtp_port": "x", "from": "a@b", "to": "c@d"}, "email2.smtp_port"},
		{Email2Name, map[string]string{"smtp_host": "h", "smtp_user": "u", "from": "a@b", "to": "c@d"}, "email2: give both"},
	}
	for _, c := range cases {
		_, _, err := Set(s, c.name, c.values)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
			continue
		}
		if strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: the error shows the value: %v", c.name, err)
		}
	}
}

func TestANtfyTopicURLSplitsIntoServerAndTopic(t *testing.T) {
	for raw, want := range map[string]NtfyTopic{
		"https://ntfy.sh/a-long-unguessable-topic":    {Server: "https://ntfy.sh/", Topic: "a-long-unguessable-topic"},
		" https://ntfy.example.test:8443/Alerts_1 ":   {Server: "https://ntfy.example.test:8443/", Topic: "Alerts_1"},
		"http://[::1]:2586/push/topic":                {Server: "http://[::1]:2586/push/", Topic: "topic"},
		"https://ntfy.example.test/a%20b/alerts-team": {Server: "https://ntfy.example.test/a%20b/", Topic: "alerts-team"},
	} {
		got, err := ParseNtfyTopic(raw)
		if err != nil || got != want {
			t.Errorf("%q: got %+v, %v; want %+v", raw, got, err, want)
		}
	}
}

// The second mail server is tried after the first, and either works
// alone. The phone legs load what was set and list as set without their
// values.
func TestAlertIntegrationsLoad(t *testing.T) {
	s := newStore(t)
	if relays, err := LoadEmailRelays(s); err != nil || len(relays) != 0 {
		t.Fatalf("nothing set: %+v, %v", relays, err)
	}
	if _, _, err := Set(s, Email2Name, map[string]string{"smtp_host": "smtp2.example.test", "from": "helios@example.test", "to": "ops@example.test"}); err != nil {
		t.Fatal(err)
	}
	if relays, err := LoadEmailRelays(s); err != nil || len(relays) != 1 || relays[0].Name != Email2Name || relays[0].Port != 587 {
		t.Fatalf("the second server alone: %+v, %v", relays, err)
	}
	if _, _, err := Set(s, EmailName, map[string]string{"smtp_host": "smtp1.example.test", "from": "helios@example.test", "to": "ops@example.test"}); err != nil {
		t.Fatal(err)
	}
	relays, err := LoadEmailRelays(s)
	if err != nil || len(relays) != 2 || relays[0].Name != EmailName || relays[0].Host != "smtp1.example.test" || relays[1].Host != "smtp2.example.test" {
		t.Fatalf("the first server first: %+v, %v", relays, err)
	}

	if _, _, err := Set(s, PushoverName, map[string]string{"app_token": testAppToken, "user_key": testUserKey}); err != nil {
		t.Fatal(err)
	}
	if p, err := LoadPushover(s); err != nil || p.AppToken != testAppToken || p.UserKey != testUserKey {
		t.Fatalf("%+v, %v", p, err)
	}
	if _, _, err := Set(s, NtfyName, map[string]string{"topic_url": testTopicURL}); err != nil {
		t.Fatal(err)
	}
	if n, err := LoadNtfy(s); err != nil || n.Server != "https://ntfy.example.test/" || n.Topic != "a-long-unguessable-topic" || n.Token != "" {
		t.Fatalf("%+v, %v", n, err)
	}
	list, err := List(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range list {
		switch st.Name {
		case PushoverName:
			if !st.Set || st.Fields["app_token"] != "(set)" || st.Fields["user_key"] != "(set)" {
				t.Errorf("%+v", st)
			}
		case NtfyName:
			if !st.Set || st.Fields["topic_url"] != "(set)" {
				t.Errorf("%+v", st)
			}
		}
	}
}

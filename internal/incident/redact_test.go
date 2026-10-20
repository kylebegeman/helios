package incident

import (
	"encoding/json"
	"net/url"
	"slices"
	"testing"
)

func TestRedactionReplacesSecretsAndPrivateAddressesOnly(t *testing.T) {
	var r redactor
	r.add("SHORT", "fake_secret", minSecretValue)
	r.add("LONG", "fake_secret_longer", minSecretValue)
	r.add("PIN", "123", minSecretValue)
	for _, c := range []struct{ in, want string }{
		{"using fake_secret_longer and fake_secret", "using [redacted LONG] and [redacted SHORT]"},
		{"pin 123 of 1234", "pin 123 of 1234"},
		{"GET /hook?api_key=abc&signal=3&page=2", "GET /hook?api_key=[redacted]&signal=3&page=2"},
		{"level=info db_password=hunter2 msg=ok", "level=info db_password=[redacted] msg=ok"},
		{`{"client_secret":"a\"b","keys":3}`, `{"client_secret":"[redacted]","keys":3}`},
		{"Authorization: Basic Zm9vOmJhcg==", "Authorization: [redacted]"},
		{"sent Bearer abc.def-ghi", "sent Bearer [redacted]"},
		{"https://user:pw@example.test/x by kyle@example.test", "https://[redacted]@example.test/x by kyle@example.test"},
		{"from 100.127.255.255 not 100.128.0.1", "from [mesh] not 100.128.0.1"},
		{"node fd7a:115c:a1e0::1 at web.example.ts.net", "node [mesh] at [mesh]"},
		{"10.0.0.1:8080 172.16.5.4 172.32.0.1 192.168.1.1 1.2.3.4 999.1.1.1", "[private]:8080 [private] 172.32.0.1 [private] 1.2.3.4 999.1.1.1"},
	} {
		if got := r.String(c.in); got != c.want {
			t.Errorf("%q became %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTheLeakScanReadsTextNotTimes(t *testing.T) {
	var r redactor
	r.add("YEAR", "2026", minSecretValue)
	e := full()
	if leaked := r.leaks(e); len(leaked) != 0 {
		t.Fatalf("times read as %q", leaked)
	}
	e.Logs[0].Lines[0].Text = "renewed until 2026"
	if leaked := r.leaks(e); !slices.Equal(leaked, []string{"YEAR"}) {
		t.Fatalf("leaked %q", leaked)
	}
}

func TestTheLeakScanSkipsHeliosOwnWordsAndLeavesThemInPlace(t *testing.T) {
	var r redactor
	r.add("RESULT", "succeeded", minEnvValue)
	e := full()
	e.RecentDeploys = []Change{{Operation: "op-api-1", Kind: "app.deploy", App: "api", StartedAt: opened, Outcome: "succeeded", Steps: []Step{{Name: "start", Status: "succeeded"}}}}
	before, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if leaked := r.leaks(e); len(leaked) != 0 {
		t.Fatalf("leaked %q", leaked)
	}
	if after, err := json.Marshal(e); err != nil || string(after) != string(before) {
		t.Fatalf("the scan changed the evidence: %v", err)
	}
	e.RecentDeploys[0].Steps[0].Name = "succeeded"
	if leaked := r.leaks(e); !slices.Equal(leaked, []string{"RESULT"}) {
		t.Fatalf("leaked %q", leaked)
	}
}

// Other encoders than Go's escape a value differently: PHP and Swift
// write / as \/, System.Text.Json and Gson write + and = as \u in upper or
// lower case, Python writes all but ASCII as \u, and a value can be
// written in base64's URL alphabet or URL escaped in lower case.
func TestAValueIsFoundHoweverItsEncoderEscapedIt(t *testing.T) {
	var r redactor
	r.add("SESSION_SECRET", "fake+b64/secret+value/AbCd=", minSecretValue)
	r.add("DATABASE_URL", "postgres://app:pg_fake_pw@db.example.test:5432/app", minEnvValue)
	r.add("PASSPHRASE", "pässwörd-fake🔑", minSecretValue)
	for _, c := range []struct{ in, want string }{
		{`{"session":"fake+b64\/secret+value\/AbCd="}`, `{"session":"[redacted SESSION_SECRET]"}`},
		{`{"session":"fake\u002Bb64/secret\u002Bvalue/AbCd\u003D"}`, `{"session":"[redacted SESSION_SECRET]"}`},
		{`{"session":"fake+b64/secret+value/AbCd\u003d"}`, `{"session":"[redacted SESSION_SECRET]"}`},
		{"cookie fake-b64_secret-value_AbCd set", "cookie [redacted SESSION_SECRET] set"},
		{"GET /next?to=fake%2bb64%2fsecret%2bvalue%2fAbCd%3d 302", "GET /next?to=[redacted SESSION_SECRET] 302"},
		{`{"db":"postgres:\/\/app:pg_fake_pw@db.example.test:5432\/app"}`, `{"db":"[redacted DATABASE_URL]"}`},
		{`{"cache":"redis:\/\/default:redis_fake_pw@cache.example.test:6379"}`, `{"cache":"redis:\/\/[redacted]@cache.example.test:6379"}`},
		{`{"phrase":"p\u00e4ssw\u00F6rd-fake\ud83d\udd11"}`, `{"phrase":"[redacted PASSPHRASE]"}`},
	} {
		if got := r.String(c.in); got != c.want {
			t.Errorf("%q became %q, want %q", c.in, got, c.want)
		}
	}
	e := full()
	e.Logs[0].Lines[0].Text = `config {"session":"fake\u002Bb64\/secret\u002Bvalue\/AbCd\u003D"}`
	if leaked := r.leaks(e); !slices.Equal(leaked, []string{"SESSION_SECRET"}) {
		t.Fatalf("leaked %q", leaked)
	}
}

// Text can be escaped again each time something carries it: JSON in a
// JSON log line, or a URL in a URL's query. Text escaped more times than
// are read is left out, since a value in it can't be found.
func TestAValueIsFoundHoweverManyTimesItWasEscaped(t *testing.T) {
	var r redactor
	r.add("SESSION_SECRET", "fake+b64/secret+value/AbCd=", minSecretValue)
	escaped := func(times int) string {
		v := "fake+b64/secret+value/AbCd="
		for range times {
			v = url.QueryEscape(v)
		}
		return "GET /cb?next=" + v + " 302"
	}
	for _, c := range []struct{ in, want string }{
		{`{"msg":"outgoing {\"session\":\"fake+b64\\\/secret+value\\\/AbCd=\"}","level":"info"}`, `{"msg":"outgoing {\"session\":\"[redacted SESSION_SECRET]\"}","level":"info"}`},
		{`{"message":"request {\"session\":\"fake+b64\\/secret+value\\/AbCd=\"}"}`, `{"message":"request {\"session\":\"[redacted SESSION_SECRET]\"}"}`},
		{`{"msg":"payload {\"session\":\"fake\\u002Bb64/secret\\u002Bvalue/AbCd\\u003D\"}"}`, `{"msg":"payload {\"session\":\"[redacted SESSION_SECRET]\"}"}`},
		{"GET /login?next=%2Fcb%3Fsession%3Dfake%252Bb64%252Fsecret%252Bvalue%252FAbCd%253D 302", "GET /login?next=%2Fcb%3Fsession%3D[redacted SESSION_SECRET] 302"},
		{escaped(maxFolds), "GET /cb?next=[redacted SESSION_SECRET] 302"},
		{escaped(maxFolds + 1), escapedTooOften},
	} {
		if got := r.String(c.in); got != c.want {
			t.Errorf("%q became %q, want %q", c.in, got, c.want)
		}
	}
	e := full()
	e.Logs[0].Lines[0].Text = `{"msg":"outgoing {\"session\":\"fake+b64\\\/secret+value\\\/AbCd=\"}"}`
	if leaked := r.leaks(e); !slices.Equal(leaked, []string{"SESSION_SECRET"}) {
		t.Errorf("leaked %q", leaked)
	}
	e.Logs[0].Lines[0].Text = escaped(maxFolds + 1)
	if leaked := r.leaks(e); !slices.Equal(leaked, []string{escapedTooOftenLeak}) {
		t.Errorf("leaked %q", leaked)
	}
}

// A resolver names an address backwards to look it up, a URL escapes an
// IPv6 address's colons, and an address can follow other dotted numbers.
func TestAMeshAddressIsFoundBackwardsEscapedOrRunIntoNumbers(t *testing.T) {
	var r redactor
	for _, c := range []struct{ in, want string }{
		{"lookup 4.3.64.100.in-addr.arpa. on 127.0.0.53:53: no such host", "lookup [mesh].in-addr.arpa. on 127.0.0.53:53: no such host"},
		{"lookup 1.0.0.10.in-addr.arpa.", "lookup [private].in-addr.arpa."},
		{"lookup 8.8.8.8.in-addr.arpa.", "lookup 8.8.8.8.in-addr.arpa."},
		{"lookup 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.", "lookup [mesh].ip6.arpa."},
		{"lookup 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", "lookup 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."},
		{"GET /cb?next=fd7a%3A115c%3Aa1e0%3A%3A1 200", "GET /cb?next=[mesh] 200"},
		{"GET /cb?to=http%3A%2F%2F%5Bfd7a%3a115c%3aa1e0%3a%3a1%5D%3A8080%2F 302", "GET /cb?to=http%3A%2F%2F%5B[mesh]%5D%3A8080%2F 302"},
		{"build 1.100.64.0.1", "build 1.[mesh]"},
		{"route 10.10.10.10.10", "route [private]"},
	} {
		if got := r.String(c.in); got != c.want {
			t.Errorf("%q became %q, want %q", c.in, got, c.want)
		}
	}
}

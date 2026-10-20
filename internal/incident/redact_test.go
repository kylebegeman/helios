package incident

import (
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

package incident

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAStatusPageIsReadWithinItsTimeAndSize(t *testing.T) {
	const ok = `{"status":{"indicator":"minor","description":"Partially Degraded Service"}}`
	answer := func(code int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v2/status.json" {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(code)
			io.WriteString(w, body)
		}
	}
	for _, c := range []struct {
		name                   string
		handler                http.HandlerFunc
		indicator, description string
		err                    string
	}{
		{"operational", answer(http.StatusOK, ok), "minor", "Partially Degraded Service", ""},
		{"64 KiB", answer(http.StatusOK, ok+strings.Repeat(" ", 64<<10-len(ok))), "minor", "Partially Degraded Service", ""},
		{"over 64 KiB", answer(http.StatusOK, ok+strings.Repeat(" ", 64<<10-len(ok)+1)), "", "", "the status page is over 64 KiB"},
		{"slow to answer", func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }, "", "", "no answer within 50ms"},
		{"slow to finish", func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"status":`)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}, "", "", "no answer within 50ms"},
		{"failing", answer(http.StatusServiceUnavailable, ok), "", "", "the status page answered 503 Service Unavailable"},
		{"no indicator", answer(http.StatusOK, `{"status":{}}`), "", "", "the status page has no indicator"},
	} {
		t.Run(c.name, func(t *testing.T) {
			server := httptest.NewServer(c.handler)
			defer server.Close()
			page := Statuspage{Name: "status.example.test", Base: server.URL + "/", Timeout: 50 * time.Millisecond}
			indicator, description, err := page.Fetch(context.Background())
			got := ""
			if err != nil {
				got = err.Error()
			}
			if indicator != c.indicator || description != c.description || got != c.err {
				t.Fatalf("got %q, %q, error %q", indicator, description, got)
			}
		})
	}
}

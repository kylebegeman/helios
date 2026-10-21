package incident

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Status page limits. The whole summary.json is about 235 KB, so only
// status.json is read.
const (
	statuspageTimeout = 5 * time.Second
	statuspageMax     = 64 << 10
)

// Statuspage is a vendor's Atlassian Statuspage, read at
// <Base>/api/v2/status.json.
type Statuspage struct {
	Name string
	Base string
	// Client is the HTTP client; nil is http.DefaultClient.
	Client *http.Client
	// Timeout bounds the read; zero is 5 seconds.
	Timeout time.Duration
}

// Upstreams are the status pages every incident's evidence reads: the
// services a host's apps lean on most.
func Upstreams() []Statuspage {
	return []Statuspage{
		{Name: "cloudflare", Base: "https://www.cloudflarestatus.com"},
		{Name: "github", Base: "https://www.githubstatus.com"},
	}
}

// Fetch reads the page's overall indicator, such as none or major, and
// its description.
func (s Statuspage) Fetch(ctx context.Context) (indicator, description string, err error) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = statuspageTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(s.Base, "/")+"/api/v2/status.json", nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/json")
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return "", "", fmt.Errorf("no answer within %s", timeout)
		}
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("the status page answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, statuspageMax+1))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return "", "", fmt.Errorf("no answer within %s", timeout)
		}
		return "", "", err
	}
	if len(body) > statuspageMax {
		return "", "", fmt.Errorf("the status page is over %d KiB", statuspageMax>>10)
	}
	var page struct {
		Status struct {
			Indicator   string `json:"indicator"`
			Description string `json:"description"`
		} `json:"status"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return "", "", fmt.Errorf("the status page isn't JSON: %w", err)
	}
	if page.Status.Indicator == "" {
		return "", "", errors.New("the status page has no indicator")
	}
	return cut(page.Status.Indicator, noteMax), cut(page.Status.Description, noteMax), nil
}

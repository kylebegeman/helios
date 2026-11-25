package edge

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Admin talks to Caddy's admin API, which listens only on a Unix socket in
// a directory the edge shares with this machine: no container, the apps'
// included, can reach it over the network.
type Admin struct {
	// Base is the URL requests go to; the host part is ignored on a socket.
	Base string
	// BootFile is where a loaded configuration is kept, for the edge to
	// start with after a restart. Empty keeps nothing.
	BootFile string
	http     *http.Client
}

// NewAdmin returns a client for the edge on this machine.
func NewAdmin() *Admin {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", AdminSocket)
		},
	}
	return &Admin{Base: "http://localhost", BootFile: BootFile, http: &http.Client{Timeout: 15 * time.Second, Transport: transport}}
}

// Load replaces the whole configuration atomically, then keeps it as the
// configuration the edge starts with. Caddy takes one identical to what it
// runs as nothing to do.
func (a *Admin) Load(ctx context.Context, config []byte) error {
	return a.load(ctx, config, false)
}

// LoadAgain is Load for a configuration the edge may already run, when
// having it start over is the point: Caddy provisions every app afresh,
// which begins certificate management again for each host, as a deploy's
// load of a changed configuration does. Without the Cache-Control header
// Caddy skips a configuration that changes nothing.
func (a *Admin) LoadAgain(ctx context.Context, config []byte) error {
	return a.load(ctx, config, true)
}

func (a *Admin) load(ctx context.Context, config []byte, again bool) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.Base+"/load", bytes.NewReader(config))
	if err != nil {
		return err
	}
	if again {
		// Exactly this value: some Caddy releases compare the whole header
		// with it rather than look for the token.
		req.Header.Set("Cache-Control", "must-revalidate")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("edge admin: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("edge rejected the configuration: %s: %s", resp.Status, bytes.TrimSpace(body))
	}
	if a.BootFile == "" {
		return nil
	}
	if err := WriteBoot(a.BootFile, config); err != nil {
		return fmt.Errorf("the edge took the configuration, but keeping it for its next start failed: %w", err)
	}
	return nil
}

// WriteBoot keeps a configuration where the edge reads it at start,
// replacing the file in one step so a restart never sees half of it.
func WriteBoot(path string, config []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// A name of its own: the CLI and the daemon can both load the edge.
	tmp := fmt.Sprintf("%s.%d-%d.tmp", path, os.Getpid(), time.Now().UnixNano())
	if err := os.WriteFile(tmp, config, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// Current returns the configuration the edge is running.
func (a *Admin) Current(ctx context.Context) ([]byte, error) {
	return a.get(ctx, "/config/")
}

// Metrics returns the edge's Prometheus metrics.
func (a *Admin) Metrics(ctx context.Context) ([]byte, error) {
	return a.get(ctx, "/metrics")
}

func (a *Admin) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.Base+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("edge admin: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("edge admin answered %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

// Answers reports whether the admin API is up.
func (a *Admin) Answers(ctx context.Context) bool {
	_, err := a.Current(ctx)
	return err == nil
}

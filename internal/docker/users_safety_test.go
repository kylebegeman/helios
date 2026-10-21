package docker

import (
	"archive/tar"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestAnImagesRootUserDefaultsToNobodyWithAnyNumericGroup(t *testing.T) {
	for _, user := range []string{"", "root", "0", "0:1000", "root:1000", "00:1000"} {
		t.Run(user, func(t *testing.T) {
			e, _ := interceptedEngine(t, func(w http.ResponseWriter, r *http.Request) bool {
				if strings.Contains(r.URL.Path, "/images/") && strings.HasSuffix(r.URL.Path, "/json") {
					json.NewEncoder(w).Encode(map[string]any{"Id": "root-user-" + user, "Config": map[string]any{"User": user}})
					return true
				}
				return false
			})
			u, err := e.EffectiveUser(context.Background(), "example:latest", "")
			if err != nil || u.UID != NobodyUID || u.GID != NobodyGID {
				t.Fatalf("image user %q runs as %+v, %v; want nobody", user, u, err)
			}
		})
	}
}

func TestAnExplicitRootUserKeepsItsRequestedNumericGroup(t *testing.T) {
	for _, user := range []string{"0:1000", "root:1000", "00:1000"} {
		t.Run(user, func(t *testing.T) {
			e, _ := connect(t)
			u, err := e.EffectiveUser(context.Background(), "example:latest", user)
			if err != nil || u.UID != 0 || u.GID != 1000 {
				t.Fatalf("explicit user %q = %+v, %v; want 0:1000", user, u, err)
			}
		})
	}
}

func TestAnImagesNamedUIDZeroUserAlsoDefaultsToNobody(t *testing.T) {
	e, _ := interceptedEngine(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/images/") && strings.HasSuffix(r.URL.Path, "/json") {
			json.NewEncoder(w).Encode(map[string]any{"Id": "named-root-user", "Config": map[string]any{"User": "administrator:1000"}})
			return true
		}
		if strings.HasSuffix(r.URL.Path, "/archive") && r.URL.Query().Get("path") == "/etc/passwd" {
			text := "administrator:x:0:1000::/:/bin/sh\n"
			w.Header().Set("X-Docker-Container-Path-Stat", base64.StdEncoding.EncodeToString([]byte(`{"name":"passwd"}`)))
			tw := tar.NewWriter(w)
			defer tw.Close()
			if err := tw.WriteHeader(&tar.Header{Name: "passwd", Mode: 0o644, Size: int64(len(text))}); err != nil {
				t.Error(err)
				return true
			}
			if _, err := io.WriteString(tw, text); err != nil {
				t.Error(err)
			}
			return true
		}
		return false
	})
	u, err := e.EffectiveUser(context.Background(), "example:latest", "")
	if err != nil || u.UID != NobodyUID || u.GID != NobodyGID {
		t.Fatalf("named root user runs as %+v, %v; want nobody", u, err)
	}
	// Explicitly requesting this image account still permits root.
	u, err = e.EffectiveUser(context.Background(), "example:latest", "administrator:1000")
	if err != nil || u.UID != 0 || u.GID != 1000 {
		t.Fatalf("explicit named root user = %+v, %v; want 0:1000", u, err)
	}
}

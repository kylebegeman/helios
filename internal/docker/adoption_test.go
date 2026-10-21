package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kylebegeman/helios/internal/docker/dockertest"
)

func interceptedEngine(t *testing.T, intercept func(http.ResponseWriter, *http.Request) bool) (*Engine, *dockertest.Server) {
	t.Helper()
	fake := dockertest.New(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !intercept(w, r) {
			fake.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("DOCKER_HOST", "tcp"+strings.TrimPrefix(server.URL, "http"))
	e, err := Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e, fake
}

func TestRunRefusesForeignOrMismatchedExistingContainers(t *testing.T) {
	for _, labels := range []map[string]string{
		{},
		{LabelOwner: OwnerValue, LabelApp: "other", LabelWorkload: "web"},
		{LabelOwner: OwnerValue, LabelApp: "site", LabelWorkload: "worker"},
	} {
		for _, running := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%s/running=%t", labels[LabelApp], labels[LabelWorkload], running), func(t *testing.T) {
				e, fake := connect(t)
				fake.Add(dockertest.Container{Name: "claimed", Running: running, Labels: labels})
				if err := e.Run(context.Background(), Spec{Name: "claimed", Image: "img", Labels: map[string]string{LabelApp: "site", LabelWorkload: "web"}}); err == nil {
					t.Fatal("adopted a container with another identity")
				}
				c, _ := fake.Container("claimed")
				if c.Running != running || fake.Last(func(call string) bool { return strings.HasPrefix(call, "POST ") }) >= 0 {
					t.Fatalf("mutated another container: %+v %v", c, fake.Calls())
				}
			})
		}
	}
}

func TestRunDoesNotCreateWhenInspectionFails(t *testing.T) {
	e, fake := interceptedEngine(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/containers/claimed/json") {
			http.Error(w, `{"message":"daemon unavailable"}`, http.StatusServiceUnavailable)
			return true
		}
		return false
	})
	if err := e.Run(context.Background(), Spec{Name: "claimed", Image: "img"}); err == nil || !strings.Contains(err.Error(), "daemon unavailable") {
		t.Fatalf("inspection failure: %v", err)
	}
	if _, ok := fake.Container("claimed"); ok {
		t.Fatal("created a container after failed inspection")
	}
}

func TestNetworkAdoptionRequiresOwnershipAndMatchingIsolation(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(map[bool]string{false: "existing", true: "create conflict"}[conflict], func(t *testing.T) {
			inspections := 0
			e, fake := interceptedEngine(t, func(w http.ResponseWriter, r *http.Request) bool {
				if conflict && strings.HasSuffix(r.URL.Path, "/networks/claimed") && r.Method == http.MethodGet {
					inspections++
					if inspections == 1 {
						http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
						return true
					}
				}
				if conflict && strings.HasSuffix(r.URL.Path, "/networks/create") {
					http.Error(w, `{"message":"name in use"}`, http.StatusConflict)
					return true
				}
				return false
			})
			fake.AddNetwork("claimed", map[string]string{})
			if err := e.EnsureNetwork(context.Background(), "claimed"); err == nil {
				t.Fatal("adopted a foreign network")
			}
		})
	}
	e, _ := connect(t)
	if err := e.EnsureInternalNetwork(context.Background(), "private"); err != nil {
		t.Fatal(err)
	}
	if err := e.EnsureNetwork(context.Background(), "private"); err == nil {
		t.Fatal("accepted internal network as an outbound-capable network")
	}
}

func TestImageDigestPinsLocallyImportedImagesByID(t *testing.T) {
	id := "sha256:" + strings.Repeat("a", 64)
	e, _ := interceptedEngine(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/images/") && strings.HasSuffix(r.URL.Path, "/json") {
			json.NewEncoder(w).Encode(map[string]any{"Id": id})
			return true
		}
		return false
	})
	if got, err := e.Digest(context.Background(), "local:latest"); err != nil || got != id {
		t.Fatalf("immutable local reference = %q, %v", got, err)
	}
}

func TestImageDescriptionHandlesShortAndMissingIDs(t *testing.T) {
	for _, id := range []string{"", "sha256:abc", "sha256:" + strings.Repeat("a", 64)} {
		if got := (Image{ID: id}).Describe(); len(got) > 12 {
			t.Fatalf("description %q", got)
		}
	}
}

func TestInspectionKeepsAnIPv6OnlyContainerAddress(t *testing.T) {
	e, _ := interceptedEngine(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/containers/v6/json") {
			json.NewEncoder(w).Encode(map[string]any{"Id": "v6", "NetworkSettings": map[string]any{"Networks": map[string]any{"private": map[string]any{"IPAddress": "", "GlobalIPv6Address": "2001:db8::2"}}}})
			return true
		}
		return false
	})
	if info, err := e.Inspect(context.Background(), "v6"); err != nil || info.IPs["private"] != "2001:db8::2" {
		t.Fatalf("lost IPv6 address: %+v, %v", info, err)
	}
}

func TestRunFinishesNetworkAttachmentAfterAnInterruptedCreate(t *testing.T) {
	attempts := 0
	e, fake := interceptedEngine(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/networks/extra/connect") {
			attempts++
			if attempts == 1 {
				http.Error(w, `{"message":"connect unavailable"}`, http.StatusServiceUnavailable)
				return true
			}
		}
		return false
	})
	spec := Spec{Name: "partial", Image: "img", Networks: []string{"primary", "extra"}}
	if err := e.Run(context.Background(), spec); err == nil {
		t.Fatal("network failure was ignored")
	}
	if err := e.Run(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if c, _ := fake.Container(spec.Name); !c.Running || attempts != 2 {
		t.Fatalf("started without repairing the network attachment: %+v attempts=%d", c, attempts)
	}
}

func TestVolumeAdoptionRefusesAnotherExplicitOwner(t *testing.T) {
	e, fake := connect(t)
	fake.AddVolume("bedrock-site-data", map[string]string{LabelOwner: "another-system"})
	if err := e.EnsureVolume(context.Background(), "bedrock-site-data"); err == nil {
		t.Fatal("adopted a volume explicitly owned by another system")
	}
}

func TestVolumeAdoptionKeepsLegacyUnlabeledVolumes(t *testing.T) {
	for _, labels := range []map[string]string{nil, {LabelOwner: OwnerValue}} {
		e, fake := connect(t)
		fake.AddVolume("bedrock-site-data", labels)
		if err := e.EnsureVolume(context.Background(), "bedrock-site-data"); err != nil {
			t.Fatalf("compatible volume was refused: %v", err)
		}
	}
}

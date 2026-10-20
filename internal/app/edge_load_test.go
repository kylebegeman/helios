package app

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/containerd/errdefs"
	"github.com/kylebegeman/helios/internal/docker"
	"github.com/kylebegeman/helios/internal/edge"
	"github.com/kylebegeman/helios/internal/secrets"
	"github.com/kylebegeman/helios/internal/state"
)

// fakeAdmin is an edge's admin API that answers or not, and keeps what it
// was given.
type fakeAdmin struct {
	answers bool
	refuse  error
	loads   int
}

func (a *fakeAdmin) Answers(context.Context) bool { return a.answers }

func (a *fakeAdmin) Load(context.Context, []byte) error {
	if a.refuse != nil {
		return a.refuse
	}
	a.loads++
	return nil
}

// An edge that doesn't answer takes nothing and keeps what it last took,
// so loading it says so, without an error, rather than count it loaded;
// the daemon then asks again.
func TestLoadingAnEdgeThatDoesNotAnswerReportsNothingLoaded(t *testing.T) {
	ctx := context.Background()
	store, sec := goldenStore(t), newSecrets(t)

	down := &fakeAdmin{}
	loaded, err := loadEdge(ctx, down, store, sec)
	if loaded || err != nil || down.loads != 0 {
		t.Fatalf("an edge not answering: loaded %v, %v, %d loads", loaded, err, down.loads)
	}

	up := &fakeAdmin{answers: true}
	loaded, err = loadEdge(ctx, up, store, sec)
	if !loaded || err != nil || up.loads != 1 {
		t.Fatalf("an edge that answers: loaded %v, %v, %d loads", loaded, err, up.loads)
	}

	refusing := &fakeAdmin{answers: true, refuse: errors.New("edge rejected the configuration")}
	loaded, err = loadEdge(ctx, refusing, store, sec)
	if loaded || err == nil {
		t.Fatalf("an edge that refuses the configuration: loaded %v, %v", loaded, err)
	}
}

// An edge that isn't there yet, or that Docker fails to describe, is
// neither replaced nor loaded, so upgrading it reports nothing loaded; a
// daemon starting there then reloads the edge when a CA runs out rather
// than trust whatever the edge last took.
func TestUpgradingAnEdgeThatCannotBeInspectedReportsNothingLoaded(t *testing.T) {
	for _, inspectErr := range []error{errdefs.ErrNotFound, errors.New("docker took too long to answer")} {
		var steps []string
		loaded, err := upgradeEdge(context.Background(), nil, nil, nil, inspectErr,
			func() error { steps = append(steps, "replace"); return nil },
			loader(&steps, true, nil))
		if loaded || err != nil || len(steps) != 0 {
			t.Fatalf("inspecting the edge failed with %q: loaded %v, %v, %v", inspectErr, loaded, err, steps)
		}
	}
}

// An edge that is there reports exactly what loading it did: one not
// answering yet took nothing, and nor did one that refused it, so the
// daemon counts the edge loaded only from when it took a configuration.
func TestUpgradingAnEdgeReportsWhatLoadingItDid(t *testing.T) {
	current := &docker.Info{Labels: map[string]string{edge.LayoutLabel: edge.Layout}}
	refused := errors.New("edge rejected the configuration")
	for _, load := range []struct {
		loaded bool
		err    error
	}{{false, nil}, {true, nil}, {false, refused}} {
		var steps []string
		loaded, err := upgradeEdge(context.Background(), nil, nil, current, nil,
			func() error { steps = append(steps, "replace"); return nil },
			loader(&steps, load.loaded, load.err))
		if loaded != load.loaded || err != load.err || !slices.Equal(steps, []string{"load"}) {
			t.Fatalf("loading reported %v, %v: upgrading reported %v, %v after %v", load.loaded, load.err, loaded, err, steps)
		}
	}
}

// An edge an older helios made is replaced before it is loaded. One that
// can't be replaced isn't loaded, and says why.
func TestUpgradingAnOlderEdgeReplacesItBeforeLoading(t *testing.T) {
	older := &docker.Info{Labels: map[string]string{}}
	var steps []string
	loaded, err := upgradeEdge(context.Background(), nil, nil, older, nil,
		func() error { steps = append(steps, "replace"); return nil },
		loader(&steps, true, nil))
	if !loaded || err != nil || !slices.Equal(steps, []string{"replace", "load"}) {
		t.Fatalf("an older edge: loaded %v, %v after %v", loaded, err, steps)
	}

	stuck := errors.New("the older edge would not stop")
	steps = nil
	loaded, err = upgradeEdge(context.Background(), nil, nil, older, nil,
		func() error { steps = append(steps, "replace"); return stuck },
		loader(&steps, true, nil))
	if loaded || err != stuck || !slices.Equal(steps, []string{"replace"}) {
		t.Fatalf("an older edge that can't be replaced: loaded %v, %v after %v", loaded, err, steps)
	}
}

// loader stands in for LoadEdge, noting that it ran and answering as told.
func loader(steps *[]string, loaded bool, err error) func(context.Context, *state.Store, *secrets.Store) (bool, error) {
	return func(context.Context, *state.Store, *secrets.Store) (bool, error) {
		*steps = append(*steps, "load")
		return loaded, err
	}
}

package app

import (
	"context"
	"errors"
	"testing"
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

package daemon

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/watch"
)

func TestAPanickingLocalWatchWaitsForItsPeerObservation(t *testing.T) {
	peersStarted := make(chan struct{})
	releasePeers := make(chan struct{})
	returned := make(chan struct{})
	var release sync.Once
	t.Cleanup(func() {
		release.Do(func() { close(releasePeers) })
		select {
		case <-returned:
		case <-time.After(time.Second):
			t.Error("the watch round did not finish after its peer observation")
		}
	})
	logf := func(string, ...any) {}
	d := &daemon{logf: logf}
	go func() {
		defer close(returned)
		guarded(logf, "watch", func() {
			d.watchRound(context.Background(), nil,
				func(context.Context) []watch.Condition {
					<-peersStarted
					panic("a defect in the local watch")
				},
				func(context.Context) []watch.Condition {
					close(peersStarted)
					<-releasePeers
					return nil
				})
		})
	}()
	<-peersStarted
	select {
	case <-returned:
		t.Fatal("the daemon can close state while its peer observation still runs")
	case <-time.After(100 * time.Millisecond):
	}
	release.Do(func() { close(releasePeers) })
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("the watch round did not finish after its peer observation")
	}
}

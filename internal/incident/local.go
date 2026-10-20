package incident

import (
	"context"
	"io"
	"sync"

	"github.com/kylebegeman/helios/internal/docker"
)

// Local points src at this machine's Docker, journal and upstream status
// pages, and returns what releases them.
func Local(src *Sources) (release func()) {
	engine := &lazyEngine{}
	src.Engine, src.Journal, src.Upstream = engine, docker.Journal{}, Upstreams()
	return engine.close
}

// lazyEngine connects to Docker on the first read of a container's
// output, so evidence that reads none never does.
type lazyEngine struct {
	once   sync.Once
	engine *docker.Engine
	err    error
}

func (l *lazyEngine) LogStreams(ctx context.Context, name string, opts docker.LogOptions, stdout, stderr io.Writer) error {
	l.once.Do(func() { l.engine, l.err = docker.Connect(ctx) })
	if l.err != nil {
		return l.err
	}
	return l.engine.LogStreams(ctx, name, opts, stdout, stderr)
}

func (l *lazyEngine) close() {
	if l.engine != nil {
		l.engine.Close()
	}
}

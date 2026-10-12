package server

import (
	"runtime/debug"
	"sync"
)

// bigUploadBytes is the size of an upload from which its analysis runs with a
// tighter garbage collector (see gcGovernor): such an analysis holds the
// packets of the whole capture, gigabytes of them, and the default collector
// would let as much garbage pile up beside them before it ran.
const bigUploadBytes = 32 << 20

// bigGCPercent is the collector's target while a big analysis runs. At 50 the
// peak memory of a 1.5 million packet analysis fell by about a fifth with no
// change in speed; going lower bought nothing more.
const bigGCPercent = 50

// gcGovernor lowers the garbage collector's GC percent while big analyses run
// and puts the original value back when the last of them is done, so
// concurrent analyses do not undo each other's setting.
type gcGovernor struct {
	mu       sync.Mutex
	active   int
	original int
}

// lower starts a big analysis and returns the function that ends it.
func (g *gcGovernor) lower() (done func()) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active == 0 {
		g.original = debug.SetGCPercent(bigGCPercent)
	}
	g.active++
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.active--
			if g.active == 0 {
				debug.SetGCPercent(g.original)
			}
		})
	}
}

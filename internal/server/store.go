package server

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

const (
	// maxStoredAnalyses is how many analyses the server keeps: the web UI
	// reloads one after a page refresh and exports from it. The oldest goes
	// first.
	maxStoredAnalyses = 8

	// storedAnalysisTTL is how long an analysis is kept.
	storedAnalysisTTL = 2 * time.Hour
)

// analysisStore keeps the latest analyses in memory, by an unguessable ID.
// They are not tied to a user: the server has a single login, and every
// endpoint that reads them needs it.
type analysisStore struct {
	mu    sync.Mutex
	items map[string]storedAnalysis
	order []string // oldest first
	max   int
	ttl   time.Duration
	now   func() time.Time
}

type storedAnalysis struct {
	res *models.AnalysisResult
	at  time.Time
}

func newAnalysisStore() *analysisStore {
	return &analysisStore{items: make(map[string]storedAnalysis), max: maxStoredAnalyses, ttl: storedAnalysisTTL, now: time.Now}
}

// put stores res and returns its ID. The retransmission events of its flows
// are dropped: nothing served from the store needs them, and a large capture
// has many.
func (s *analysisStore) put(res *models.AnalysisResult) string {
	for i := range res.Flows {
		res.Flows[i].RetransmitEvents = nil
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand failed: " + err.Error()) // the system has no entropy source: nothing safe to do
	}
	id := hex.EncodeToString(buf)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	s.items[id] = storedAnalysis{res: res, at: s.now()}
	s.order = append(s.order, id)
	for len(s.order) > s.max {
		delete(s.items, s.order[0])
		s.order = s.order[1:]
	}
	return id
}

// get returns the analysis with the given ID, if it is still held.
func (s *analysisStore) get(id string) (*models.AnalysisResult, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	it, ok := s.items[id]
	return it.res, ok
}

// expire drops analyses older than the TTL. The caller holds the lock.
func (s *analysisStore) expire() {
	cutoff := s.now().Add(-s.ttl)
	kept := s.order[:0]
	for _, id := range s.order {
		if s.items[id].at.Before(cutoff) {
			delete(s.items, id)
			continue
		}
		kept = append(kept, id)
	}
	s.order = kept
}

package routerstate

import (
	"sync"
	"time"
)

// MemStore — хранилище в памяти для тестов и eval: рестарт процесса обнуляет состояние;
// повторный Load имитирует рестарт (резервы, незакрытые к этому моменту, списываются).
type MemStore struct {
	mu     sync.Mutex
	st     *State
	ops    int
	failed error
	now    func() time.Time
}

func NewMemory(id Identity) *MemStore { return &MemStore{st: NewState(id), now: time.Now} }

func (s *MemStore) Load() (*State, LoadInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return nil, LoadInfo{}, ErrFailed
	}
	info := LoadInfo{Fresh: s.ops == 0}
	for _, h := range s.st.Holds {
		info.OrphanHolds++
		info.OrphanTokens += h.Tokens
	}
	for _, op := range recoverOrphans(s.st, stamp(s.now())) {
		if err := s.st.Apply(op); err != nil {
			return nil, LoadInfo{}, err
		}
		s.ops++
	}
	return s.st.Clone(), info, nil
}

func (s *MemStore) Append(op Op) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return ErrFailed
	}
	if err := s.st.Apply(op); err != nil {
		return err
	}
	s.ops++
	return nil
}

func (s *MemStore) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failed
}

func (s *MemStore) Close() error { return nil }

// Snapshot — копия текущего состояния.
func (s *MemStore) Snapshot() *State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Clone()
}

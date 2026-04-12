package sshhoneypot

import (
	"sync"

	"github.com/rexlx/sweetshell/internal"
)

type SSHHoneypot struct {
	Memory sync.RWMutex
	Stats  []internal.Stat
}

func (s *SSHHoneypot) Start() error {
	return nil
}

func (s *SSHHoneypot) Stop() error {
	return nil
}

func (s *SSHHoneypot) ClearData() error {
	s.Memory.Lock()
	defer s.Memory.Unlock()
	s.Stats = []internal.Stat{}
	return nil
}

func (s *SSHHoneypot) AddStat(stat internal.Stat) error {
	s.Memory.Lock()
	defer s.Memory.Unlock()
	s.Stats = append(s.Stats, stat)
	return nil
}

func (s *SSHHoneypot) GetStats() ([]internal.Stat, error) {
	s.Memory.RLock()
	defer s.Memory.RUnlock()
	return s.Stats, nil
}

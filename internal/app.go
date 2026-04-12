package internal

import (
	"net/http"
	"sync"
	"time"
)

type Stat struct {
	TransactionID string    `json:"transaction_id"`
	Info          string    `json:"info"`
	Time          time.Time `json:"time"`
	Value         string    `json:"value"`
}

type Honeypot interface {
	Start() error
	Stop() error
	ClearData() error
	AddStat(stat Stat) error
	GetStats() ([]Stat, error)
}

type App struct {
	Gateway             *http.ServeMux
	Memory              sync.RWMutex
	LogRoationFrequency time.Duration
	StartTime           time.Time
	APIKey              string
	HoneyPots           map[string]Honeypot
}

func NewApp(apiKey string, logRotationFrequency time.Duration) *App {
	return &App{
		Gateway:             http.NewServeMux(),
		LogRoationFrequency: logRotationFrequency,
		StartTime:           time.Now(),
		APIKey:              apiKey,
		HoneyPots:           make(map[string]Honeypot),
	}
}

func (a *App) AddHoneypot(name string, honeypot Honeypot) {
	a.Memory.Lock()
	defer a.Memory.Unlock()
	a.HoneyPots[name] = honeypot
}

func (a *App) RotateLogs() {}

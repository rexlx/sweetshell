package internal

import (
	"net/http"
	"sync"
	"time"
)

type Stat struct {
	TransactionID string                 `json:"transaction_id"`
	Value         string                 `json:"value"`
	Info          string                 `json:"info"`
	Time          time.Time              `json:"time"`
	Payload       map[string]interface{} `json:"payload"`
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
	app := &App{
		Gateway:             http.NewServeMux(),
		LogRoationFrequency: logRotationFrequency,
		StartTime:           time.Now(),
		APIKey:              apiKey,
		HoneyPots:           make(map[string]Honeypot),
	}
	app.Gateway.Handle("GET /stats/{name}", app.AuthMiddleware(http.HandlerFunc(app.HandleGetStats)))
	app.Gateway.Handle("/honeypots", app.AuthMiddleware(http.HandlerFunc(app.HandleListHoneypots)))
	return app
}

func (a *App) AddHoneypot(name string, honeypot Honeypot) {
	a.Memory.Lock()
	defer a.Memory.Unlock()
	a.HoneyPots[name] = honeypot
}

func (a *App) RotateLogs() {}

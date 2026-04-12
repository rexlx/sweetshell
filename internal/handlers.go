package internal

import (
	"encoding/json"
	"net/http"
)

// HandleGetStats returns the logs for a specific honeypot by name.
func (a *App) HandleGetStats(w http.ResponseWriter, r *http.Request) {
	// Extract the honeypot name from the URL path (e.g., /stats/{name})
	name := r.PathValue("name")

	// Look up the honeypot in the registry with a read-lock
	a.Memory.RLock()
	hp, exists := a.HoneyPots[name]
	a.Memory.RUnlock()

	if !exists {
		http.Error(w, "Honeypot not found", http.StatusNotFound)
		return
	}

	// Retrieve the stats from the honeypot's internal memory
	stats, err := hp.GetStats()
	if err != nil {
		http.Error(w, "Failed to retrieve stats", http.StatusInternalServerError)
		return
	}

	// Serve as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// HandleListHoneypots returns a list of all registered honeypot names.
func (a *App) HandleListHoneypots(w http.ResponseWriter, r *http.Request) {
	a.Memory.RLock()
	defer a.Memory.RUnlock()

	names := make([]string, 0, len(a.HoneyPots))
	for name := range a.HoneyPots {
		names = append(names, name)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(names)
}

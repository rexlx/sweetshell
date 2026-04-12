package internal

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"
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

// HandleGetReputation looks up a specific IP or Hostname in the indicators table.
func (a *App) HandleGetReputation(w http.ResponseWriter, r *http.Request) {
	// Extract the search value from the URL path (e.g., /reputation/{value})
	value := r.PathValue("value")

	if value == "" {
		http.Error(w, "Value parameter is required", http.StatusBadRequest)
		return
	}

	var reputation string
	var count int
	var lastSeen time.Time

	// Query the global DB object
	query := `SELECT reputation, occurrence_count, last_seen FROM indicators WHERE value = $1`
	err := DB.QueryRow(query, value).Scan(&reputation, &count, &lastSeen)

	if err == sql.ErrNoRows {
		// If the value isn't in our DB yet, we return an 'unknown' status instead of 404
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"value":      value,
			"reputation": "unknown",
			"message":    "No historical data found for this identifier",
		})
		return
	} else if err != nil {
		http.Error(w, "Database query failed", http.StatusInternalServerError)
		return
	}

	// Prepare response
	response := struct {
		Value      string    `json:"value"`
		Reputation string    `json:"reputation"`
		Hits       int       `json:"total_hits"`
		LastSeen   time.Time `json:"last_seen"`
	}{
		Value:      value,
		Reputation: reputation,
		Hits:       count,
		LastSeen:   lastSeen,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

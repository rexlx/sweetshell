package internal

import (
	"net/http"
)

// AuthMiddleware wraps a handler to ensure the request has a valid API Key.
func (a *App) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestKey := r.Header.Get("X-API-Key")

		if requestKey == "" || requestKey != a.APIKey {
			http.Error(w, "Unauthorized: Invalid or missing API Key", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

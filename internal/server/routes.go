package server

import (
	"encoding/json"
	"log"
	"net/http"
)

func (s *Server) RegisterRoutes() http.Handler {
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("GET /", s.HelloWorldHandler)

	// Public auth routes (no authentication required)
	mux.HandleFunc("POST /auth/register", s.authHandler.Register)
	mux.HandleFunc("POST /auth/login", s.authHandler.Login)

	// Protected auth routes (authentication required)
	mux.HandleFunc("POST /auth/refresh", s.authMiddleware(s.authHandler.Refresh))
	mux.HandleFunc("POST /auth/logout", s.authMiddleware(s.authHandler.Logout))
	mux.HandleFunc("GET /auth/me", s.authMiddleware(s.authHandler.Me))

	// Wrap the mux with CORS middleware
	return s.corsMiddleware(mux)
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		// IMPORTANT: In production, replace with your actual frontend URL
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = s.config.FrontendURL
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-CSRF-Token")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight OPTIONS requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Proceed with the next handler
		next.ServeHTTP(w, r)
	})
}

func (s *Server) HelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	resp := map[string]string{"message": "Hello World"}
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(jsonResp); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

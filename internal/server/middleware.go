package server

import (
	"context"
	"log"
	"net/http"

	"auth-microservice/internal/utils"
)

// authMiddleware validates the access token and adds user info to the request context
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract access token from cookie
		accessToken, err := utils.GetCookieValue(r, utils.AccessTokenCookie)
		if err != nil {
			utils.WriteError(w, http.StatusUnauthorized, "unauthorized", "No access token found")
			return
		}

		// Validate token and get user info
		user, err := s.authHandler.ValidateAccessToken(r.Context(), accessToken)
		if err != nil {
			log.Printf("Failed to validate access token: %v", err)
			utils.WriteError(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired access token")
			return
		}

		// Add user to request context
		ctx := context.WithValue(r.Context(), utils.UserContextKey, user)

		// Call the next handler with the updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

package utils

import (
	"fmt"
	"net/http"
	"strings"
)

// ExtractBearerToken extrae el token del header Authorization
// Formato esperado: "Authorization: Bearer <token>"
func ExtractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("authorization header missing")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return parts[1], nil
}

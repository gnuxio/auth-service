package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// JWTClaims represents the claims from a Cognito JWT token
type JWTClaims struct {
	Sub               string `json:"sub"`
	Email             string `json:"email"`
	CognitoUsername   string `json:"cognito:username"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
}

// DecodeJWTClaims decodes a JWT token and extracts the claims without verification
// Note: This is only used to extract the username for refresh token operations
// Token validation is handled by Cognito's GetUser API
func DecodeJWTClaims(token string) (*JWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims JWTClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWT claims: %w", err)
	}

	return &claims, nil
}

// GetUsernameFromIDToken extracts the username from an ID token
// Returns cognito:username which is the authoritative username used by Cognito
func GetUsernameFromIDToken(idToken string) (string, error) {
	claims, err := DecodeJWTClaims(idToken)
	if err != nil {
		return "", err
	}

	// cognito:username is the authoritative username in Cognito
	// This is what was used during authentication
	if claims.CognitoUsername != "" {
		return claims.CognitoUsername, nil
	}

	// Fallback to email (should match cognito:username in most cases)
	if claims.Email != "" {
		return claims.Email, nil
	}

	// Last resort: use sub (user UUID)
	if claims.Sub != "" {
		return claims.Sub, nil
	}

	return "", fmt.Errorf("no username found in token")
}

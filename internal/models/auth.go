package models

// LoginRequest represents the login request payload
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RegisterRequest represents the registration request payload
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name,omitempty"`
}

// RefreshRequest is empty since refresh token comes from cookie
type RefreshRequest struct{}

// LogoutRequest is empty since logout just clears cookies
type LogoutRequest struct{}

// AuthResponse represents the successful authentication response
type AuthResponse struct {
	User    User   `json:"user"`
	Message string `json:"message,omitempty"`
}

// User represents the authenticated user data
type User struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name,omitempty"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// CognitoTokens holds the tokens returned from Cognito
type CognitoTokens struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	ExpiresIn    int32
}

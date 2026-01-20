package handlers

import (
	"context"
	"log"
	"net/http"
	"strings"

	"auth-microservice/internal/cognito"
	"auth-microservice/internal/config"
	"auth-microservice/internal/models"
	"auth-microservice/internal/utils"
)

type AuthHandler struct {
	cognitoClient *cognito.Client
	config        *config.Config
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(cognitoClient *cognito.Client, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		cognitoClient: cognitoClient,
		config:        cfg,
	}
}

// getCookieOptions determines the cookie options based on the request origin.
func (h *AuthHandler) getCookieOptions(r *http.Request) utils.CookieOptions {
	origin := r.Header.Get("Origin")

	// Check if the origin is a known local development host.
	isLocal := strings.HasPrefix(origin, "http://localhost") || strings.HasPrefix(origin, "http://127.0.0.1")

	// For local development, we don't set the domain, allowing the browser to use the host from the request.
	if isLocal {
		return utils.CookieOptions{
			Domain: "",    // Let the browser handle it for localhost.
			Secure: false, // Cookies for localhost should not be Secure.
		}
	}

	// For production, use the configured domain and secure setting.
	return utils.CookieOptions{
		Domain: h.config.CookieDomain,
		Secure: h.config.CookieSecure,
	}
}

// ValidateAccessToken validates an access token and returns the user info
func (h *AuthHandler) ValidateAccessToken(ctx context.Context, accessToken string) (*models.User, error) {
	return h.cognitoClient.GetUser(ctx, accessToken)
}

// Register handles user registration
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req models.RegisterRequest
	if err := utils.ParseJSON(r, &req); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		utils.WriteError(w, http.StatusBadRequest, "missing_fields", "Email and password are required")
		return
	}

	if err := h.cognitoClient.SignUp(r.Context(), req.Email, req.Password, req.Name); err != nil {
		log.Printf("Registration failed: %v", err)
		utils.WriteError(w, http.StatusBadRequest, "registration_failed", err.Error())
		return
	}

	response := models.AuthResponse{
		Message: "Registration successful. Please check your email to verify your account.",
	}

	utils.WriteJSON(w, http.StatusCreated, response)
}

// Login handles user authentication
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := utils.ParseJSON(r, &req); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		utils.WriteError(w, http.StatusBadRequest, "missing_fields", "Email and password are required")
		return
	}

	log.Printf("Login request - username (email): %s", req.Email)

	tokens, err := h.cognitoClient.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		log.Printf("Login failed: %v", err)
		utils.WriteError(w, http.StatusUnauthorized, "authentication_failed", "Invalid email or password")
		return
	}

	user, err := h.cognitoClient.GetUser(r.Context(), tokens.AccessToken)
	if err != nil {
		log.Printf("Failed to get user info: %v", err)
		utils.WriteError(w, http.StatusInternalServerError, "user_info_failed", "Failed to retrieve user information")
		return
	}

	response := models.AuthResponse{
		User:         *user,
		Message:      "Login successful",
		AccessToken:  tokens.AccessToken,
		IDToken:      tokens.IDToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    tokens.ExpiresIn,
	}

	utils.WriteJSON(w, http.StatusOK, response)
}

// Refresh handles token refresh
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	// Get refresh token from request body
	var req models.RefreshRequest
	if err := utils.ParseJSON(r, &req); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.RefreshToken == "" {
		utils.WriteError(w, http.StatusBadRequest, "missing_refresh_token", "Refresh token is required")
		return
	}

	// Get email from request body (no middleware required for refresh)
	if req.Email == "" {
		utils.WriteError(w, http.StatusBadRequest, "missing_email", "Email is required")
		return
	}
	username := req.Email

	log.Printf("Refresh token request - username: %s", username)

	tokens, err := h.cognitoClient.RefreshToken(r.Context(), req.RefreshToken, username)
	if err != nil {
		log.Printf("Token refresh failed: %v", err)
		utils.WriteError(w, http.StatusUnauthorized, "refresh_failed", "Failed to refresh token")
		return
	}

	updatedUser, err := h.cognitoClient.GetUser(r.Context(), tokens.AccessToken)
	if err != nil {
		log.Printf("Failed to get user info: %v", err)
		utils.WriteError(w, http.StatusInternalServerError, "user_info_failed", "Failed to retrieve user information")
		return
	}

	response := models.AuthResponse{
		User:         *updatedUser,
		Message:      "Token refreshed successfully",
		AccessToken:  tokens.AccessToken,
		IDToken:      tokens.IDToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    tokens.ExpiresIn,
	}

	utils.WriteJSON(w, http.StatusOK, response)
}

// Logout handles user logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Extract access token from Authorization header
	accessToken, err := utils.ExtractBearerToken(r)
	if err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	// Perform global sign out in Cognito
	if err := h.cognitoClient.GlobalSignOut(r.Context(), accessToken); err != nil {
		log.Printf("Global signout failed: %v", err)
		utils.WriteError(w, http.StatusInternalServerError, "signout_failed", "Failed to sign out")
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Logged out successfully",
	})
}

// Me returns the current authenticated user
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	user, ok := utils.GetUserFromContext(r.Context())
	if !ok {
		log.Printf("User not found in context despite auth middleware")
		utils.WriteError(w, http.StatusInternalServerError, "server_error", "Failed to retrieve user from context")
		return
	}

	response := models.AuthResponse{
		User: *user,
	}

	utils.WriteJSON(w, http.StatusOK, response)
}

// VerifyEmail confirms a user's email with a verification code
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req models.VerifyEmailRequest
	if err := utils.ParseJSON(r, &req); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.Email == "" || req.Code == "" {
		utils.WriteError(w, http.StatusBadRequest, "missing_fields", "Email and verification code are required")
		return
	}

	if err := h.cognitoClient.ConfirmSignUp(r.Context(), req.Email, req.Code); err != nil {
		log.Printf("Email verification failed: %v", err)
		utils.WriteError(w, http.StatusBadRequest, "verification_failed", "Invalid or expired verification code")
		return
	}

	response := models.AuthResponse{
		Message: "Email verified successfully. You can now log in.",
	}

	utils.WriteJSON(w, http.StatusOK, response)
}

// ResendVerification resends the verification code to the user's email
func (h *AuthHandler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	var req models.ResendVerificationRequest
	if err := utils.ParseJSON(r, &req); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.Email == "" {
		utils.WriteError(w, http.StatusBadRequest, "missing_fields", "Email is required")
		return
	}

	if err := h.cognitoClient.ResendConfirmationCode(r.Context(), req.Email); err != nil {
		log.Printf("Failed to resend verification code: %v", err)
		utils.WriteError(w, http.StatusBadRequest, "resend_failed", "Failed to resend verification code")
		return
	}

	response := models.AuthResponse{
		Message: "Verification code sent. Please check your email.",
	}

	utils.WriteJSON(w, http.StatusOK, response)
}

// ForgotPassword initiates the password reset process
func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req models.ForgotPasswordRequest
	if err := utils.ParseJSON(r, &req); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.Email == "" {
		utils.WriteError(w, http.StatusBadRequest, "missing_fields", "Email is required")
		return
	}

	if err := h.cognitoClient.ForgotPassword(r.Context(), req.Email); err != nil {
		log.Printf("Failed to initiate password reset: %v", err)
		utils.WriteError(w, http.StatusBadRequest, "forgot_password_failed", "Failed to initiate password reset")
		return
	}

	response := models.AuthResponse{
		Message: "Password reset code sent. Please check your email.",
	}

	utils.WriteJSON(w, http.StatusOK, response)
}

// ResetPassword completes the password reset process
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req models.ResetPasswordRequest
	if err := utils.ParseJSON(r, &req); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.Email == "" || req.Code == "" || req.NewPassword == "" {
		utils.WriteError(w, http.StatusBadRequest, "missing_fields", "Email, code, and new password are required")
		return
	}

	if err := h.cognitoClient.ConfirmForgotPassword(r.Context(), req.Email, req.Code, req.NewPassword); err != nil {
		log.Printf("Password reset failed: %v", err)
		utils.WriteError(w, http.StatusBadRequest, "reset_password_failed", "Invalid or expired code, or password does not meet requirements")
		return
	}

	response := models.AuthResponse{
		Message: "Password reset successful. You can now log in with your new password.",
	}

	utils.WriteJSON(w, http.StatusOK, response)
}

// ChangePassword allows authenticated users to change their password
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var req models.ChangePasswordRequest
	if err := utils.ParseJSON(r, &req); err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		utils.WriteError(w, http.StatusBadRequest, "missing_fields", "Current password and new password are required")
		return
	}

	// Get access token from Authorization header
	accessToken, err := utils.ExtractBearerToken(r)
	if err != nil {
		utils.WriteError(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	if err := h.cognitoClient.ChangePassword(r.Context(), accessToken, req.CurrentPassword, req.NewPassword); err != nil {
		log.Printf("Password change failed: %v", err)
		utils.WriteError(w, http.StatusBadRequest, "change_password_failed", "Invalid current password or new password does not meet requirements")
		return
	}

	response := models.AuthResponse{
		Message: "Password changed successfully.",
	}

	utils.WriteJSON(w, http.StatusOK, response)
}

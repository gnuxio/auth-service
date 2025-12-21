package utils

import (
	"net/http"
)

const (
	AccessTokenCookie  = "access_token"
	IDTokenCookie      = "id_token"
	RefreshTokenCookie = "refresh_token"
)

// CookieOptions holds configuration for setting cookies
type CookieOptions struct {
	Domain string
	Secure bool
}

// SetAuthCookies sets all authentication cookies (access, ID, and refresh tokens)
func SetAuthCookies(w http.ResponseWriter, accessToken, idToken, refreshToken string, expiresIn int32, opts CookieOptions) {
	// Access token cookie
	setSecureCookie(w, AccessTokenCookie, accessToken, int(expiresIn), opts)

	// ID token cookie
	setSecureCookie(w, IDTokenCookie, idToken, int(expiresIn), opts)

	// Refresh token cookie
	setSecureCookie(w, RefreshTokenCookie, refreshToken, 30*24*60*60, opts)
}

// ClearAuthCookies removes all authentication cookies
func ClearAuthCookies(w http.ResponseWriter, opts CookieOptions) {
	clearCookie(w, AccessTokenCookie, opts)
	clearCookie(w, IDTokenCookie, opts)
	clearCookie(w, RefreshTokenCookie, opts)
}

// GetCookieValue retrieves a cookie value from the request
func GetCookieValue(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

// setSecureCookie creates a secure, httpOnly cookie
func setSecureCookie(w http.ResponseWriter, name, value string, maxAge int, opts CookieOptions) {
	// Use SameSite=Lax for local development (when Secure is false)
	// Use SameSite=None for production (when Secure is true) to allow cross-site cookies
	sameSite := http.SameSiteLaxMode
	if opts.Secure {
		sameSite = http.SameSiteNoneMode
	}

	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   opts.Secure,
		SameSite: sameSite,
	}

	if opts.Domain != "" {
		cookie.Domain = opts.Domain
	}

	http.SetCookie(w, cookie)
}

// clearCookie removes a cookie by setting its MaxAge to -1
func clearCookie(w http.ResponseWriter, name string, opts CookieOptions) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   opts.Secure,
		SameSite: http.SameSiteStrictMode,
	}

	if opts.Domain != "" {
		cookie.Domain = opts.Domain
	}

	http.SetCookie(w, cookie)
}

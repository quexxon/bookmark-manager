package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/saaste/bookmark-manager/config"
)

type contextKey string

const authenticatedContextKey contextKey = "authenticated"

// AuthMiddlewareConfig holds configuration options for the authentication
// middleware. The type is opaque. Individual options must by set via
// AuthMiddlewareOption functions.
type AuthMiddlewareConfig struct {
	useBearerToken    bool
	redirect          string
	bypassRemediation bool
}

// AuthMiddlewareOption is a function type that modifies AuthMiddlewareConfig.
type AuthMiddlewareOption func(*AuthMiddlewareConfig)

// WithBearerToken enables bearer token authentication.
func WithBearerToken(config *AuthMiddlewareConfig) {
	config.useBearerToken = true
}

// WithRedirect sets a redirect URL for unauthenticated requests. When present,
// unauthenticated requests will be redirected to the given address rather than
// the default behavior of returning an error response.
func WithRedirect(address string) AuthMiddlewareOption {
	return func(config *AuthMiddlewareConfig) {
		config.redirect = address
	}
}

// BypassRemediation prevents redirects or error responses for unauthenticated
// requests.
func BypassRemediation(config *AuthMiddlewareConfig) {
	config.bypassRemediation = true
}

// Authenticate is a Chi middleware that checks for authentication via either
// cookies or Bearer token in the Authorization header.
func Authenticate(
	appConf *config.AppConfig,
	options ...AuthMiddlewareOption,
) func(http.Handler) http.Handler {
	config := AuthMiddlewareConfig{}
	for _, optionFunc := range options {
		optionFunc(&config)
	}

	return func(next http.Handler) http.Handler {
		a := NewAuthenticator(appConf)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var isAuthenticated bool

			// First check for Authorization header (Bearer token)
			authHeader := r.Header.Get("Authorization")
			if config.useBearerToken && authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
				token := strings.TrimPrefix(authHeader, "Bearer ")
				isAuthenticated = a.isValidBearerToken(token)
			} else {
				// Fall back to cookie authentication
				cookie, err := r.Cookie("auth")
				if err == nil {
					isAuthenticated = a.isValidCookie(cookie)

					// Refresh the cookie if it's valid
					if isAuthenticated {
						a.SetCookie(w, cookie.Value)
					}
				}
			}

			if !isAuthenticated && !config.bypassRemediation {
				if config.redirect == "" {
					http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				} else {
					http.Redirect(w, r, config.redirect, http.StatusFound)
				}
				return
			}

			ctx := context.WithValue(r.Context(), authenticatedContextKey, isAuthenticated)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// IsAuthenticated retrieves the authentication status from the request context.
// When the BypassRemediation option is set in the Authenticate middleware, this
// function can be called from request handlers to determine whether a request
// is authenticated.
func IsAuthenticated(r *http.Request) bool {
	if isAuthenticated, ok := r.Context().Value(authenticatedContextKey).(bool); ok {
		return isAuthenticated
	}
	return false
}

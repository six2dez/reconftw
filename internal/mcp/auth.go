// Package mcp — Bearer auth HTTP middleware.
//
// BearerAuthMiddleware wraps a net/http.Handler and validates the
// "Authorization: Bearer <key>" header BEFORE the request reaches the
// MCP go-sdk layer. Auth MUST be at the net/http layer: the SDK's
// AddReceivingMiddleware operates post-HTTP-decode and cannot read raw
// HTTP headers (RESEARCH.md Pitfall 1).
//
// Security properties enforced here (T-08-02-01, T-08-02-02):
//   - Empty apiKey: all requests are rejected with 401 (safe default).
//   - Wrong/missing token: 401, no leak of the correct key.
//   - Constant-time comparison: subtle.ConstantTimeCompare prevents a
//     timing oracle that would let an attacker learn prefix bytes of the key.
package mcp

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// BearerAuthMiddleware returns an http.Handler that requires a valid
// "Authorization: Bearer <apiKey>" header on every request.
//
// Rejection cases (all return HTTP 401 Unauthorized):
//   - apiKey is empty (belt-and-suspenders; the server should refuse to
//     start if no key is configured, but the middleware enforces it too).
//   - Authorization header is absent or does not start with "Bearer ".
//   - Token after "Bearer " does not match apiKey (constant-time compare).
//
// On success the request is forwarded to next unchanged.
func BearerAuthMiddleware(apiKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// T-08-02-01: empty key → reject all requests (safe default).
		if len(apiKey) == 0 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(auth, "Bearer ")

		// T-08-02-02: constant-time comparison prevents timing oracle.
		if subtle.ConstantTimeCompare([]byte(token), []byte(apiKey)) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

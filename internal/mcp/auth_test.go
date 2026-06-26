package mcp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	mcp "github.com/six2dez/reconftw/internal/mcp"
)

func TestBearerAuthMiddleware(t *testing.T) {
	t.Parallel()

	const correctKey = "correctkey"

	// okHandler is a trivial next handler that records it was called.
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cases := []struct {
		name       string
		apiKey     string
		authHeader string
		wantStatus int
	}{
		{
			name:       "missing_authorization_header",
			apiKey:     correctKey,
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "non_bearer_scheme",
			apiKey:     correctKey,
			authHeader: "Token xyz",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong_bearer_key",
			apiKey:     correctKey,
			authHeader: "Bearer wrongkey",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "correct_bearer_key",
			apiKey:     correctKey,
			authHeader: "Bearer " + correctKey,
			wantStatus: http.StatusOK,
		},
		{
			name:       "empty_apikey_any_token",
			apiKey:     "",
			authHeader: "Bearer " + correctKey,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "empty_apikey_no_header",
			apiKey:     "",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "bearer_prefix_only_no_token",
			apiKey:     correctKey,
			authHeader: "Bearer ",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler := mcp.BearerAuthMiddleware(tc.apiKey, okHandler)

			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tc.wantStatus)
			}
		})
	}
}

package mcp_test

import (
	"errors"
	"testing"

	mcp "github.com/six2dez/reconftw/internal/mcp"
)

func TestSessionScope_Contains(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		scope    *mcp.SessionScope
		target   string
		wantIn   bool
	}{
		{
			name:   "nil_scope_returns_false",
			scope:  nil,
			target: "example.com",
			wantIn: false,
		},
		{
			name:   "empty_patterns_returns_false",
			scope:  mcp.NewSessionScope(nil),
			target: "example.com",
			wantIn: false,
		},
		{
			name:   "empty_slice_returns_false",
			scope:  mcp.NewSessionScope([]string{}),
			target: "example.com",
			wantIn: false,
		},
		{
			name:   "exact_match",
			scope:  mcp.NewSessionScope([]string{"example.com"}),
			target: "example.com",
			wantIn: true,
		},
		{
			name:   "wildcard_subdomain_match",
			scope:  mcp.NewSessionScope([]string{"*.example.com"}),
			target: "sub.example.com",
			wantIn: true,
		},
		{
			name:   "wildcard_apex_match",
			scope:  mcp.NewSessionScope([]string{"*.example.com"}),
			target: "example.com",
			wantIn: true,
		},
		{
			name:   "non_matching_domain",
			scope:  mcp.NewSessionScope([]string{"example.com"}),
			target: "evil.com",
			wantIn: false,
		},
		{
			name:   "substring_not_matching_anchored",
			scope:  mcp.NewSessionScope([]string{"*.example.com"}),
			target: "examplecom.evil.org",
			wantIn: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.scope.Contains(tc.target)
			if got != tc.wantIn {
				t.Errorf("Contains(%q) = %v, want %v", tc.target, got, tc.wantIn)
			}
		})
	}
}

func TestCheckScope(t *testing.T) {
	t.Parallel()

	// Helper: a registry with one session that has a scope set.
	newRegWithSession := func(id, target string) *mcp.SessionRegistry {
		reg := mcp.NewSessionRegistry()
		scope := mcp.NewSessionScope([]string{target})
		reg.Register(id, "/tmp", scope)
		return reg
	}

	t.Run("unknown_session_id_returns_ErrOutOfScope", func(t *testing.T) {
		t.Parallel()
		reg := mcp.NewSessionRegistry()
		err := mcp.CheckScope("ghost", "example.com", reg)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, mcp.ErrOutOfScope) {
			t.Errorf("errors.Is(err, ErrOutOfScope) = false, want true; err = %v", err)
		}
	})

	t.Run("nil_scope_returns_ErrOutOfScope", func(t *testing.T) {
		t.Parallel()
		reg := mcp.NewSessionRegistry()
		reg.Register("sess-1", "/tmp", nil) // nil scope
		err := mcp.CheckScope("sess-1", "example.com", reg)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, mcp.ErrOutOfScope) {
			t.Errorf("errors.Is(err, ErrOutOfScope) = false, want true; err = %v", err)
		}
	})

	t.Run("target_in_scope_returns_nil", func(t *testing.T) {
		t.Parallel()
		reg := newRegWithSession("sess-2", "example.com")
		err := mcp.CheckScope("sess-2", "example.com", reg)
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	})

	t.Run("target_not_in_scope_returns_ErrOutOfScope", func(t *testing.T) {
		t.Parallel()
		reg := newRegWithSession("sess-3", "example.com")
		err := mcp.CheckScope("sess-3", "evil.com", reg)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, mcp.ErrOutOfScope) {
			t.Errorf("errors.Is(err, ErrOutOfScope) = false, want true; err = %v", err)
		}
	})

	t.Run("wildcard_scope_subdomain_allowed", func(t *testing.T) {
		t.Parallel()
		reg := mcp.NewSessionRegistry()
		reg.Register("sess-4", "/tmp", mcp.NewSessionScope([]string{"*.example.com"}))
		err := mcp.CheckScope("sess-4", "api.example.com", reg)
		if err != nil {
			t.Errorf("expected nil error for in-scope subdomain, got %v", err)
		}
	})

	t.Run("wildcard_scope_out_of_scope_rejected", func(t *testing.T) {
		t.Parallel()
		reg := mcp.NewSessionRegistry()
		reg.Register("sess-5", "/tmp", mcp.NewSessionScope([]string{"*.example.com"}))
		err := mcp.CheckScope("sess-5", "other.com", reg)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, mcp.ErrOutOfScope) {
			t.Errorf("errors.Is(err, ErrOutOfScope) = false, want true; err = %v", err)
		}
	})
}

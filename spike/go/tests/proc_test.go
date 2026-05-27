// SPDX-License-Identifier: MIT
// Spike PoC — DO NOT EVOLVE INTO PRODUCTION
// Source: .planning/phases/01-language-adr-spike/01-02-PLAN.md Task 2
// Locked scope: spike/README.md §Scope
// Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §Pattern 1
package tests

import (
	"context"
	"testing"
	"time"

	"github.com/six2dez/reconftw/spike/go/internal/proc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProc_RunCaptures verifies that proc.Run streams stdout line-by-line through lineFn.
func TestProc_RunCaptures(t *testing.T) {
	var collected []string
	lineFn := func(b []byte) error {
		collected = append(collected, string(b))
		return nil
	}

	ctx := context.Background()
	err := proc.Run(ctx, "echo", []string{"hello"}, lineFn)
	require.NoError(t, err)
	require.Equal(t, []string{"hello"}, collected)
}

// TestProc_RunTimeout verifies that proc.Run returns within the expected time when
// context is cancelled. sleep 10 is cancelled after 1s; with WaitDelay=5s grace,
// the function should return within ~6s (1 + 5), certainly within 10s.
func TestProc_RunTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	start := time.Now()
	// sleep 10 will be killed by ctx cancellation
	err := proc.Run(ctx, "sleep", []string{"10"}, nil)
	elapsed := time.Since(start)

	// We expect an error (context cancelled or killed)
	assert.Error(t, err)
	// The function must return within 10s (1s ctx + 5s WaitDelay + buffer)
	assert.Less(t, elapsed, 10*time.Second, "proc.Run should return within 10s after context cancel")
}

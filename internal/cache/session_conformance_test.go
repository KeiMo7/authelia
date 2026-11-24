// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/session"
	"github.com/authelia/authelia/v4/internal/session/sessiontest"
)

func TestMemorySessionConformance(t *testing.T) {
	memory := NewMemory()

	sessiontest.RunSuite(t, sessiontest.Harness{
		Name:       "cache-memory-in-process-fake",
		Repository: session.NewRepository(memory),
		Expiration: func(t *testing.T, issuer, id string) time.Time {
			t.Helper()

			memory.mu.RLock()
			defer memory.mu.RUnlock()

			item, ok := memory.session[memory.key(issuer, id)]
			if !ok {
				return time.Time{}
			}

			return item.expires
		},
	})

	require.NoError(t, memory.StartupCheck())
}

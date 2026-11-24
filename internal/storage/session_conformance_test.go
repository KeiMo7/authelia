// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/session/sessiontest"
)

func TestSQLiteSessionConformance(t *testing.T) {
	ctx, provider := newTestSessionProvider(t)

	sessiontest.RunSuite(t, sessiontest.Harness{
		Name:       "relational-sqlite-file",
		Repository: NewSessionRepository(provider),
		Expiration: func(t *testing.T, issuer, id string) time.Time {
			t.Helper()

			var row struct {
				Expiration time.Time `db:"expiration"`
			}

			require.NoError(t, provider.db.GetContext(ctx, &row, provider.db.Rebind(`SELECT expiration FROM session WHERE issuer = ? AND signature = ?`), issuer, id))

			return row.Expiration
		},
	})
}

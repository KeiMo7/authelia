// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package sessiontest

import "testing"

func TestMapRepositoryConformance(t *testing.T) {
	repo := NewMapRepository()

	RunSuite(t, Harness{
		Name:       "process-map",
		Repository: repo,
		Expiration: repo.Expiration,
	})
}

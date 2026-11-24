// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

func TestValidateSessionKeyGenerations(t *testing.T) {
	testCases := []struct {
		name        string
		session     schema.Session
		expected    []string
		primaryID   string
		secretValue string
	}{
		{
			name:    "LegacySingleSecretRemainsValid",
			session: schema.Session{Secret: testJWTSecret},
		},
		{
			name: "ValidMultipleGenerations",
			session: schema.Session{
				PrimaryKeyID: "g2",
				EncryptionKeys: []schema.SessionEncryptionKey{
					{ID: "g1", Secret: "old-secret-value"},
					{ID: "g2", Secret: "new-secret-value", Primary: true},
				},
			},
			primaryID:   "g2",
			secretValue: "new-secret-value",
		},
		{
			name: "EmptySetWithPrimaryID",
			session: schema.Session{
				PrimaryKeyID:   "g1",
				EncryptionKeys: []schema.SessionEncryptionKey{},
			},
			expected: []string{
				"session: option 'encryption_keys' must contain at least one generation when multi-generation session encryption is configured",
			},
		},
		{
			name: "DuplicateIdentifiers",
			session: schema.Session{
				EncryptionKeys: []schema.SessionEncryptionKey{
					{ID: "g1", Secret: "one", Primary: true},
					{ID: "g1", Secret: "two"},
				},
			},
			expected: []string{
				"session: option 'encryption_keys' contains duplicate id 'g1' at index 1",
			},
		},
		{
			name: "PrimaryIDNotInSet",
			session: schema.Session{
				PrimaryKeyID: "missing",
				EncryptionKeys: []schema.SessionEncryptionKey{
					{ID: "g1", Secret: "one"},
				},
			},
			expected: []string{
				"session: option 'primary_key_id' must identify one of the configured generation ids",
			},
		},
		{
			name: "RetiredPrimary",
			session: schema.Session{
				EncryptionKeys: []schema.SessionEncryptionKey{
					{ID: "g1", Secret: "one", Primary: true, Retired: true},
				},
			},
			expected: []string{
				"session: primary generation 'g1' can't be marked as retired",
			},
		},
		{
			name: "MissingIDAndSecret",
			session: schema.Session{
				EncryptionKeys: []schema.SessionEncryptionKey{{}},
			},
			expected: []string{
				"session: option 'encryption_keys[0].id' is required",
				"session: option 'encryption_keys[0].secret' is required",
				"session: option 'primary_key_id' must identify one of the configured generation ids",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := schema.NewStructValidator()
			config := &schema.Configuration{Session: tc.session}

			validateSessionKeyGenerations(config, validator)

			errs := validator.Errors()
			require.Len(t, errs, len(tc.expected))

			for i, expected := range tc.expected {
				assert.EqualError(t, errs[i], expected)
			}

			if tc.primaryID != "" {
				assert.Equal(t, tc.primaryID, config.Session.PrimaryKeyID)
			}

			if tc.secretValue != "" {
				assert.Equal(t, tc.secretValue, config.Session.Secret)
			}
		})
	}
}

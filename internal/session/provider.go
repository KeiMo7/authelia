// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"errors"

	"github.com/authelia/authelia/v4/internal/clock"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/random"
)

// NewProvider returns a new Provider with a Strategy for every configured session cookie domain, each sharing the
// Codec derived from the session secret and HMAC key.
func NewProvider(config *schema.Configuration, hmac []byte, clock clock.Provider, random random.Provider, repository Repository) (provider Provider, err error) {
	var (
		codec       Codec
		ring        *KeyRing
		coordinator *RingCoordinator
	)

	if len(config.Session.EncryptionKeys) == 0 {
		switch {
		case config.Session.Encryption != nil:
			config.Session.EncryptionKeys = append(config.Session.Encryption.Keys, config.Session.Encryption.Generations...)

			if config.Session.PrimaryKeyID == "" {
				config.Session.PrimaryKeyID = firstNonEmptyGenerationID(config.Session.Encryption.PrimaryKeyID, config.Session.Encryption.Primary)
			}
		case config.Session.KeyRing != nil:
			config.Session.EncryptionKeys = append(config.Session.KeyRing.Keys, config.Session.KeyRing.Generations...)

			if config.Session.PrimaryKeyID == "" {
				config.Session.PrimaryKeyID = firstNonEmptyGenerationID(config.Session.KeyRing.PrimaryKeyID, config.Session.KeyRing.Primary)
			}
		case len(config.Session.KeyGenerations) != 0:
			config.Session.EncryptionKeys = config.Session.KeyGenerations
		case len(config.Session.Keys) != 0:
			config.Session.EncryptionKeys = config.Session.Keys
		}
	}

	if len(config.Session.EncryptionKeys) > 0 {
		generations := make([]KeyGenerationConfig, 0, len(config.Session.EncryptionKeys))

		primaryID := config.Session.PrimaryKeyID
		primarySeen := false

		for _, key := range config.Session.EncryptionKeys {
			key.Normalize()

			primary := key.Primary || (primaryID != "" && key.ID == primaryID)
			if primary {
				primarySeen = true
			}

			generations = append(generations, KeyGenerationConfig{
				ID:      key.ID,
				Secret:  key.Secret,
				Primary: primary,
				Retired: key.Retired,
			})
		}

		if primaryID != "" && !primarySeen {
			return nil, ErrKeyGenerationUnavailable
		}

		if ring, err = NewKeyRing(generations...); err != nil {
			return nil, err
		}

		if codec, err = NewCodecWithKeyRing(ring, hmac, random); err != nil {
			return nil, err
		}

		coordinator = NewRingCoordinator(ring, NewRepositoryRingStateStore(repository), DefaultKeyRingSyncInterval)
	} else if codec, err = NewCodec(config.Session.Secret, hmac, random); err != nil {
		return nil, err
	}

	strategies := make(map[string]Strategy, len(config.Session.Cookies))

	for _, cookie := range config.Session.Cookies {
		strategy := NewStrategy(cookie, clock, codec, repository)

		if coordinator != nil {
			if definable, ok := strategy.(*DefaultStrategy); ok {
				definable.ringCoordinator = coordinator
			}
		}

		strategies[cookie.Domain] = strategy
	}

	return &DefaultProvider{strategies: strategies, ring: ring, coordinator: coordinator}, nil
}

// DefaultProvider is the default Provider which resolves a Strategy from the cookie domain of a request.
type DefaultProvider struct {
	strategies map[string]Strategy

	ring        *KeyRing
	coordinator *RingCoordinator
}

// KeyRing returns the configured generation ring when multi-generation encryption is enabled.
func (d *DefaultProvider) KeyRing() *KeyRing { return d.ring }

// RingCoordinator returns the shared-state propagation coordinator when multi-generation encryption is enabled.
func (d *DefaultProvider) RingCoordinator() *RingCoordinator { return d.coordinator }

// PromoteGeneration promotes an already configured key generation and propagates the secret-free state.
func (d *DefaultProvider) PromoteGeneration(ctx context.Context, id string) (err error) {
	if d.coordinator == nil {
		return ErrKeyGenerationUnavailable
	}

	return d.coordinator.Promote(ctx, id)
}

// RetireGeneration retires a non-primary key generation and propagates the secret-free state.
func (d *DefaultProvider) RetireGeneration(ctx context.Context, id string) (err error) {
	if d.coordinator == nil {
		return ErrKeyGenerationUnavailable
	}

	return d.coordinator.Retire(ctx, id)
}

// StartupCheck implements the Provider interface.
func (d DefaultProvider) StartupCheck() (err error) {
	return nil
}

// GetStrategy returns the Strategy configured for the given cookie domain, returning an error when the domain has no
// configured session cookie.
func (d DefaultProvider) GetStrategy(domain string) (strategy Strategy, err error) {
	var ok bool

	if strategy, ok = d.strategies[domain]; ok {
		return strategy, nil
	}

	return nil, errors.New("not found")
}

var (
	_ Provider = (*DefaultProvider)(nil)
)

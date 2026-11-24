// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

const (
	keyRingStateIssuer = "authelia:session-keyring"
	keyRingStateID     = "primary-state"
	keyRingStatePID    = "session-keyring-state"

	// DefaultKeyRingSyncInterval bounds how long a generation promotion or retirement takes to reach another instance.
	DefaultKeyRingSyncInterval = 5 * time.Second
)

// RingStateStore stores the secret-free lifecycle state of a KeyRing in a shared backend.
type RingStateStore interface {
	LoadRingState(ctx context.Context) (snapshot RingSnapshot, found bool, err error)
	SaveRingState(ctx context.Context, snapshot RingSnapshot) (err error)
}

// RepositoryRingStateStore persists KeyRing state through the existing session Repository. It reuses the three
// supported backend families without adding a component or a database migration. The stored document contains only
// generation identifiers, lifecycle states, and a monotonic revision.
type RepositoryRingStateStore struct {
	repository Repository
	issuer     string
}

// NewRepositoryRingStateStore returns a RingStateStore backed by the given session Repository.
func NewRepositoryRingStateStore(repository Repository) *RepositoryRingStateStore {
	return &RepositoryRingStateStore{repository: repository, issuer: keyRingStateIssuer}
}

// LoadRingState implements RingStateStore.
func (s *RepositoryRingStateStore) LoadRingState(ctx context.Context) (snapshot RingSnapshot, found bool, err error) {
	record, err := s.repository.Get(ctx, s.issuer, keyRingStateID)
	if err != nil {
		return RingSnapshot{}, false, err
	}

	if record == nil || len(record.GetSessionData()) == 0 {
		return RingSnapshot{}, false, nil
	}

	if err = json.Unmarshal(record.GetSessionData(), &snapshot); err != nil {
		return RingSnapshot{}, true, err
	}

	return snapshot, true, nil
}

// SaveRingState implements RingStateStore.
func (s *RepositoryRingStateStore) SaveRingState(ctx context.Context, snapshot RingSnapshot) (err error) {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}

	return s.repository.Save(ctx, s.issuer, keyRingStateID, keyRingStatePID, "", 0, data)
}

// RingCoordinator applies local promotion/retirement changes, publishes secret-free state, and polls shared state so
// other instances converge without a restart.
type RingCoordinator struct {
	ring  *KeyRing
	store RingStateStore

	interval time.Duration

	syncMu   sync.Mutex
	lastSync time.Time
}

// NewRingCoordinator returns a coordinator for the given ring and shared state store.
func NewRingCoordinator(ring *KeyRing, store RingStateStore, interval time.Duration) *RingCoordinator {
	if interval <= 0 {
		interval = DefaultKeyRingSyncInterval
	}

	return &RingCoordinator{ring: ring, store: store, interval: interval}
}

// SyncIfDue performs at most one shared-state synchronization per configured interval. Request paths use it to make
// generation promotion/retirement visible to other instances within a bounded delay without running a separate service.
func (c *RingCoordinator) SyncIfDue(ctx context.Context) (changed bool, err error) {
	if c == nil || c.store == nil {
		return false, nil
	}

	c.syncMu.Lock()
	defer c.syncMu.Unlock()

	if !c.lastSync.IsZero() && time.Since(c.lastSync) < c.interval {
		return false, nil
	}

	changed, err = c.Sync(ctx)
	c.lastSync = time.Now()

	return changed, err
}

// Promote changes the primary generation locally and publishes the resulting state.
func (c *RingCoordinator) Promote(ctx context.Context, id string) (err error) {
	if err = c.ring.SetPrimary(id); err != nil {
		return err
	}

	return c.publish(ctx)
}

// Retire retires a non-primary generation locally and publishes the resulting state.
func (c *RingCoordinator) Retire(ctx context.Context, id string) (err error) {
	if err = c.ring.Retire(id); err != nil {
		return err
	}

	return c.publish(ctx)
}

func (c *RingCoordinator) publish(ctx context.Context) (err error) {
	if c.store == nil {
		return nil
	}

	return c.store.SaveRingState(ctx, c.ring.Snapshot())
}

// Sync loads shared state and applies it when its revision is newer than the local revision. A missing shared document
// is initialized from this instance, which makes first rollout deterministic.
func (c *RingCoordinator) Sync(ctx context.Context) (changed bool, err error) {
	if c.store == nil {
		return false, nil
	}

	snapshot, found, err := c.store.LoadRingState(ctx)
	if err != nil {
		return false, err
	}

	if !found {
		if err = c.store.SaveRingState(ctx, c.ring.Snapshot()); err != nil {
			return false, err
		}

		return false, nil
	}

	if snapshot.Revision <= c.ring.Revision() && snapshot.Primary == c.ring.PrimaryID() {
		return false, nil
	}

	if err = c.ring.ApplyState(snapshot); err != nil {
		return false, err
	}

	return true, nil
}

// Run periodically synchronizes state until ctx is done. Tests and callers which need deterministic convergence can call
// Sync directly instead of waiting for the ticker.
func (c *RingCoordinator) Run(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = c.Sync(ctx)
		}
	}
}

// SyncWithRetry calls Sync until it reports changed or the context expires. It is primarily useful in tests and bounded
// startup convergence; ordinary request paths should not block on it.
func (c *RingCoordinator) SyncWithRetry(ctx context.Context, delay time.Duration) (err error) {
	if delay <= 0 {
		delay = time.Millisecond
	}

	ticker := time.NewTicker(delay)
	defer ticker.Stop()

	for {
		changed, syncErr := c.Sync(ctx)
		if syncErr == nil && changed {
			return nil
		}

		if syncErr != nil && !errors.Is(syncErr, ErrKeyGenerationUnavailable) {
			return syncErr
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

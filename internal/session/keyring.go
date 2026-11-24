// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// Compatibility aliases for callers and tests which use "generation" or "key ring" terminology.
type (
	Generation        = KeyGenerationConfig
	KeyGeneration     = KeyGenerationConfig
	GenerationRing    = KeyRing
	KeyGenerationRing = KeyRing
)

// NewGenerationRing is an alias for NewKeyRing.
var NewGenerationRing = NewKeyRing

// NewKeyGenerationRing is an alias for NewKeyRing.
var NewKeyGenerationRing = NewKeyRing

// Stable reason codes returned by session read and repair operations. They are safe to log and use as metric labels
// because they never contain key material, plaintext sessions, or the backend's decryption error text.
const (
	ReadReasonBackendUnavailable = "backend_unavailable"
	ReadReasonKeyUnavailable     = "key_generation_unavailable"
	ReadReasonGenerationRetired  = "key_generation_retired"
	ReadReasonRecordUnopenable   = "record_unopenable"
	ReadReasonSignatureMismatch  = "signature_mismatch"
	ReadReasonDomainMismatch     = "domain_mismatch"
	RepairReasonResealSucceeded  = "reseal_succeeded"
	RepairReasonResealFailed     = "reseal_failed"
	RepairReasonCleanupSucceeded = "cleanup_succeeded"
	RepairReasonCleanupFailed    = "cleanup_failed"
)

// Key generation lifecycle states.
const (
	KeyGenerationStatePrimary  = "primary"
	KeyGenerationStateReadOnly = "read_only"
	KeyGenerationStateRetired  = "retired"
)

// Sentinel errors classify session read failures without wrapping cryptographic or backend error detail that may be
// unsafe or unstable.
var (
	ErrKeyGenerationUnavailable = errors.New("session key generation is not configured")
	ErrKeyUnavailable           = ErrKeyGenerationUnavailable

	ErrKeyGenerationRetired = errors.New("session key generation is retired")
	ErrGenerationRetired    = ErrKeyGenerationRetired

	ErrSessionOpen       = errors.New("session record could not be opened")
	ErrSessionDecrypt    = ErrSessionOpen
	ErrRecordUnopenable  = ErrSessionOpen
	ErrSessionUnopenable = ErrSessionOpen

	ErrKeyRingConfiguration = errors.New("invalid session key generation configuration")
)

// ReadError is the classified form of a session read failure. Its ordinary Error text preserves contextual diagnostics
// for compatibility; logging and client-facing code should use ReasonForError and GenerationForError instead of logging
// the complete error chain, because the chain may contain a backend or cryptographic cause.
type ReadError struct {
	// Reason is one of the stable ReadReason* constants.
	Reason string

	// Generation is the non-secret generation identifier recorded by the envelope, when known.
	Generation string

	// Err is the wrapped cause or stable sentinel underlying the failure.
	Err error
}

func (e *ReadError) Error() string {
	if e == nil {
		return ""
	}

	if e.Err != nil {
		return e.Err.Error()
	}

	if e.Generation == "" {
		return "session read failed: reason=" + e.Reason
	}

	return "session read failed: reason=" + e.Reason + " generation=" + e.Generation
}

func (e *ReadError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.Err
}

// Is allows stable failure sentinels to classify errors even when Err contains additional legacy context.
func (e *ReadError) Is(target error) bool {
	if e == nil {
		return false
	}

	switch target {
	case ErrKeyGenerationUnavailable, ErrKeyUnavailable:
		return e.Reason == ReadReasonKeyUnavailable
	case ErrKeyGenerationRetired, ErrGenerationRetired:
		return e.Reason == ReadReasonGenerationRetired
	case ErrSessionOpen, ErrSessionDecrypt, ErrRecordUnopenable, ErrSessionUnopenable:
		return e.Reason == ReadReasonRecordUnopenable
	}

	return false
}

// KeyGenerationConfig configures one generation of the session data encryption key.
type KeyGenerationConfig struct {
	// ID is the stable, non-secret generation identifier written into the backend record envelope.
	ID string

	// Generation is an alias for ID used by configuration surfaces which prefer that terminology.
	Generation string

	// Secret is the raw key material. It is never exposed by String, Error, logs, or snapshots.
	Secret string

	// Key is an alias for Secret.
	Key string

	// State optionally declares the generation lifecycle. When empty, Primary/Retired and ring construction supply it.
	State string

	// Primary marks the sole generation used for new seals.
	Primary bool

	// Active is an alias for Primary.
	Active bool

	// Retired denies reads and causes records of this generation to be treated as absent and cleaned up.
	Retired bool

	// Disabled is an alias for Retired.
	Disabled bool

	// ReadOnly explicitly marks a non-primary generation which remains readable and eligible for read-time resealing.
	ReadOnly bool
}

func (c *KeyGenerationConfig) normalize() {
	if c.ID == "" && c.Generation != "" {
		c.ID = c.Generation
	}

	if c.Secret == "" && c.Key != "" {
		c.Secret = c.Key
	}

	if c.Primary == false && c.Active {
		c.Primary = true
	}

	if !c.Retired && c.Disabled {
		c.Retired = true
	}

	switch c.State {
	case KeyGenerationStatePrimary:
		c.Primary = true
		c.Retired = false
	case KeyGenerationStateRetired:
		c.Retired = true
		c.Primary = false
	case KeyGenerationStateReadOnly:
		if !c.Primary {
			c.Retired = false
		}
	}
}

// GenerationSnapshot is the secret-free state of a KeyRing suitable for propagation to other instances.
type GenerationSnapshot struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

// RingSnapshot is the secret-free primary and generation lifecycle state.
type RingSnapshot struct {
	Primary     string               `json:"primary"`
	Generations []GenerationSnapshot `json:"generations"`
	Revision    uint64               `json:"revision"`
}

type keyGeneration struct {
	id    string
	key   []byte
	state string
}

// KeyRing is a concurrency-safe collection of session encryption key generations. Exactly one generation is primary
// and used for writes; other non-retired generations are readable.
type KeyRing struct {
	mu sync.RWMutex

	primary  string
	byID     map[string]*keyGeneration
	order    []string
	revision atomic.Uint64
}

// NewKeyRing creates a KeyRing from generation configurations. Exactly one non-retired generation must be marked
// primary. IDs must be unique and non-empty, and every generation must contain key material.
func NewKeyRing(configs ...KeyGenerationConfig) (ring *KeyRing, err error) {
	ring = &KeyRing{byID: make(map[string]*keyGeneration, len(configs))}

	if len(configs) == 0 {
		return nil, fmt.Errorf("%w: generation set is empty", ErrKeyRingConfiguration)
	}

	primaryCount := 0

	for i := range configs {
		cfg := configs[i]
		cfg.normalize()

		if cfg.ID == "" {
			return nil, fmt.Errorf("%w: generations[%d].id is required", ErrKeyRingConfiguration, i)
		}

		if len(cfg.ID) > 255 {
			return nil, fmt.Errorf("%w: generations[%d].id must be at most 255 bytes", ErrKeyRingConfiguration, i)
		}

		if _, exists := ring.byID[cfg.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate generation id %q at generations[%d].id", ErrKeyRingConfiguration, cfg.ID, i)
		}

		if cfg.Secret == "" {
			return nil, fmt.Errorf("%w: generations[%d].secret is required", ErrKeyRingConfiguration, i)
		}

		key, derr := deriveGenerationKey(cfg.Secret)
		if derr != nil {
			return nil, fmt.Errorf("%w: generations[%d].secret could not be derived: %v", ErrKeyRingConfiguration, i, derr)
		}

		state := cfg.State
		if state == "" {
			switch {
			case cfg.Retired:
				state = KeyGenerationStateRetired
			case cfg.Primary:
				state = KeyGenerationStatePrimary
			default:
				state = KeyGenerationStateReadOnly
			}
		}

		switch state {
		case KeyGenerationStatePrimary:
			if cfg.Retired {
				return nil, fmt.Errorf("%w: generation %q cannot be both primary and retired", ErrKeyRingConfiguration, cfg.ID)
			}

			primaryCount++
			ring.primary = cfg.ID
		case KeyGenerationStateReadOnly, KeyGenerationStateRetired:
			if cfg.Primary {
				return nil, fmt.Errorf("%w: retired generation %q cannot be primary", ErrKeyRingConfiguration, cfg.ID)
			}
		default:
			return nil, fmt.Errorf("%w: generation %q has unsupported state %q", ErrKeyRingConfiguration, cfg.ID, state)
		}

		ring.byID[cfg.ID] = &keyGeneration{id: cfg.ID, key: key, state: state}
		ring.order = append(ring.order, cfg.ID)
	}

	switch {
	case primaryCount == 0:
		return nil, fmt.Errorf("%w: no primary generation is configured", ErrKeyRingConfiguration)
	case primaryCount > 1:
		return nil, fmt.Errorf("%w: %d primary generations are configured; exactly one is required", ErrKeyRingConfiguration, primaryCount)
	}

	ring.revision.Store(1)

	return ring, nil
}

// NewLegacyKeyRing returns the single-generation ring equivalent to the historical one-key codec. Its generation ID is
// empty and records are not envelope-wrapped, preserving the old byte format.
func NewLegacyKeyRing(rawSecret string) (ring *KeyRing, err error) {
	key, err := deriveGenerationKey(rawSecret)
	if err != nil {
		return nil, err
	}

	ring = &KeyRing{byID: map[string]*keyGeneration{}}
	ring.byID[""] = &keyGeneration{id: "", key: key, state: KeyGenerationStatePrimary}
	ring.order = []string{""}
	ring.primary = ""
	ring.revision.Store(1)

	return ring, nil
}

// PrimaryID returns the generation used for new seals.
func (r *KeyRing) PrimaryID() string {
	if r == nil {
		return ""
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.primary
}

// Revision returns the current state revision. The value increases after every local change or applied remote state.
func (r *KeyRing) Revision() uint64 {
	if r == nil {
		return 0
	}

	return r.revision.Load()
}

func (r *KeyRing) generation(id string) (generation *keyGeneration, ok bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	generation, ok = r.byID[id]

	return generation, ok
}

func (r *KeyRing) primaryGeneration() (generation *keyGeneration, ok bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	generation, ok = r.byID[r.primary]

	return generation, ok
}

// ReadableIDs returns the non-retired generation IDs, primary first.
func (r *KeyRing) ReadableIDs() []string {
	if r == nil {
		return nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.order))

	if r.primary != "" {
		if g, ok := r.byID[r.primary]; ok && g.state != KeyGenerationStateRetired {
			ids = append(ids, r.primary)
		}
	}

	for _, id := range r.order {
		if id == r.primary {
			continue
		}

		if g, ok := r.byID[id]; ok && g.state != KeyGenerationStateRetired {
			ids = append(ids, id)
		}
	}

	return ids
}

// Rotate installs a new primary generation. The previous primary becomes readable. The new ID must not already exist.
func (r *KeyRing) Rotate(cfg KeyGenerationConfig) (err error) {
	cfg.normalize()
	cfg.Primary, cfg.Active, cfg.Retired, cfg.Disabled = true, true, false, false
	cfg.State = KeyGenerationStatePrimary

	if cfg.ID == "" {
		return fmt.Errorf("%w: rotated generation id is required", ErrKeyRingConfiguration)
	}

	key, err := deriveGenerationKey(cfg.Secret)
	if err != nil {
		return fmt.Errorf("%w: rotated generation %q could not be derived", ErrKeyRingConfiguration, cfg.ID)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.byID[cfg.ID]; exists {
		return fmt.Errorf("%w: duplicate generation id %q", ErrKeyRingConfiguration, cfg.ID)
	}

	if current, ok := r.byID[r.primary]; ok {
		current.state = KeyGenerationStateReadOnly
	}

	r.byID[cfg.ID] = &keyGeneration{id: cfg.ID, key: key, state: KeyGenerationStatePrimary}
	r.order = append(r.order, cfg.ID)
	r.primary = cfg.ID
	r.revision.Add(1)

	return nil
}

// SetPrimary promotes an already configured generation. The old primary becomes read-only.
func (r *KeyRing) SetPrimary(id string) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	g, ok := r.byID[id]
	if !ok {
		return fmt.Errorf("%w: %q", ErrKeyGenerationUnavailable, id)
	}

	if g.state == KeyGenerationStateRetired {
		return fmt.Errorf("%w: %q", ErrKeyGenerationRetired, id)
	}

	if current, ok := r.byID[r.primary]; ok && current.id != id {
		current.state = KeyGenerationStateReadOnly
	}

	g.state = KeyGenerationStatePrimary
	r.primary = id
	r.revision.Add(1)

	return nil
}

// Retire marks an existing non-primary generation unreadable. Retiring the primary is rejected; promote another
// generation first.
func (r *KeyRing) Retire(id string) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	g, ok := r.byID[id]
	if !ok {
		return fmt.Errorf("%w: %q", ErrKeyGenerationUnavailable, id)
	}

	if id == r.primary || g.state == KeyGenerationStatePrimary {
		return fmt.Errorf("%w: generation %q is primary and cannot be retired", ErrKeyRingConfiguration, id)
	}

	g.state = KeyGenerationStateRetired
	r.revision.Add(1)

	return nil
}

// Snapshot returns secret-free lifecycle state suitable for transport between instances.
func (r *KeyRing) Snapshot() (snapshot RingSnapshot) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	snapshot = RingSnapshot{Primary: r.primary, Revision: r.revision.Load(), Generations: make([]GenerationSnapshot, 0, len(r.order))}

	for _, id := range r.order {
		if g, ok := r.byID[id]; ok {
			snapshot.Generations = append(snapshot.Generations, GenerationSnapshot{ID: g.id, State: g.state})
		}
	}

	return snapshot
}

// ApplyState applies secret-free lifecycle state previously produced by Snapshot. Every referenced generation must
// already have key material configured locally. It does not install or transport key material.
func (r *KeyRing) ApplyState(snapshot RingSnapshot) (err error) {
	if snapshot.Primary == "" {
		return fmt.Errorf("%w: propagated state has no primary", ErrKeyRingConfiguration)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.byID[snapshot.Primary]; !ok {
		return fmt.Errorf("%w: primary %q is not configured on this instance", ErrKeyGenerationUnavailable, snapshot.Primary)
	}

	updates := make(map[string]string, len(snapshot.Generations))

	for _, g := range snapshot.Generations {
		if g.ID == "" {
			return fmt.Errorf("%w: propagated state contains an empty generation id", ErrKeyRingConfiguration)
		}

		if _, ok := r.byID[g.ID]; !ok {
			return fmt.Errorf("%w: generation %q is not configured on this instance", ErrKeyGenerationUnavailable, g.ID)
		}

		switch g.State {
		case KeyGenerationStatePrimary, KeyGenerationStateReadOnly, KeyGenerationStateRetired:
			updates[g.ID] = g.State
		default:
			return fmt.Errorf("%w: generation %q has unsupported state %q", ErrKeyRingConfiguration, g.ID, g.State)
		}
	}

	if state := updates[snapshot.Primary]; state != KeyGenerationStatePrimary {
		return fmt.Errorf("%w: primary %q has state %q", ErrKeyRingConfiguration, snapshot.Primary, state)
	}

	for id, state := range updates {
		r.byID[id].state = state
	}

	r.primary = snapshot.Primary

	if snapshot.Revision > r.revision.Load() {
		r.revision.Store(snapshot.Revision)
	} else {
		r.revision.Add(1)
	}

	return nil
}

func deriveGenerationKey(rawSecret string) (key []byte, err error) {
	return hkdf.Key(sha256.New, []byte(rawSecret), nil, hkdfKeyInfoCodec, 32)
}

func firstNonEmptyGenerationID(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}

// sessionEnvelopeMagic prefixes envelope-wrapped ciphertext. It is intentionally printable so operators and tests can
// distinguish self-describing records from legacy nonce-prefixed AES-GCM ciphertext.
var sessionEnvelopeMagic = []byte("authelia-session-generation:v1\n")

const envelopeIDLengthBytes = 2

func sealEnvelope(generation string, ciphertext []byte) (data []byte, err error) {
	id := []byte(generation)

	if len(id) > 65535 {
		return nil, fmt.Errorf("%w: generation id is too long", ErrKeyRingConfiguration)
	}

	data = make([]byte, len(sessionEnvelopeMagic)+envelopeIDLengthBytes+len(id)+len(ciphertext))

	n := copy(data, sessionEnvelopeMagic)
	binary.BigEndian.PutUint16(data[n:n+envelopeIDLengthBytes], uint16(len(id)))
	n += envelopeIDLengthBytes
	n += copy(data[n:], id)
	copy(data[n:], ciphertext)

	return data, nil
}

func openEnvelope(data []byte) (generation string, ciphertext []byte, wrapped bool, err error) {
	if len(data) < len(sessionEnvelopeMagic)+envelopeIDLengthBytes || string(data[:len(sessionEnvelopeMagic)]) != string(sessionEnvelopeMagic) {
		return "", data, false, nil
	}

	pos := len(sessionEnvelopeMagic)
	idLen := int(binary.BigEndian.Uint16(data[pos : pos+envelopeIDLengthBytes]))
	pos += envelopeIDLengthBytes

	if len(data) < pos+idLen {
		return "", nil, true, ErrRecordUnopenable
	}

	generation = string(data[pos : pos+idLen])
	pos += idLen

	return generation, data[pos:], true, nil
}

// ReasonForError returns the stable session read reason for an error. Unknown errors return an empty string.
func ReasonForError(err error) string {
	var readErr *ReadError

	if errors.As(err, &readErr) {
		return readErr.Reason
	}

	switch {
	case errors.Is(err, ErrRepositoryGet):
		return ReadReasonBackendUnavailable
	case errors.Is(err, ErrKeyGenerationUnavailable):
		return ReadReasonKeyUnavailable
	case errors.Is(err, ErrKeyGenerationRetired):
		return ReadReasonGenerationRetired
	case errors.Is(err, ErrSessionOpen):
		return ReadReasonRecordUnopenable
	}

	return ""
}

// SafeError returns an error value suitable for logs and error metrics. Cryptographic failure detail is replaced by
// the stable sentinel; safe configuration/binding diagnostics are returned unchanged.
func SafeError(err error) error {
	if err == nil {
		return nil
	}

	var readErr *ReadError
	if errors.As(err, &readErr) && readErr.Reason == ReadReasonRecordUnopenable {
		return ErrSessionOpen
	}

	return err
}

// GenerationForError returns the non-secret generation associated with a classified read error, when known.
func GenerationForError(err error) string {
	var readErr *ReadError
	if errors.As(err, &readErr) {
		return readErr.Generation
	}

	return ""
}

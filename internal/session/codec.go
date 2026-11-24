// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/authelia/authelia/v4/internal/random"
	"github.com/authelia/authelia/v4/internal/utils"
)

// NewCodec returns a new SecureCodec.
func NewCodec(rawKey string, hmacKey []byte, random random.Provider) (codec Codec, err error) {
	var key []byte

	if key, err = hkdf.Key(sha256.New, []byte(rawKey), nil, hkdfKeyInfoCodec, 32); err != nil {
		return nil, err
	}

	return &SecureCodec{
		encKey:  key,
		hmacKey: hmacKey,
		random:  random,
	}, nil
}

// NewCodecWithKeyRing returns a SecureCodec which writes using the ring's primary generation and can open records
// sealed by any readable generation.
func NewCodecWithKeyRing(ring *KeyRing, hmacKey []byte, random random.Provider) (codec *SecureCodec, err error) {
	primary, ok := ring.primaryGeneration()
	if !ok {
		return nil, ErrKeyGenerationUnavailable
	}

	return &SecureCodec{
		encKey:  primary.key,
		hmacKey: hmacKey,
		random:  random,
		keys:    ring,
	}, nil
}

// SecureCodec is the default Codec which signs session identifiers with a HMAC key and seals session data with an
// authenticated encryption key derived from the session secret.
type SecureCodec struct {
	encKey  []byte
	hmacKey []byte

	random random.Provider

	keys *KeyRing
}

// GeneratePublicID returns a new random public identifier for a session. The public identifier is the value shared
// with consumers which need to reference a session without being able to derive its signature.
func (c *SecureCodec) GeneratePublicID() (id string, err error) {
	var pid uuid.UUID

	if pid, err = uuid.NewV7(); err != nil {
		return "", err
	}

	return pid.String(), nil
}

// GenerateSessionID returns a new random session identifier which is the raw value encoded into the session cookie.
func (c *SecureCodec) GenerateSessionID() (id []byte, err error) {
	id = make([]byte, sessionIDLength)

	if _, err = c.random.Read(id); err != nil {
		return nil, err
	}

	return id, nil
}

// Verify returns true if the given signature is the signature of the given data, comparing them in constant time.
func (c *SecureCodec) Verify(data []byte, signature string) bool {
	actual, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}

	expected := c.sign(data)

	return hmac.Equal(expected, actual)
}

// Sign returns the hex encoded HMAC signature of the given data.
func (c *SecureCodec) Sign(data []byte) string {
	return hex.EncodeToString(c.sign(data))
}

func (c *SecureCodec) sign(data []byte) []byte {
	mac := hmac.New(sha256.New, c.hmacKey)
	mac.Write(data)

	return mac.Sum(nil)
}

// PrimaryGeneration returns the generation used for new seals. The historical single-key codec returns an empty
// identifier and writes the legacy unwrapped format.
func (c *SecureCodec) PrimaryGeneration() (generation string) {
	if c.keys == nil {
		return ""
	}

	return c.keys.PrimaryID()
}

// Seal marshals and encrypts the given UserSession, binding the ciphertext to the domain and session identifier so it
// cannot be replayed against another domain or session.
func (c *SecureCodec) Seal(domain, id string, session UserSession) (data []byte, err error) {
	_, data, err = c.SealGeneration(domain, id, session)

	return data, err
}

// SealGeneration behaves like Seal and additionally returns the generation written into the backend-only envelope.
func (c *SecureCodec) SealGeneration(domain, id string, session UserSession) (generation string, data []byte, err error) {
	raw, err := session.MarshalMsg(nil)
	if err != nil {
		return "", nil, fmt.Errorf("unable to marshal session: %w", err)
	}

	encryptionKey := c.encKey
	generation = ""
	wrap := false

	if c.keys != nil {
		generation = c.keys.PrimaryID()

		if primary, ok := c.keys.primaryGeneration(); ok && generation != "" {
			encryptionKey = primary.key
			wrap = true
		}
	}

	if data, err = utils.Encrypt(raw, getAAD(domain, id), encryptionKey); err != nil {
		return "", nil, fmt.Errorf("unable to encrypt session: %w", err)
	}

	if wrap {
		if data, err = sealEnvelope(generation, data); err != nil {
			return "", nil, err
		}
	}

	return generation, data, nil
}

// Open decrypts and unmarshals the data of the given Record into the given UserSession. A nil record, or one with no
// data, leaves the session untouched and returns no error.
func (c *SecureCodec) Open(domain string, record Record, session *UserSession) (err error) {
	_, err = c.OpenGeneration(domain, record, session)

	return err
}

// OpenGeneration behaves like Open and returns the generation which sealed the record. Legacy unwrapped records return
// an empty generation.
func (c *SecureCodec) OpenGeneration(domain string, record Record, session *UserSession) (generation string, err error) {
	if record == nil || len(record.GetSessionData()) == 0 {
		return "", nil
	}

	generation, ciphertext, wrapped, envelopeErr := openEnvelope(record.GetSessionData())
	if envelopeErr != nil {
		return "", &ReadError{Reason: ReadReasonRecordUnopenable, Err: ErrRecordUnopenable}
	}

	aad := getAAD(domain, record.GetSessionSignature())

	if wrapped {
		if c.keys == nil {
			return generation, &ReadError{Reason: ReadReasonKeyUnavailable, Generation: generation, Err: fmt.Errorf("%w: %s", ErrKeyGenerationUnavailable, generation)}
		}

		g, ok := c.keys.generation(generation)
		if !ok {
			return generation, &ReadError{Reason: ReadReasonKeyUnavailable, Generation: generation, Err: fmt.Errorf("%w: %s", ErrKeyGenerationUnavailable, generation)}
		}

		if g.state == KeyGenerationStateRetired {
			return generation, &ReadError{Reason: ReadReasonGenerationRetired, Generation: generation, Err: fmt.Errorf("%w: %s", ErrKeyGenerationRetired, generation)}
		}

		data, decryptErr := utils.Decrypt(ciphertext, aad, g.key)
		if decryptErr != nil {
			return generation, &ReadError{Reason: ReadReasonRecordUnopenable, Generation: generation, Err: fmt.Errorf("unable to decrypt session: %w", decryptErr)}
		}

		if _, unmarshalErr := session.UnmarshalMsg(data); unmarshalErr != nil {
			return generation, &ReadError{Reason: ReadReasonRecordUnopenable, Generation: generation, Err: fmt.Errorf("unable to unmarshal session: %w", unmarshalErr)}
		}

		return generation, nil
	}

	// Legacy unwrapped records do not name their generation. Try the historical/current key first, then every readable
	// configured generation so old backend rows remain readable during a rotation without a migration.
	keys := make([]struct {
		id  string
		key []byte
	}, 0)

	if len(c.encKey) != 0 {
		keys = append(keys, struct {
			id  string
			key []byte
		}{id: "", key: c.encKey})
	}

	if c.keys != nil {
		for _, id := range c.keys.ReadableIDs() {
			if id == c.keys.PrimaryID() && len(c.encKey) != 0 {
				continue
			}

			if g, ok := c.keys.generation(id); ok {
				keys = append(keys, struct {
					id  string
					key []byte
				}{id: id, key: g.key})
			}
		}
	}

	var lastErr error

	for _, candidate := range keys {
		data, decryptErr := utils.Decrypt(ciphertext, aad, candidate.key)
		if decryptErr != nil {
			lastErr = decryptErr

			continue
		}

		if _, unmarshalErr := session.UnmarshalMsg(data); unmarshalErr != nil {
			return candidate.id, &ReadError{Reason: ReadReasonRecordUnopenable, Generation: candidate.id, Err: fmt.Errorf("unable to unmarshal session: %w", unmarshalErr)}
		}

		return candidate.id, nil
	}

	if lastErr != nil {
		return "", &ReadError{Reason: ReadReasonRecordUnopenable, Err: fmt.Errorf("unable to decrypt session: %w", lastErr)}
	}

	return "", &ReadError{Reason: ReadReasonRecordUnopenable, Err: errors.New("unable to decrypt session: no configured generation could open the record")}
}

func getAAD(domain, id string) []byte {
	return []byte("authelia:session:v2:" + domain + ":" + id)
}

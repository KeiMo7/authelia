// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package sessiontest contains the backend-independent session conformance suite. Production backend packages call
// RunSuite against their own Repository implementation, ensuring the same observable lifecycle across the in-process
// map, cache, and relational backends.
package sessiontest

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/clock"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/random"
	"github.com/authelia/authelia/v4/internal/session"
)

const (
	Domain    = "conformance.example.com"
	Cookie    = "conformance_session"
	HMACKey   = "conformance-hmac-key"
	OldSecret = "conformance-old-secret-value"
	NewSecret = "conformance-new-secret-value"
	OldGen    = "g1"
	NewGen    = "g2"
	Username  = "john"
)

// Harness connects the shared suite to one backend.
type Harness struct {
	Name string

	// Repository is the backend under test.
	Repository session.Repository

	// Expiration returns the stored absolute expiration for a record when the backend can expose it. It is optional.
	Expiration func(t *testing.T, issuer, id string) time.Time

	// NewContext constructs a request context. When nil, the suite's in-memory Context is used.
	NewContext func() session.Context
}

// Context is the in-memory session.Context used by the suite.
type Context struct {
	context.Context

	Cookies map[string]string
	Set     int
	Cleared *http.Cookie
}

func NewContext() *Context {
	return &Context{Context: context.Background(), Cookies: map[string]string{}}
}

func (c *Context) GetCookie(name string) string { return c.Cookies[name] }

func (c *Context) SetCookie(cookie *http.Cookie) {
	c.Set++
	c.Cookies[cookie.Name] = cookie.Value
}

func (c *Context) ClearCookie(cookie *http.Cookie) {
	c.Cleared = cookie
	delete(c.Cookies, cookie.Name)
}

// Issuer returns the strategy issuer for the shared test domain.
func Issuer(t *testing.T) string {
	t.Helper()

	codec := newCodec(t, NewSecret, nil)

	return codec.Sign([]byte(Domain))
}

func newCodec(t *testing.T, secret string, ring *session.KeyRing) session.Codec {
	t.Helper()

	if ring != nil {
		codec, err := session.NewCodecWithKeyRing(ring, []byte(HMACKey), random.NewMathematical())
		require.NoError(t, err)

		return codec
	}

	codec, err := session.NewCodec(secret, []byte(HMACKey), random.NewMathematical())
	require.NoError(t, err)

	return codec
}

// NewRing returns g2 primary and g1 readable by default.
func NewRing(t *testing.T) *session.KeyRing {
	t.Helper()

	ring, err := session.NewKeyRing(
		session.KeyGenerationConfig{ID: NewGen, Secret: NewSecret, Primary: true},
		session.KeyGenerationConfig{ID: OldGen, Secret: OldSecret},
	)
	require.NoError(t, err)

	return ring
}

// NewStrategy builds a strategy using the supplied codec and backend.
func NewStrategy(t *testing.T, repo session.Repository, codec session.Codec) session.Strategy {
	t.Helper()

	cfg := schema.SessionCookie{
		SessionCookieCommon: schema.SessionCookieCommon{
			Name:                Cookie,
			SameSite:            "lax",
			Expiration:          time.Hour,
			RememberMe:          24 * time.Hour * 30,
			AnonymousExpiration: time.Minute,
		},
		Domain: Domain,
	}

	return session.NewStrategy(cfg, clock.New(), codec, repo)
}

func newRequestContext(h Harness) session.Context {
	if h.NewContext != nil {
		return h.NewContext()
	}

	return NewContext()
}

type seededSession struct {
	rawID  []byte
	sid    string
	cookie string
	pid    string
}

func seedOldGeneration(t *testing.T, ctx context.Context, repo session.Repository, pid string) seededSession {
	t.Helper()

	return seedGeneration(t, ctx, repo, pid, true)
}

func seedLegacyGeneration(t *testing.T, ctx context.Context, repo session.Repository, pid string) seededSession {
	t.Helper()

	return seedGeneration(t, ctx, repo, pid, false)
}

func seedGeneration(t *testing.T, ctx context.Context, repo session.Repository, pid string, enveloped bool) seededSession {
	t.Helper()

	var codec session.Codec

	if enveloped {
		oldRing, err := session.NewKeyRing(session.KeyGenerationConfig{ID: OldGen, Secret: OldSecret, Primary: true})
		require.NoError(t, err)

		codec, err = session.NewCodecWithKeyRing(oldRing, []byte(HMACKey), random.NewMathematical())
		require.NoError(t, err)
	} else {
		var err error

		codec, err = session.NewCodec(OldSecret, []byte(HMACKey), random.NewMathematical())
		require.NoError(t, err)
	}

	rawID, err := codec.GenerateSessionID()
	require.NoError(t, err)

	sid := codec.Sign(rawID)
	issuer := codec.Sign([]byte(Domain))

	user := session.NewUserSession(Username)
	user.CookieDomain = Domain
	user.PublicID = pid

	data, err := codec.Seal(Domain, sid, user)
	require.NoError(t, err)

	require.NoError(t, repo.Save(ctx, issuer, sid, pid, Username, time.Hour, data))

	return seededSession{rawID: rawID, sid: sid, cookie: base64.RawURLEncoding.EncodeToString(rawID), pid: pid}
}

func cookieContext(h Harness, value string) *Context {
	if h.NewContext != nil {
		panic("sessiontest: custom contexts must be initialized with the seeded cookie by the caller")
	}

	ctx := NewContext()
	ctx.Cookies[Cookie] = value

	return ctx
}

// RunSuite executes every shared conformance case against h.
func RunSuite(t *testing.T, h Harness) {
	t.Helper()

	t.Run("RepositoryLifecycle", func(t *testing.T) { testRepositoryLifecycle(t, h) })
	t.Run("RotationReadRepair", func(t *testing.T) { testRotationReadRepair(t, h) })
	t.Run("LegacyFormatReadRepair", func(t *testing.T) { testLegacyFormatReadRepair(t, h) })
	t.Run("RetirementCleanup", func(t *testing.T) { testRetirementCleanup(t, h) })
	t.Run("Propagation", func(t *testing.T) { testPropagation(t, h) })
	t.Run("Concurrency", func(t *testing.T) { testConcurrency(t, h) })
}

func testRepositoryLifecycle(t *testing.T, h Harness) {
	ctx := context.Background()
	issuer := Issuer(t)

	require.NoError(t, h.Repository.Save(ctx, issuer, "id-1", "pid-1", Username, time.Hour, []byte("data-1")))

	record, err := h.Repository.Get(ctx, issuer, "id-1")
	require.NoError(t, err)
	require.NotNil(t, record)
	assert.Equal(t, "id-1", record.GetSessionSignature())
	assert.Equal(t, []byte("data-1"), record.GetSessionData())

	byPID, err := h.Repository.GetByPublicID(ctx, issuer, "pid-1")
	require.NoError(t, err)
	require.NotNil(t, byPID)
	assert.Equal(t, "id-1", byPID.GetSessionSignature())

	ids, err := h.Repository.GetIDsByUsername(ctx, issuer, Username)
	require.NoError(t, err)
	assert.Contains(t, ids, "id-1")

	require.NoError(t, h.Repository.SaveData(ctx, issuer, "id-1", "pid-1", Username, 2*time.Hour, []byte("data-2")))

	record, err = h.Repository.Get(ctx, issuer, "id-1")
	require.NoError(t, err)
	require.Equal(t, []byte("data-2"), record.GetSessionData())

	require.NoError(t, h.Repository.ChangeID(ctx, issuer, "id-1", "id-2", "pid-1", Username, time.Hour, []byte("data-3")))

	record, err = h.Repository.Get(ctx, issuer, "id-1")
	require.NoError(t, err)
	assert.Nil(t, record)

	record, err = h.Repository.Get(ctx, issuer, "id-2")
	require.NoError(t, err)
	require.NotNil(t, record)
	assert.Equal(t, []byte("data-3"), record.GetSessionData())

	byPID, err = h.Repository.GetByPublicID(ctx, issuer, "pid-1")
	require.NoError(t, err)
	require.NotNil(t, byPID)
	assert.Equal(t, "id-2", byPID.GetSessionSignature())

	require.NoError(t, h.Repository.Delete(ctx, issuer, "id-2", "pid-1", Username))

	record, err = h.Repository.Get(ctx, issuer, "id-2")
	require.NoError(t, err)
	assert.Nil(t, record)

	byPID, err = h.Repository.GetByPublicID(ctx, issuer, "pid-1")
	require.NoError(t, err)
	assert.Nil(t, byPID)

	ids, err = h.Repository.GetIDsByUsername(ctx, issuer, Username)
	require.NoError(t, err)
	assert.NotContains(t, ids, "id-2")

	require.NoError(t, h.Repository.GarbageCollection(ctx))
}

func testRotationReadRepair(t *testing.T, h Harness) {
	ctx := context.Background()
	issuer := Issuer(t)
	pid := "pid-rotation"
	seed := seedOldGeneration(t, ctx, h.Repository, pid)

	before, err := h.Repository.Get(ctx, issuer, seed.sid)
	require.NoError(t, err)
	require.NotNil(t, before)
	beforeData := append([]byte(nil), before.GetSessionData()...)

	var beforeExpiration time.Time
	if h.Expiration != nil {
		beforeExpiration = h.Expiration(t, issuer, seed.sid)
	}

	ring := NewRing(t)
	codec, err := session.NewCodecWithKeyRing(ring, []byte(HMACKey), random.NewMathematical())
	require.NoError(t, err)

	strategy := NewStrategy(t, h.Repository, codec)
	reqCtx := cookieContext(h, seed.cookie)

	loaded, err := strategy.Get(reqCtx)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, Username, loaded.Username)
	assert.Equal(t, pid, loaded.PublicID)
	assert.Equal(t, Domain, loaded.CookieDomain)

	after, err := h.Repository.Get(ctx, issuer, seed.sid)
	require.NoError(t, err)
	require.NotNil(t, after, "read-time reseal must keep the same identifier")
	assert.NotEqual(t, beforeData, after.GetSessionData(), "record should have been resealed")

	opened := &session.UserSession{}
	generation, err := codec.OpenGeneration(Domain, after, opened)
	require.NoError(t, err)
	assert.Equal(t, NewGen, generation)
	assert.Equal(t, Username, opened.Username)
	assert.Equal(t, pid, opened.PublicID)
	assert.Equal(t, Domain, opened.CookieDomain)

	byPID, err := h.Repository.GetByPublicID(ctx, issuer, pid)
	require.NoError(t, err)
	require.NotNil(t, byPID)
	assert.Equal(t, seed.sid, byPID.GetSessionSignature(), "public identifier lookup must stay同源")

	ids, err := h.Repository.GetIDsByUsername(ctx, issuer, Username)
	require.NoError(t, err)
	assert.Contains(t, ids, seed.sid, "username lookup must stay同源")

	if h.Expiration != nil && !beforeExpiration.IsZero() {
		afterExpiration := h.Expiration(t, issuer, seed.sid)
		assert.False(t, afterExpiration.Before(beforeExpiration), "reseal may refresh expiration but must not shorten it")
	}
}

func testLegacyFormatReadRepair(t *testing.T, h Harness) {
	ctx := context.Background()
	issuer := Issuer(t)
	pid := "pid-legacy-format"
	seed := seedLegacyGeneration(t, ctx, h.Repository, pid)

	before, err := h.Repository.Get(ctx, issuer, seed.sid)
	require.NoError(t, err)
	require.NotNil(t, before)

	ring := NewRing(t)
	codec, err := session.NewCodecWithKeyRing(ring, []byte(HMACKey), random.NewMathematical())
	require.NoError(t, err)

	strategy := NewStrategy(t, h.Repository, codec)
	reqCtx := NewContext()
	reqCtx.Cookies[Cookie] = seed.cookie

	loaded, err := strategy.Get(reqCtx)
	require.NoError(t, err)
	assert.Equal(t, Username, loaded.Username)
	assert.Equal(t, pid, loaded.PublicID)

	after, err := h.Repository.Get(ctx, issuer, seed.sid)
	require.NoError(t, err)
	require.NotNil(t, after)

	opened := &session.UserSession{}
	generation, err := codec.OpenGeneration(Domain, after, opened)
	require.NoError(t, err)
	assert.Equal(t, NewGen, generation, "legacy record must be resealed into the primary envelope generation")
	assert.Equal(t, pid, opened.PublicID)
	assert.NotEqual(t, before.GetSessionData(), after.GetSessionData())
}

func testRetirementCleanup(t *testing.T, h Harness) {
	ctx := context.Background()
	issuer := Issuer(t)
	pid := "pid-retired"
	seed := seedOldGeneration(t, ctx, h.Repository, pid)

	ring, err := session.NewKeyRing(
		session.KeyGenerationConfig{ID: NewGen, Secret: NewSecret, Primary: true},
		session.KeyGenerationConfig{ID: OldGen, Secret: OldSecret, Retired: true},
	)
	require.NoError(t, err)

	codec, err := session.NewCodecWithKeyRing(ring, []byte(HMACKey), random.NewMathematical())
	require.NoError(t, err)

	strategy := NewStrategy(t, h.Repository, codec)
	reqCtx := NewContext()
	reqCtx.Cookies[Cookie] = seed.cookie

	_, getErr := strategy.Get(reqCtx)
	require.Error(t, getErr)
	assert.ErrorIs(t, getErr, session.ErrKeyGenerationRetired)
	assert.Equal(t, session.ReadReasonGenerationRetired, session.ReasonForError(getErr))
	require.NotNil(t, reqCtx.Cleared, "retirement must clear the cookie")

	record, err := h.Repository.Get(ctx, issuer, seed.sid)
	require.NoError(t, err)
	assert.Nil(t, record)

	byPID, err := h.Repository.GetByPublicID(ctx, issuer, pid)
	require.NoError(t, err)
	assert.Nil(t, byPID)

	ids, err := h.Repository.GetIDsByUsername(ctx, issuer, Username)
	require.NoError(t, err)
	assert.NotContains(t, ids, seed.sid)

	// A regenerated replacement with a new identifier is not affected by retiring the old generation.
	replacementPID := "pid-replacement"
	replacement := seedOldGeneration(t, ctx, h.Repository, replacementPID)
	require.NoError(t, ring.Rotate(session.KeyGenerationConfig{ID: NewGen + "-x", Secret: "another-new-secret"}))

	// Put the ring back to a state where g2 is primary and old is retired for deterministic opening.
	require.NoError(t, ring.SetPrimary(NewGen))

	replacementCtx := NewContext()
	replacementCtx.Cookies[Cookie] = replacement.cookie

	// The replacement was seeded with g1 which is now retired, so first clean it and then exercise a fresh new-gen save.
	_, _ = strategy.Get(replacementCtx)

	fresh := strategy.New(Username)
	fresh.PublicID = "pid-fresh-after-retirement"
	freshCtx := NewContext()
	require.NoError(t, strategy.Save(freshCtx, &fresh))

	freshLoaded, err := strategy.Get(freshCtx)
	require.NoError(t, err)
	assert.Equal(t, Username, freshLoaded.Username)
}

func testPropagation(t *testing.T, h Harness) {
	ctx := context.Background()

	local, err := session.NewKeyRing(
		session.KeyGenerationConfig{ID: NewGen, Secret: NewSecret, Primary: true},
		session.KeyGenerationConfig{ID: OldGen, Secret: OldSecret},
	)
	require.NoError(t, err)

	remote, err := session.NewKeyRing(
		session.KeyGenerationConfig{ID: NewGen, Secret: NewSecret, Primary: true},
		session.KeyGenerationConfig{ID: OldGen, Secret: OldSecret},
	)
	require.NoError(t, err)

	store := session.NewRepositoryRingStateStore(h.Repository)
	localCoord := session.NewRingCoordinator(local, store, time.Millisecond)
	remoteCoord := session.NewRingCoordinator(remote, store, time.Millisecond)

	_, err = localCoord.Sync(ctx)
	require.NoError(t, err)

	require.NoError(t, localCoord.Retire(ctx, OldGen))

	changed, err := remoteCoord.Sync(ctx)
	require.NoError(t, err)
	assert.True(t, changed)

	snapshot := remote.Snapshot()
	for _, generation := range snapshot.Generations {
		if generation.ID == OldGen {
			assert.Equal(t, session.KeyGenerationStateRetired, generation.State)
		}
	}
}

func testConcurrency(t *testing.T, h Harness) {
	t.Run("ResealAndDestroy", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			pid := fmt.Sprintf("pid-reseal-destroy-%s-%d", h.Name, i)
			seed := seedOldGeneration(t, context.Background(), h.Repository, pid)
			ring := NewRing(t)
			codec, err := session.NewCodecWithKeyRing(ring, []byte(HMACKey), random.NewMathematical())
			require.NoError(t, err)
			strategy := NewStrategy(t, h.Repository, codec)

			readCtx := NewContext()
			readCtx.Cookies[Cookie] = seed.cookie
			destroyCtx := NewContext()
			destroyCtx.Cookies[Cookie] = seed.cookie

			start := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(2)

			go func() { defer wg.Done(); <-start; _, _ = strategy.Get(readCtx) }()
			go func() { defer wg.Done(); <-start; _ = strategy.Destroy(destroyCtx) }()

			close(start)
			wg.Wait()

			assert.Eventually(t, func() bool {
				record, getErr := h.Repository.Get(context.Background(), Issuer(t), seed.sid)
				return getErr == nil && record == nil
			}, time.Second, time.Millisecond)

			byPID, err := h.Repository.GetByPublicID(context.Background(), Issuer(t), pid)
			require.NoError(t, err)
			assert.Nil(t, byPID, "destroyed session must not remain reachable by public id")
		}
	})

	t.Run("ResealAndChangeID", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			pid := fmt.Sprintf("pid-reseal-change-%s-%d", h.Name, i)
			seed := seedOldGeneration(t, context.Background(), h.Repository, pid)
			ring := NewRing(t)
			codec, err := session.NewCodecWithKeyRing(ring, []byte(HMACKey), random.NewMathematical())
			require.NoError(t, err)
			strategy := NewStrategy(t, h.Repository, codec)

			readCtx := NewContext()
			readCtx.Cookies[Cookie] = seed.cookie
			changeCtx := NewContext()
			changeCtx.Cookies[Cookie] = seed.cookie

			start := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(2)

			go func() { defer wg.Done(); <-start; _, _ = strategy.Get(readCtx) }()
			go func() { defer wg.Done(); <-start; _ = strategy.Regenerate(changeCtx) }()

			close(start)
			wg.Wait()

			require.NotEmpty(t, changeCtx.Cookies[Cookie])

			nextCtx := NewContext()
			nextCtx.Cookies[Cookie] = changeCtx.Cookies[Cookie]

			loaded, getErr := strategy.Get(nextCtx)
			require.NoError(t, getErr)
			require.NotNil(t, loaded)
			assert.Equal(t, Username, loaded.Username)
			assert.Equal(t, pid, loaded.PublicID)

			oldRecord, err := h.Repository.Get(context.Background(), Issuer(t), seed.sid)
			require.NoError(t, err)
			assert.Nil(t, oldRecord, "old identifier must not remain valid after ChangeID")

			byPID, err := h.Repository.GetByPublicID(context.Background(), Issuer(t), pid)
			require.NoError(t, err)
			require.NotNil(t, byPID)
			assert.NotEqual(t, seed.sid, byPID.GetSessionSignature())

			ids, err := h.Repository.GetIDsByUsername(context.Background(), Issuer(t), Username)
			require.NoError(t, err)
			assert.NotContains(t, ids, seed.sid, "username lookup must repoint rather than retain the old identifier")
			assert.Len(t, uniqueStrings(ids), len(ids), "username lookup must not contain duplicate session identifiers")
		}
	})

	t.Run("DoubleReseal", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			pid := fmt.Sprintf("pid-double-reseal-%s-%d", h.Name, i)
			seed := seedOldGeneration(t, context.Background(), h.Repository, pid)
			ring := NewRing(t)
			codec, err := session.NewCodecWithKeyRing(ring, []byte(HMACKey), random.NewMathematical())
			require.NoError(t, err)
			strategy := NewStrategy(t, h.Repository, codec)

			one := NewContext()
			one.Cookies[Cookie] = seed.cookie
			two := NewContext()
			two.Cookies[Cookie] = seed.cookie

			start := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(2)

			go func() { defer wg.Done(); <-start; _, _ = strategy.Get(one) }()
			go func() { defer wg.Done(); <-start; _, _ = strategy.Get(two) }()

			close(start)
			wg.Wait()

			record, err := h.Repository.Get(context.Background(), Issuer(t), seed.sid)
			require.NoError(t, err)
			require.NotNil(t, record, "double reseal must keep one record at the same identifier")

			opened := &session.UserSession{}
			generation, err := codec.OpenGeneration(Domain, record, opened)
			require.NoError(t, err)
			assert.Equal(t, NewGen, generation)
			assert.Equal(t, pid, opened.PublicID)

			byPID, err := h.Repository.GetByPublicID(context.Background(), Issuer(t), pid)
			require.NoError(t, err)
			require.NotNil(t, byPID)
			assert.Equal(t, seed.sid, byPID.GetSessionSignature())
		}
	})
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))

	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}

		seen[value] = struct{}{}
		out = append(out, value)
	}

	return out
}

// MapRepository is a small mutex-protected Repository used as the process-local conformance backend.
type MapRepository struct {
	mu sync.Mutex

	data        map[string]*mapItem
	publicIDs   map[string]string
	usernames   map[string][]string
	expirations map[string]time.Time
}

type mapItem struct {
	data      []byte
	id        string
	pid       string
	issuer    string
	username  string
	expires   time.Time
	destroyed bool
}

func NewMapRepository() *MapRepository {
	return &MapRepository{data: map[string]*mapItem{}, publicIDs: map[string]string{}, usernames: map[string][]string{}, expirations: map[string]time.Time{}}
}

func mapKey(issuer, id string) string { return issuer + "\x00" + id }

func (r *MapRepository) Get(_ context.Context, issuer, id string) (session.Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	item, ok := r.data[mapKey(issuer, id)]
	if !ok || item.destroyed || (!item.expires.IsZero() && !item.expires.After(time.Now())) {
		return nil, nil
	}

	return session.NewRecord(item.id, append([]byte(nil), item.data...)), nil
}

func (r *MapRepository) GetByPublicID(ctx context.Context, issuer, pid string) (session.Record, error) {
	r.mu.Lock()
	id, ok := r.publicIDs[mapKey(issuer, pid)]
	r.mu.Unlock()

	if !ok {
		return nil, nil
	}

	return r.Get(ctx, issuer, id)
}

func (r *MapRepository) GetIDsByUsername(_ context.Context, issuer, username string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ids := r.usernames[mapKey(issuer, username)]
	out := make([]string, 0, len(ids))

	for _, id := range ids {
		item, ok := r.data[mapKey(issuer, id)]
		if ok && !item.destroyed && (item.expires.IsZero() || item.expires.After(time.Now())) {
			out = append(out, id)
		}
	}

	return out, nil
}

func (r *MapRepository) Save(_ context.Context, issuer, id, pid, username string, expiration time.Duration, data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := mapKey(issuer, id)
	if item, ok := r.data[key]; ok && item.destroyed && (item.expires.IsZero() || item.expires.After(time.Now())) {
		return session.ErrSessionSuperseded
	}

	expires := time.Time{}
	if expiration > 0 {
		expires = time.Now().Add(expiration)
	}

	r.data[key] = &mapItem{data: append([]byte(nil), data...), id: id, pid: pid, issuer: issuer, username: username, expires: expires}
	r.publicIDs[mapKey(issuer, pid)] = id
	r.usernames[mapKey(issuer, username)] = append(r.usernames[mapKey(issuer, username)], id)
	r.expirations[key] = expires

	return nil
}

func (r *MapRepository) SaveData(_ context.Context, issuer, id, _, _ string, expiration time.Duration, data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := mapKey(issuer, id)

	item, ok := r.data[key]
	if !ok || item.destroyed {
		return session.ErrSessionSuperseded
	}

	item.data = append([]byte(nil), data...)
	if expiration > 0 {
		item.expires = time.Now().Add(expiration)
	}

	r.expirations[key] = item.expires

	return nil
}

func (r *MapRepository) Delete(_ context.Context, issuer, id, _, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := mapKey(issuer, id)

	item, ok := r.data[key]
	if !ok {
		return nil
	}

	delete(r.publicIDs, mapKey(issuer, item.pid))
	r.removeUsernameID(issuer, item.username, id)

	item.data, item.username, item.destroyed = nil, "", true

	return nil
}

func (r *MapRepository) ChangeID(_ context.Context, issuer, oldID, id, pid, username string, expiration time.Duration, data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	oldKey := mapKey(issuer, oldID)

	item, ok := r.data[oldKey]
	if !ok || item.destroyed {
		return nil
	}

	delete(r.data, oldKey)
	delete(r.publicIDs, mapKey(issuer, item.pid))
	r.removeUsernameID(issuer, item.username, oldID)

	expires := time.Time{}
	if expiration > 0 {
		expires = time.Now().Add(expiration)
	}

	item.id, item.pid, item.data, item.expires = id, pid, append([]byte(nil), data...), expires
	if username != "" {
		item.username = username
	}

	r.data[mapKey(issuer, id)] = item
	r.publicIDs[mapKey(issuer, pid)] = id
	r.usernames[mapKey(issuer, item.username)] = append(r.usernames[mapKey(issuer, item.username)], id)
	r.expirations[mapKey(issuer, id)] = expires
	delete(r.expirations, oldKey)

	return nil
}

func (r *MapRepository) removeUsernameID(issuer, username, id string) {
	key := mapKey(issuer, username)
	ids := r.usernames[key]

	for i, candidate := range ids {
		if candidate != id {
			continue
		}

		r.usernames[key] = append(ids[:i], ids[i+1:]...)

		break
	}
}

func (r *MapRepository) GarbageCollection(context.Context) error { return nil }

func (r *MapRepository) GarbageCollectionFrequency(context.Context) time.Duration { return 0 }

func (r *MapRepository) StartupCheck() error { return nil }

func (r *MapRepository) Expiration(_ *testing.T, issuer, id string) time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.expirations[mapKey(issuer, id)]
}

var _ session.Repository = (*MapRepository)(nil)

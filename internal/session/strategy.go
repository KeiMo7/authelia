// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/authelia/authelia/v4/internal/clock"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

// NewStrategy returns a new Strategy for the given session cookie configuration. The issuer is the signature of the
// Authelia URL, falling back to the cookie domain, which scopes every record this strategy stores.
func NewStrategy(config schema.SessionCookie, clock clock.Provider, codec Codec, storage Repository) (provider Strategy) {
	sameSite := newSameSite(config.SameSite)

	value := config.Domain

	if config.AutheliaURL != nil {
		value = config.AutheliaURL.String()
	}

	issuer := codec.Sign([]byte(strings.ToLower(value)))

	return &DefaultStrategy{
		config:     config,
		issuer:     issuer,
		domain:     newDomain(config.Domain, sameSite),
		samesite:   sameSite,
		clock:      clock,
		codec:      codec,
		repository: storage,
	}
}

// DefaultStrategy is the default Strategy which stores the session identifier in a cookie and the session data in a
// Repository, scoped to a single configured session cookie domain.
type DefaultStrategy struct {
	config schema.SessionCookie

	issuer   string
	domain   string
	samesite http.SameSite

	clock clock.Provider

	codec      Codec
	repository Repository

	ringCoordinator *RingCoordinator

	resealSuccesses       atomic.Uint64
	resealFailures        atomic.Uint64
	consecutiveResealFail atomic.Uint64
	cleanupSuccesses      atomic.Uint64
	cleanupFailures       atomic.Uint64
}

// RepairMetrics contains observable counts for transparent key-generation repair operations.
type RepairMetrics struct {
	ResealSuccesses        uint64
	ResealFailures         uint64
	ConsecutiveResealFails uint64
	CleanupSuccesses       uint64
	CleanupFailures        uint64
}

// RepairMetrics returns cumulative repair counts for this strategy.
func (p *DefaultStrategy) RepairMetrics() RepairMetrics {
	return RepairMetrics{
		ResealSuccesses:        p.resealSuccesses.Load(),
		ResealFailures:         p.resealFailures.Load(),
		ConsecutiveResealFails: p.consecutiveResealFail.Load(),
		CleanupSuccesses:       p.cleanupSuccesses.Load(),
		CleanupFailures:        p.cleanupFailures.Load(),
	}
}

// GetConfig returns the session cookie configuration of this strategy.
func (p *DefaultStrategy) GetConfig() (config schema.SessionCookie) {
	return p.config
}

// New returns a session for the given username bound to this strategies cookie domain. Giving a session a username at
// construction is the only supported way to do so, see NewUserSession.
func (p *DefaultStrategy) New(username string) (userSession UserSession) {
	userSession = NewUserSession(username)

	userSession.CookieDomain = p.config.Domain

	return userSession
}

// NewDefault returns an anonymous session bound to this strategies cookie domain.
func (p *DefaultStrategy) NewDefault() (userSession UserSession) {
	return p.New("")
}

// Get returns the session for the given request, returning an anonymous session when the request has no session
// cookie or the cookie does not resolve to a readable record.
func (p *DefaultStrategy) Get(ctx Context) (session *UserSession, err error) {
	_, session, err = p.get(ctx)

	return session, err
}

// Save persists the session. The userSession is a pointer as a session which has no public identifier has one generated
// for it, and the caller must observe it to avoid orphaning the generated identifier on a subsequent save. An anonymous
// session which holds no state isn't persisted, and the record and cookie of any previously persisted session for the
// request are discarded instead, as the absence of a session is equivalent to it. A save which was superseded is dropped
// so a stale request can't restore a session, except for a new anonymous session whose cookie refers to a destroyed
// session, which is given a new identifier so its state isn't lost.
func (p *DefaultStrategy) Save(ctx Context, session *UserSession) (err error) {
	if session == nil {
		return errors.New("error occurred saving session: it is nil")
	}

	switch {
	case session.CookieDomain == "":
		session.CookieDomain = p.config.Domain
	case session.CookieDomain != p.config.Domain:
		return errors.New("error occurred saving session: domain does not match cookie domain")
	}

	if !session.RequiresPersistence() {
		return p.discard(ctx, session)
	}

	// A session which has neither a user nor a public identifier was not loaded from a record, so being superseded means
	// the cookie refers to a destroyed session rather than the save having lost a race with a login or regeneration.
	abandoned := session.Username == "" && session.PublicID == ""

	var id []byte

	if id = p.getCookieID(ctx); len(id) == 0 {
		if id, err = p.codec.GenerateSessionID(); err != nil {
			return fmt.Errorf("error occurred generating session ID: %w", err)
		}
	}

	if session.PublicID == "" {
		if session.PublicID, err = p.codec.GeneratePublicID(); err != nil {
			return fmt.Errorf("error occurred generating session public ID: %w", err)
		}
	}

	if err = p.persist(ctx, id, session); !errors.Is(err, ErrSessionSuperseded) {
		return err
	}

	if !abandoned {
		return nil
	}

	if id, err = p.codec.GenerateSessionID(); err != nil {
		return fmt.Errorf("error occurred generating session ID: %w", err)
	}

	return p.persist(ctx, id, session)
}

func (p *DefaultStrategy) persist(ctx Context, id []byte, session *UserSession) (err error) {
	var data []byte

	sid := p.codec.Sign(id)

	if data, err = p.codec.Seal(p.config.Domain, sid, *session); err != nil {
		return fmt.Errorf("error occurred encoding session: %w", err)
	}

	expiration := p.getExpiration(*session)

	if err = p.repository.Save(ctx, p.issuer, sid, session.PublicID, session.Username, expiration, data); err != nil {
		return fmt.Errorf("error occurred saving session to registry: %w", err)
	}

	p.setCached(ctx, session)

	ctx.SetCookie(p.newCookie(id, p.getExpires(expiration)))

	return nil
}

// Regenerate issues a new session identifier for the current session, preserving the session data and public
// identifier, which mitigates session fixation across an authentication level change. A session which can't be read is
// deleted and replaced with an anonymous session as none of its data can be reused, whereas a failure to retrieve it from
// the Repository is returned as the session may be valid.
func (p *DefaultStrategy) Regenerate(ctx Context) (err error) {
	var (
		oldSID  string
		id      []byte
		session *UserSession
	)

	if oldSID, session, err = p.get(ctx); err != nil {
		if errors.Is(err, ErrRepositoryGet) {
			return err
		}

		if err = p.repository.Delete(ctx, p.issuer, oldSID, "", ""); err != nil {
			return fmt.Errorf("error occurred deleting unreadable session from backend: %w", err)
		}

		p.setCached(ctx, nil)

		anonymous := p.NewDefault()

		oldSID, session = "", &anonymous
	}

	if id, err = p.codec.GenerateSessionID(); err != nil {
		return fmt.Errorf("error occurred generating session ID: %w", err)
	}

	sid := p.codec.Sign(id)
	expiration := p.getExpiration(*session)

	if len(oldSID) != 0 {
		var data []byte

		if data, err = p.codec.Seal(p.config.Domain, sid, *session); err != nil {
			return fmt.Errorf("error occurred encoding session: %w", err)
		}

		if err = p.repository.ChangeID(ctx, p.issuer, oldSID, sid, session.PublicID, session.Username, expiration, data); err != nil {
			return fmt.Errorf("error occurred changing session ID: %w", err)
		}
	}

	ctx.SetCookie(p.newCookie(id, p.getExpires(expiration)))

	return nil
}

// Destroy removes the backend record for the current session and instructs the user agent to discard the cookie.
func (p *DefaultStrategy) Destroy(ctx Context) (err error) {
	id, userSession, _ := p.get(ctx)

	if len(id) != 0 {
		var pid, username string

		if userSession != nil {
			pid = userSession.PublicID
			username = userSession.Username
		}

		if err = p.repository.Delete(ctx, p.issuer, id, pid, username); err != nil {
			return fmt.Errorf("error occurred deleting session from backend: %w", err)
		}
	}

	p.setCached(ctx, nil)

	ctx.ClearCookie(p.newDeletionCookie())

	return nil
}

func (p *DefaultStrategy) discard(ctx Context, session *UserSession) (err error) {
	id := p.getCookieID(ctx)

	if len(id) == 0 {
		return nil
	}

	if err = p.repository.Delete(ctx, p.issuer, p.codec.Sign(id), session.PublicID, session.Username); err != nil {
		return fmt.Errorf("error occurred deleting session from backend: %w", err)
	}

	p.setCached(ctx, nil)

	ctx.ClearCookie(p.newDeletionCookie())

	return nil
}

func (p *DefaultStrategy) get(ctx Context) (id string, session *UserSession, err error) {
	cookie := p.getCookieID(ctx)

	userSession := p.NewDefault()

	if len(cookie) == 0 {
		return "", &userSession, nil
	}

	id = p.codec.Sign(cookie)

	if p.ringCoordinator != nil {
		// Propagation is best effort and throttled. A synchronization failure must not turn an otherwise readable local
		// generation into a different class of error; the authoritative record read below classifies backend failure.
		_, _ = p.ringCoordinator.SyncIfDue(ctx)
	}

	if cached, ok := p.getCached(ctx); ok {
		return id, cached, nil
	}

	var record Record

	if record, err = p.repository.Get(ctx, p.issuer, id); err != nil {
		wrapped := fmt.Errorf("%w: %w", ErrRepositoryGet, err)

		return id, nil, &ReadError{Reason: ReadReasonBackendUnavailable, Err: wrapped}
	}

	if record == nil || len(record.GetSessionData()) == 0 {
		p.setCached(ctx, &userSession)

		return id, &userSession, nil
	}

	if record.GetSessionSignature() != id {
		err = &ReadError{Reason: ReadReasonSignatureMismatch, Err: errors.New("error occurred getting session: signature does not match the session identifier")}

		_ = p.purgeUnreadable(ctx, id, "", "")
		p.setCached(ctx, &userSession)

		return id, nil, err
	}

	session = &UserSession{}

	generation, openErr := p.openRecord(p.config.Domain, record, session)
	if openErr != nil {
		err = fmt.Errorf("error occurred decoding session: %w", openErr)

		// A missing key generation may become available after configuration/state propagation, so retain the backend
		// record. Cache the anonymous fallback for this request so repeated consumers do not log the same identifier
		// failure more than once. Retired/unopenable records are additionally purged and their cookie is cleared.
		if !errors.Is(openErr, ErrKeyGenerationUnavailable) {
			_ = p.purgeUnreadable(ctx, id, "", "")
		}

		p.setCached(ctx, &userSession)

		return id, nil, err
	}

	if session.CookieDomain != p.config.Domain {
		err = &ReadError{Reason: ReadReasonDomainMismatch, Generation: generation, Err: errors.New("error occurred getting session: domain does not match cookie domain")}

		_ = p.purgeUnreadable(ctx, id, session.PublicID, session.Username)
		p.setCached(ctx, &userSession)

		return id, nil, err
	}

	p.maybeReseal(ctx, id, generation, session)

	p.setCached(ctx, session)

	return id, session, nil
}

type generationCodec interface {
	OpenGeneration(domain string, record Record, session *UserSession) (generation string, err error)
	PrimaryGeneration() string
}

type generationSealer interface {
	SealGeneration(domain, id string, session UserSession) (generation string, data []byte, err error)
}

func (p *DefaultStrategy) openRecord(domain string, record Record, session *UserSession) (generation string, err error) {
	if gc, ok := p.codec.(generationCodec); ok {
		return gc.OpenGeneration(domain, record, session)
	}

	return "", p.codec.Open(domain, record, session)
}

func (p *DefaultStrategy) primaryGeneration() string {
	if gc, ok := p.codec.(generationCodec); ok {
		return gc.PrimaryGeneration()
	}

	return ""
}

// maybeReseal transparently rewrites a record sealed by a readable non-primary generation. The returned read always
// uses the successfully opened session even when this best-effort repair fails. Repository atomicity ensures a lost race
// with Destroy or ChangeID cannot resurrect a moved/destroyed identifier.
func (p *DefaultStrategy) maybeReseal(ctx Context, id, generation string, session *UserSession) {
	primary := p.primaryGeneration()

	if generation == primary {
		return
	}

	var (
		data []byte
		err  error
	)

	if gs, ok := p.codec.(generationSealer); ok {
		_, data, err = gs.SealGeneration(p.config.Domain, id, *session)
	} else {
		data, err = p.codec.Seal(p.config.Domain, id, *session)
	}

	if err != nil {
		p.noteResealFailure()

		return
	}

	expiration := p.getExpiration(*session)

	if err = p.repository.SaveData(ctx, p.issuer, id, session.PublicID, session.Username, expiration, data); err != nil {
		p.noteResealFailure()

		return
	}

	p.resealSuccesses.Add(1)
	p.consecutiveResealFail.Store(0)
}

func (p *DefaultStrategy) noteResealFailure() {
	p.resealFailures.Add(1)
	p.consecutiveResealFail.Add(1)
}

// purgeUnreadable removes a record which must be treated as absent and expires the browser cookie. Backend deletion
// errors are counted but deliberately do not expose backend or cryptographic detail to callers.
func (p *DefaultStrategy) purgeUnreadable(ctx Context, id, pid, username string) (err error) {
	if err = p.repository.Delete(ctx, p.issuer, id, pid, username); err != nil {
		p.cleanupFailures.Add(1)

		return err
	}

	p.cleanupSuccesses.Add(1)
	ctx.ClearCookie(p.newDeletionCookie())

	return nil
}

func (p *DefaultStrategy) getCached(ctx Context) (session *UserSession, ok bool) {
	caching, ok := ctx.(CachingContext)
	if !ok {
		return nil, false
	}

	cached, ok := caching.CachedSession(p.config.Domain)
	if !ok || cached == nil {
		return nil, false
	}

	value := cached.deepCopy()

	return &value, true
}

func (p *DefaultStrategy) setCached(ctx Context, session *UserSession) {
	caching, ok := ctx.(CachingContext)
	if !ok {
		return
	}

	if session == nil {
		caching.CacheSession(p.config.Domain, nil)

		return
	}

	value := session.deepCopy()

	caching.CacheSession(p.config.Domain, &value)
}

func (p *DefaultStrategy) getCookieID(ctx Context) (id []byte) {
	value := ctx.GetCookie(p.config.Name)

	if len(value) == 0 {
		return nil
	}

	var err error

	if id, err = base64.RawURLEncoding.DecodeString(value); err != nil || len(id) != sessionIDLength {
		return nil
	}

	return id
}

func (p *DefaultStrategy) newCookie(id []byte, expires time.Time) (cookie *http.Cookie) {
	//nolint:gosec // The SameSite attribute is determined by the validated configuration which restricts it to 'none', 'lax', or 'strict'.
	return &http.Cookie{
		Name:     p.config.Name,
		Value:    encodeCookieID(id),
		Path:     "/",
		Domain:   p.domain,
		Expires:  expires,
		Secure:   true,
		HttpOnly: true,
		SameSite: p.samesite,
	}
}

func (p *DefaultStrategy) newDeletionCookie() (cookie *http.Cookie) {
	return p.newCookie(nil, p.clock.Now().Add(-cookieDeletionOffset))
}

func (p *DefaultStrategy) getExpiration(userSession UserSession) (expiration time.Duration) {
	switch {
	case userSession.Username == "" && p.config.AnonymousExpiration > 0:
		return p.config.AnonymousExpiration
	case userSession.KeepMeLoggedIn && !p.config.DisableRememberMe:
		return p.config.RememberMe
	}

	return p.config.Expiration
}

func (p *DefaultStrategy) getExpires(expiration time.Duration) (exp time.Time) {
	if expiration == 0 {
		return expireUnlimited
	}

	return p.clock.Now().Add(expiration)
}

func encodeCookieID(id []byte) string {
	return base64.RawURLEncoding.EncodeToString(id)
}

func newDomain(value string, samSite http.SameSite) string {
	switch {
	case strings.HasPrefix(value, "."), samSite == http.SameSiteStrictMode, net.ParseIP(value) != nil:
		return value
	default:
		return "." + value
	}
}

func newSameSite(value string) http.SameSite {
	switch strings.ToLower(value) {
	case "strict":
		return http.SameSiteStrictMode
	case "lax":
		return http.SameSiteLaxMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
}

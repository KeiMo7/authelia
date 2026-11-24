// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"net/url"
	"time"
)

// Session represents the configuration related to user sessions.
type Session struct {
	SessionCookieCommon `koanf:",squash" yaml:",inline"`

	Secret string `koanf:"secret" yaml:"secret,omitempty" toml:"secret,omitempty" json:"secret,omitempty" jsonschema:"title=Secret" jsonschema_description:"Secret used to encrypt the session data."`

	// PrimaryKeyID selects the primary generation in EncryptionKeys. When empty, exactly one generation may set Primary.
	PrimaryKeyID string `koanf:"primary_key_id" yaml:"primary_key_id,omitempty" toml:"primary_key_id,omitempty" json:"primary_key_id,omitempty"`

	// Encryption configures a nested key ring. It is merged with EncryptionKeys during validation.
	Encryption *SessionKeyRing `koanf:"encryption" yaml:"encryption,omitempty" toml:"encryption,omitempty" json:"encryption,omitempty"`

	// KeyRing is an alias for Encryption.
	KeyRing *SessionKeyRing `koanf:"key_ring" yaml:"key_ring,omitempty" toml:"key_ring,omitempty" json:"key_ring,omitempty"`

	// EncryptionKeys configures multiple session encryption key generations. The primary generation writes new records;
	// other non-retired generations remain readable during rotation windows.
	EncryptionKeys []SessionEncryptionKey `koanf:"encryption_keys" yaml:"encryption_keys,omitempty" toml:"encryption_keys,omitempty" json:"encryption_keys,omitempty"`

	// KeyGenerations is an alias for EncryptionKeys for configuration surfaces which use generation terminology.
	KeyGenerations []SessionEncryptionKey `koanf:"key_generations" yaml:"key_generations,omitempty" toml:"key_generations,omitempty" json:"key_generations,omitempty"`

	// Keys is a short alias for EncryptionKeys.
	Keys []SessionEncryptionKey `koanf:"keys" yaml:"keys,omitempty" toml:"keys,omitempty" json:"keys,omitempty"`

	Storage string `koanf:"storage" yaml:"storage,omitempty" toml:"storage,omitempty" json:"storage,omitempty" jsonschema:"default=internal,title=Storage,enum=internal,enum=cache" jsonschema_description:"The storage provider to use for session storage."`

	Cookies []SessionCookie `koanf:"cookies" yaml:"cookies,omitempty" toml:"cookies,omitempty" json:"cookies,omitempty" jsonschema:"title=Cookies" jsonschema_description:"List of cookie domain configurations."`

	// Deprecated: Use the session cookies option with the same name instead.
	Domain string `koanf:"domain" yaml:"domain,omitempty" toml:"domain,omitempty" json:"domain,omitempty" jsonschema:"deprecated,title=Domain"`
}

// SessionEncryptionKey configures one generation of session encryption key material.
type SessionEncryptionKey struct {
	// ID is the non-secret generation identifier written to the backend record envelope.
	ID string `koanf:"id" yaml:"id,omitempty" toml:"id,omitempty" json:"id,omitempty"`

	// KeyID is an alias for ID.
	KeyID string `koanf:"key_id" yaml:"key_id,omitempty" toml:"key_id,omitempty" json:"key_id,omitempty"`

	// Generation is an alias for ID.
	Generation string `koanf:"generation" yaml:"generation,omitempty" toml:"generation,omitempty" json:"generation,omitempty"`

	// Secret is the raw key material for this generation.
	Secret string `koanf:"secret" yaml:"secret,omitempty" toml:"secret,omitempty" json:"secret,omitempty"`

	// Key is an alias for Secret.
	Key string `koanf:"key" yaml:"key,omitempty" toml:"key,omitempty" json:"key,omitempty"`

	// Primary marks the generation used for new seals.
	Primary bool `koanf:"primary" yaml:"primary,omitempty" toml:"primary,omitempty" json:"primary,omitempty"`

	// Active is an alias for Primary.
	Active bool `koanf:"active" yaml:"active,omitempty" toml:"active,omitempty" json:"active,omitempty"`

	// Retired denies reads for records of this generation and causes them to be cleaned up as absent.
	Retired bool `koanf:"retired" yaml:"retired,omitempty" toml:"retired,omitempty" json:"retired,omitempty"`

	// Disabled is an alias for Retired.
	Disabled bool `koanf:"disabled" yaml:"disabled,omitempty" toml:"disabled,omitempty" json:"disabled,omitempty"`

	// State accepts primary, read_only, or retired and normalizes the boolean lifecycle fields.
	State string `koanf:"state" yaml:"state,omitempty" toml:"state,omitempty" json:"state,omitempty"`
}

// Normalize fills field aliases and lifecycle booleans from their canonical alternatives.
func (k *SessionEncryptionKey) Normalize() {
	if k.ID == "" {
		for _, candidate := range []string{k.KeyID, k.Generation} {
			if candidate != "" {
				k.ID = candidate
				break
			}
		}
	}

	if k.Secret == "" && k.Key != "" {
		k.Secret = k.Key
	}

	if !k.Primary && k.Active {
		k.Primary = true
	}

	if !k.Retired && k.Disabled {
		k.Retired = true
	}

	switch k.State {
	case "primary", "active":
		k.Primary = true
		k.Retired = false
	case "retired", "disabled":
		k.Retired = true
		k.Primary = false
	case "read_only", "readonly", "readable":
		if !k.Primary {
			k.Retired = false
		}
	}
}

// SessionKeyRing configures a primary key generation and its readable/retired generations.
type SessionKeyRing struct {
	// PrimaryKeyID selects the generation used for new seals.
	PrimaryKeyID string `koanf:"primary_key_id" yaml:"primary_key_id,omitempty" toml:"primary_key_id,omitempty" json:"primary_key_id,omitempty"`

	// Primary is an alias for PrimaryKeyID.
	Primary string `koanf:"primary" yaml:"primary,omitempty" toml:"primary,omitempty" json:"primary,omitempty"`

	// Keys is the generation set.
	Keys []SessionEncryptionKey `koanf:"keys" yaml:"keys,omitempty" toml:"keys,omitempty" json:"keys,omitempty"`

	// Generations is an alias for Keys.
	Generations []SessionEncryptionKey `koanf:"generations" yaml:"generations,omitempty" toml:"generations,omitempty" json:"generations,omitempty"`
}

// Compatibility aliases for configuration surfaces which call a generation a key or key generation.
type (
	SessionKey        = SessionEncryptionKey
	SessionGeneration = SessionEncryptionKey
	SessionKeyConfig  = SessionEncryptionKey
)

// SessionCookieCommon represents the session cookie configuration options shared by every session cookie domain.
type SessionCookieCommon struct {
	Name       string        `koanf:"name" yaml:"name,omitempty" toml:"name,omitempty" json:"name,omitempty" jsonschema:"default=authelia_session,title=Name" jsonschema_description:"The session cookie name."`
	SameSite   string        `koanf:"same_site" yaml:"same_site,omitempty" toml:"same_site,omitempty" json:"same_site,omitempty" jsonschema:"default=lax,enum=lax,enum=strict,enum=none,title=Same Site" jsonschema_description:"The session cookie same site value."`
	Expiration time.Duration `koanf:"expiration" yaml:"expiration,omitempty" toml:"expiration,omitempty" json:"expiration,omitempty" jsonschema:"default=1 hour,title=Expiration" jsonschema_description:"The session cookie expiration when remember me is not checked."`
	Inactivity time.Duration `koanf:"inactivity" yaml:"inactivity,omitempty" toml:"inactivity,omitempty" json:"inactivity,omitempty" jsonschema:"default=5 minutes,title=Inactivity" jsonschema_description:"The session inactivity timeout."`
	RememberMe time.Duration `koanf:"remember_me" yaml:"remember_me,omitempty" toml:"remember_me,omitempty" json:"remember_me,omitempty" jsonschema:"default=30 days,title=Remember Me" jsonschema_description:"The session cookie expiration when remember me is checked."`

	AnonymousExpiration time.Duration `koanf:"anonymous_expiration" yaml:"anonymous_expiration,omitempty" toml:"anonymous_expiration,omitempty" json:"anonymous_expiration,omitempty" jsonschema:"default=10 minutes,title=Anonymous Expiration" jsonschema_description:"The expiration of sessions which do not belong to a user."`

	DisableRememberMe bool `yaml:"-" toml:"-" json:"-"`
}

// SessionCookie represents the configuration for a cookie domain.
type SessionCookie struct {
	SessionCookieCommon `koanf:",squash" yaml:",inline"`

	Domain                string   `koanf:"domain" yaml:"domain,omitempty" toml:"domain,omitempty" json:"domain,omitempty" jsonschema:"format=hostname,title=Domain" jsonschema_description:"The domain for this session cookie configuration."`
	AutheliaURL           *url.URL `koanf:"authelia_url" yaml:"authelia_url,omitempty" toml:"authelia_url,omitempty" json:"authelia_url,omitempty" jsonschema:"format=uri,title=Authelia URL" jsonschema_description:"The Root Authelia URL to redirect users to for this session cookie configuration."`
	DefaultRedirectionURL *url.URL `koanf:"default_redirection_url" yaml:"default_redirection_url,omitempty" toml:"default_redirection_url,omitempty" json:"default_redirection_url,omitempty" jsonschema:"format=uri,title=Default Redirection URL" jsonschema_description:"The default redirection URL for this session cookie configuration."`

	Legacy bool `yaml:"-" toml:"-" json:"-"`
}

// DefaultSessionConfiguration is the default session configuration.
var DefaultSessionConfiguration = Session{
	Storage: "internal",
	SessionCookieCommon: SessionCookieCommon{
		Name:       "authelia_session",
		Expiration: time.Hour,
		Inactivity: time.Minute * 5,
		RememberMe: time.Hour * 24 * 30,
		SameSite:   "lax",

		AnonymousExpiration: time.Minute * 10,
	},
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Last State contributors

package lep

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// ParseKeyMaterial decodes a 32-byte key from hex (64 chars) or standard/raw base64.
// Leading "hex:" or "base64:" prefixes are accepted.
func ParseKeyMaterial(reference string) ([]byte, error) {
	value := strings.TrimSpace(reference)
	if value == "" {
		return nil, fmt.Errorf("empty key material")
	}
	switch {
	case strings.HasPrefix(value, "hex:"):
		raw, err := hex.DecodeString(strings.TrimSpace(strings.TrimPrefix(value, "hex:")))
		if err != nil {
			return nil, fmt.Errorf("decode hex key: %w", err)
		}
		if len(raw) != chacha20poly1305.KeySize {
			return nil, fmt.Errorf("key must be %d bytes, got %d", chacha20poly1305.KeySize, len(raw))
		}
		return raw, nil
	case strings.HasPrefix(value, "base64:"):
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(value, "base64:")))
		if err != nil {
			return nil, fmt.Errorf("decode base64 key: %w", err)
		}
		if len(raw) != chacha20poly1305.KeySize {
			return nil, fmt.Errorf("key must be %d bytes, got %d", chacha20poly1305.KeySize, len(raw))
		}
		return raw, nil
	default:
		if raw, err := hex.DecodeString(value); err == nil && len(raw) == chacha20poly1305.KeySize {
			return raw, nil
		}
		if raw, err := base64.StdEncoding.DecodeString(value); err == nil && len(raw) == chacha20poly1305.KeySize {
			return raw, nil
		}
		if raw, err := base64.RawStdEncoding.DecodeString(value); err == nil && len(raw) == chacha20poly1305.KeySize {
			return raw, nil
		}
		return nil, fmt.Errorf("key material must be 32-byte hex or base64")
	}
}

// BuildMemoryKeyring constructs a keyring from string IDs and resolved secret material.
// All keys must be exactly 32 bytes; invalid entries return an error (never silently dropped).
func BuildMemoryKeyring(entries []Key, activeID, authID string) (*MemoryKeyring, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("at least one key is required")
	}
	for _, entry := range entries {
		if len(entry.Key) != chacha20poly1305.KeySize {
			return nil, fmt.Errorf("key %x has invalid length %d", entry.ID, len(entry.Key))
		}
	}
	active := KeyIDFromString(activeID)
	auth := KeyIDFromString(authID)
	if activeID == "" {
		active = entries[0].ID
	}
	if authID == "" {
		auth = active
	}
	ring := NewMemoryKeyring(entries, active, auth)
	if !ring.HaveActive {
		return nil, fmt.Errorf("active key id not found in key set")
	}
	if !ring.HaveAuth {
		return nil, fmt.Errorf("auth key id not found in key set")
	}
	return ring, nil
}

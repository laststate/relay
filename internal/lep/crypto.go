// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Last State contributors

package lep

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"

	"golang.org/x/crypto/chacha20poly1305"
)

// Seal/Open follow spec/lep-crypto.md. Spool and ACK use on-wire bytes;
// Open is for verification and analysis only.

const (
	// AEADMetadataSize is the fixed AEAD header extension.
	AEADMetadataSize = 28
	// AEADTagSize is the ChaCha20-Poly1305 tag trailer length.
	AEADTagSize = 16
	// HMACSize is the auth-only trailer length.
	HMACSize = 32
	// KeyIDSize is the fixed wire key identifier length.
	KeyIDSize = 8

	AlgChaCha20Poly1305 uint8 = 1
)

// Key is a 32-byte secret with an 8-byte identifier for AEAD envelopes.
type Key struct {
	ID  [KeyIDSize]byte
	Key []byte // 32 bytes
}

// Keyring resolves keys by ID for Open and selects an active key for Seal.
type Keyring interface {
	Get(id [KeyIDSize]byte) (Key, bool)
	// Active returns the key used for newly sealed envelopes.
	Active() (Key, bool)
	// AuthKey returns the HMAC key for auth-only envelopes (may share material).
	AuthKey() (Key, bool)
}

// MemoryKeyring is a simple in-process key set.
type MemoryKeyring struct {
	Keys       map[[KeyIDSize]byte]Key
	ActiveID   [KeyIDSize]byte
	AuthKeyID  [KeyIDSize]byte
	HaveActive bool
	HaveAuth   bool
}

// NewMemoryKeyring indexes keys by ID. Entries with invalid key length are ignored;
// prefer BuildMemoryKeyring for production configuration loading (it errors instead).
func NewMemoryKeyring(keys []Key, activeID, authID [KeyIDSize]byte) *MemoryKeyring {
	ring := &MemoryKeyring{Keys: make(map[[KeyIDSize]byte]Key, len(keys))}
	for _, key := range keys {
		if len(key.Key) != chacha20poly1305.KeySize {
			continue
		}
		ring.Keys[key.ID] = key
	}
	if _, ok := ring.Keys[activeID]; ok {
		ring.ActiveID = activeID
		ring.HaveActive = true
	}
	if _, ok := ring.Keys[authID]; ok {
		ring.AuthKeyID = authID
		ring.HaveAuth = true
	} else if ring.HaveActive {
		ring.AuthKeyID = ring.ActiveID
		ring.HaveAuth = true
	}
	return ring
}

func (ring *MemoryKeyring) Get(id [KeyIDSize]byte) (Key, bool) {
	key, ok := ring.Keys[id]
	return key, ok
}

func (ring *MemoryKeyring) Active() (Key, bool) {
	if !ring.HaveActive {
		return Key{}, false
	}
	return ring.Get(ring.ActiveID)
}

func (ring *MemoryKeyring) AuthKey() (Key, bool) {
	if !ring.HaveAuth {
		return Key{}, false
	}
	return ring.Get(ring.AuthKeyID)
}

// ParseKeyID copies up to 8 bytes into a fixed key ID (zero-padded).
func ParseKeyID(raw []byte) [KeyIDSize]byte {
	var id [KeyIDSize]byte
	copy(id[:], raw)
	return id
}

// KeyIDFromString uses the UTF-8 bytes when ≤8, otherwise the first 8 bytes of SHA-256.
func KeyIDFromString(s string) [KeyIDSize]byte {
	if len(s) <= KeyIDSize {
		return ParseKeyID([]byte(s))
	}
	sum := sha256.Sum256([]byte(s))
	return ParseKeyID(sum[:KeyIDSize])
}

// Seal encrypts and/or authenticates a plain validated envelope.
// plain must be a plain (flags=0) or compressed-only envelope.
func Seal(plain []byte, ring Keyring, encrypt bool) ([]byte, error) {
	envelope, err := Validate(plain)
	if err != nil {
		return nil, err
	}
	if envelope.Flags&^FlagCompressed != 0 {
		return nil, errors.New("seal requires a non-authenticated envelope")
	}
	payload := plain[HeaderSize : HeaderSize+int(envelope.PayloadLength)]
	preserveCompress := envelope.Flags & FlagCompressed

	if encrypt {
		key, ok := ring.Active()
		if !ok {
			return nil, errors.New("no active encryption key")
		}
		aead, err := chacha20poly1305.New(key.Key)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, chacha20poly1305.NonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}

		// Build final header core (without CRC) used as AAD.
		headerCore := make([]byte, 20)
		copy(headerCore, plain[:20])
		headerCore[7] = FlagAuthenticated | FlagEncrypted | FlagAEAD | preserveCompress
		binary.LittleEndian.PutUint32(headerCore[16:20], uint32(len(payload))) // ciphertext same length as plaintext for chacha

		// Actually ciphertext length equals plaintext; tag is separate.
		// Seal produces ciphertext||tag with len = len(plaintext)+tag.
		// We put only ciphertext in PayloadLength.
		// AAD must use final PayloadLength = len(ct) = len(payload).
		binary.LittleEndian.PutUint32(headerCore[16:20], uint32(len(payload)))

		sealed := aead.Seal(nil, nonce, payload, headerCore)
		ct, tag := sealed[:len(sealed)-AEADTagSize], sealed[len(sealed)-AEADTagSize:]

		meta := make([]byte, AEADMetadataSize)
		meta[0] = AlgChaCha20Poly1305
		meta[1] = KeyIDSize
		copy(meta[2:10], key.ID[:])
		copy(meta[10:22], nonce)

		out := make([]byte, HeaderSize+AEADMetadataSize+len(ct)+4+AEADTagSize)
		copy(out[:20], headerCore)
		binary.LittleEndian.PutUint32(out[20:24], crc32.ChecksumIEEE(out[:20]))
		copy(out[HeaderSize:], meta)
		copy(out[HeaderSize+AEADMetadataSize:], ct)
		crcRegion := out[HeaderSize : HeaderSize+AEADMetadataSize+len(ct)]
		binary.LittleEndian.PutUint32(out[HeaderSize+AEADMetadataSize+len(ct):], crc32.ChecksumIEEE(crcRegion))
		copy(out[len(out)-AEADTagSize:], tag)
		return out, nil
	}

	key, ok := ring.AuthKey()
	if !ok {
		return nil, errors.New("no auth key")
	}
	headerCore := make([]byte, 20)
	copy(headerCore, plain[:20])
	headerCore[7] = FlagAuthenticated | preserveCompress
	binary.LittleEndian.PutUint32(headerCore[16:20], uint32(len(payload)))

	mac := hmac.New(sha256.New, key.Key)
	mac.Write(headerCore)
	mac.Write(payload)
	sum := mac.Sum(nil)

	out := make([]byte, HeaderSize+len(payload)+4+HMACSize)
	copy(out[:20], headerCore)
	binary.LittleEndian.PutUint32(out[20:24], crc32.ChecksumIEEE(out[:20]))
	copy(out[HeaderSize:], payload)
	binary.LittleEndian.PutUint32(out[HeaderSize+len(payload):], crc32.ChecksumIEEE(payload))
	copy(out[len(out)-HMACSize:], sum)
	return out, nil
}

// Open verifies authentication and decrypts when needed, returning a plain (or compressed-only) envelope.
func Open(raw []byte, ring Keyring) ([]byte, error) {
	envelope, err := Validate(raw)
	if err != nil {
		return nil, err
	}
	if envelope.Flags&FlagAuthenticated == 0 {
		return append([]byte(nil), raw...), nil
	}
	headerCore := raw[:20]
	if envelope.Flags&FlagAEAD != 0 {
		return openAEAD(raw, envelope, headerCore, ring)
	}
	return openHMAC(raw, envelope, headerCore, ring)
}

func openAEAD(raw []byte, envelope Envelope, headerCore []byte, ring Keyring) ([]byte, error) {
	if len(raw) < HeaderSize+AEADMetadataSize+4+AEADTagSize {
		return nil, &ValidationError{Kind: ErrorCorrupt, Field: "aead", Reason: "envelope too short for AEAD"}
	}
	meta := raw[HeaderSize : HeaderSize+AEADMetadataSize]
	if meta[0] != AlgChaCha20Poly1305 {
		return nil, &ValidationError{Kind: ErrorUnsupported, Field: "aead.alg", Reason: fmt.Sprintf("unsupported alg %d", meta[0])}
	}
	if meta[1] != KeyIDSize {
		return nil, &ValidationError{Kind: ErrorCorrupt, Field: "aead.key_id_len", Reason: "expected 8"}
	}
	var keyID [KeyIDSize]byte
	copy(keyID[:], meta[2:10])
	nonce := meta[10:22]
	for _, b := range meta[22:28] {
		if b != 0 {
			return nil, &ValidationError{Kind: ErrorCorrupt, Field: "aead.reserved", Reason: "non-zero reserved bytes"}
		}
	}
	key, ok := ring.Get(keyID)
	if !ok {
		return nil, fmt.Errorf("unknown key id %x", keyID)
	}
	ctLen := int(envelope.PayloadLength)
	ctStart := HeaderSize + AEADMetadataSize
	ctEnd := ctStart + ctLen
	if ctEnd+4+AEADTagSize != len(raw) {
		return nil, &ValidationError{Kind: ErrorCorrupt, Field: "aead", Reason: "length mismatch"}
	}
	ciphertext := raw[ctStart:ctEnd]
	tag := raw[len(raw)-AEADTagSize:]
	aead, err := chacha20poly1305.New(key.Key)
	if err != nil {
		return nil, err
	}
	sealed := append(append([]byte(nil), ciphertext...), tag...)
	plaintext, err := aead.Open(nil, nonce, sealed, headerCore)
	if err != nil {
		return nil, &ValidationError{Kind: ErrorCorrupt, Field: "aead", Reason: "authentication failed"}
	}
	return rebuildPlain(raw, plaintext)
}

func openHMAC(raw []byte, envelope Envelope, headerCore []byte, ring Keyring) ([]byte, error) {
	if len(raw) < HeaderSize+4+HMACSize {
		return nil, &ValidationError{Kind: ErrorCorrupt, Field: "hmac", Reason: "envelope too short"}
	}
	payload := raw[HeaderSize : HeaderSize+int(envelope.PayloadLength)]
	mac := raw[len(raw)-HMACSize:]
	if key, ok := ring.AuthKey(); ok && verifyHMAC(key.Key, headerCore, payload, mac) {
		return rebuildPlain(raw, payload)
	}
	for _, candidate := range allKeys(ring) {
		if verifyHMAC(candidate.Key, headerCore, payload, mac) {
			return rebuildPlain(raw, payload)
		}
	}
	if _, ok := ring.AuthKey(); !ok && len(allKeys(ring)) == 0 {
		return nil, errors.New("no auth key configured")
	}
	return nil, &ValidationError{Kind: ErrorCorrupt, Field: "hmac", Reason: "authentication failed"}
}

func verifyHMAC(key, headerCore, payload, mac []byte) bool {
	h := hmac.New(sha256.New, key)
	h.Write(headerCore)
	h.Write(payload)
	return hmac.Equal(h.Sum(nil), mac)
}

func rebuildPlain(original, payload []byte) ([]byte, error) {
	out := make([]byte, HeaderSize+len(payload)+4)
	copy(out[:20], original[:20])
	out[7] = original[7] & FlagCompressed
	binary.LittleEndian.PutUint32(out[16:20], uint32(len(payload)))
	binary.LittleEndian.PutUint32(out[20:24], crc32.ChecksumIEEE(out[:20]))
	copy(out[HeaderSize:], payload)
	binary.LittleEndian.PutUint32(out[HeaderSize+len(payload):], crc32.ChecksumIEEE(payload))
	if _, err := Validate(out); err != nil {
		return nil, err
	}
	return out, nil
}

func allKeys(ring Keyring) []Key {
	if mem, ok := ring.(*MemoryKeyring); ok {
		out := make([]Key, 0, len(mem.Keys))
		for _, key := range mem.Keys {
			out = append(out, key)
		}
		return out
	}
	if key, ok := ring.Active(); ok {
		return []Key{key}
	}
	return nil
}

// MetadataKeyID extracts the AEAD key id when present.
func MetadataKeyID(raw []byte) ([KeyIDSize]byte, bool) {
	var id [KeyIDSize]byte
	envelope, err := Validate(raw)
	if err != nil || envelope.Flags&FlagAEAD == 0 {
		return id, false
	}
	if len(raw) < HeaderSize+AEADMetadataSize {
		return id, false
	}
	copy(id[:], raw[HeaderSize+2:HeaderSize+10])
	return id, true
}

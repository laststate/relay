# LEP crypto (draft)

Draft layout used by Relay until the shared protocol freezes. Tests:
`internal/lep/crypto_test.go`.

## Goals

- Authenticate envelopes (integrity / device origin)
- Optionally encrypt payloads with AEAD
- Carry a key ID so keys can rotate without re-flashing peers
- Keep storage and ACK on the bytes as received (ciphertext stays opaque)

## Flags

| Flag | Bit | Meaning |
|------|-----|---------|
| Authenticated | 0 | Auth trailer present |
| Encrypted | 1 | Payload is ciphertext (with AEAD) |
| AEAD | 2 | 28-byte AEAD metadata present |
| Compressed | 3 | Payload is compressed (inner) |

Rules enforced by `lep.Validate`:

- Encrypted and AEAD are both set or both clear
- AEAD requires Authenticated

## AEAD metadata (28 bytes)

After the 24-byte header when AEAD is set:

| Offset | Size | Field |
|--------|------|--------|
| 0 | 1 | alg (`1` = ChaCha20-Poly1305) |
| 1 | 1 | key_id_len (must be 8) |
| 2–9 | 8 | key_id |
| 10–21 | 12 | nonce |
| 22–27 | 6 | reserved (zero) |

AAD is header bytes `[0:20]` (magic through `payload_length`, no header CRC).

Wire after header:

```text
metadata(28) || ciphertext || payload_crc(4) || tag(16)
```

`payload_crc` covers `metadata || ciphertext`.

## Auth-only (HMAC-SHA256)

When Authenticated is set without AEAD:

```text
header(24) || payload || payload_crc(4) || mac(32)
```

```text
mac = HMAC-SHA256(key, header[0:20] || payload)
```

Auth-only has no key ID on the wire; config maps sources to keys (or uses a default).

## Key rotation

Configure several 8-byte IDs. Seal uses the active key; Open looks up the ID on
the envelope (AEAD) or tries known keys (HMAC).

## Compression

If Compressed is set, plaintext before Seal (or after Open) is a zstd frame.
Order: TLV encode → optional zstd → optional Seal.

## Forwarding

| Mode | Behavior |
|------|----------|
| Opaque (default) | Deliver raw bytes |
| Verify / decrypt on ingest | Open locally; store still holds original bytes |
| Re-encrypt per dest | Future: Open with device key, Seal with dest key |

## Replay (optional)

When enabled, Relay remembers `(source_id, event_id)` → payload hash and rejects
a *different* payload reusing the same device event id. Identical retransmits
still yield `ACK_DUPLICATE`.

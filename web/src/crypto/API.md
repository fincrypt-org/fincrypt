# Fincrypt Crypto Core — Public API

**Status: FROZEN (P1 exit).** The export set of `web/src/crypto/index.ts`
is asserted by `index.test.ts`. Any change to a signature, format, or
export requires a `THREAT_MODEL.md` delta in the same PR
(CONTRIBUTING rule 2). Downstream phases consume; they do not modify.

## Byte formats (normative, §P1-0 — PLAN §0 verbatim + gap-fills D1–D4)

| Artifact               | Exact format                                                                                                                                                                                                                  |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `kdf_salt`             | 32 crypto-random bytes (`getRandomValues`); b64 on the wire, `bytea` at rest; **never email-derived**                                                                                                                         |
| `kdf_params` (jsonb)   | `{"alg":"argon2id","version":19,"m":65536,"t":3,"p":4}`                                                                                                                                                                       |
| KEK (passphrase)       | `Argon2id(utf8(passphrase), kdf_salt, params)` → 32 B → non-extractable AES-256-GCM `CryptoKey`                                                                                                                               |
| DEK                    | random 32 B, device-generated, raw + zeroizable; never persisted, never logged; wrapped twice                                                                                                                                 |
| Subkey                 | `HKDF-SHA256(DEK, salt=utf8("fincrypt/v1/hkdf"), info=utf8(record_type), 256)` → AES-256-GCM, non-extractable (salt = D1 gap-fill; info = bare record_type, §0-locked)                                                        |
| Record types           | `transactions`, `attachments`, `chat` (§0) + `accounts`, `vault` (D2 — §1 tables store `encrypted_blob`)                                                                                                                      |
| Record AAD             | `utf8("v1                                                                                                                                                                                                                     | <userId> | <type>                     | <recordId>")`— mandatory; vault row uses`record_id="vault"` |
| Envelope               | JSON `{record_id, type, nonce, ciphertext, aad, ts}` — **NO `v` field**; serialized in fixed key order; `nonce` = 12 B b64; `ciphertext` = GCM ct‖tag b64; `ts` = RFC 3339, advisory                                          |
| `wrapped_dek`          | `b64(nonce(12) ‖ GCM(dek_raw, KEK, aad))` = exactly 60 B; wrap AAD = `v1                                                                                                                                                      | <userId> | wrapped-dek` (D3)          |
| `wrapped_dek_recovery` | same packing under the recovery KEK; AAD `v1                                                                                                                                                                                  | <userId> | wrapped-dek-recovery` (D3) |
| Recovery KEK           | mnemonic → BIP39 seed (`mnemonicToSeed(phrase, "")` — 25th word pinned empty, D4) → `HKDF-SHA256(seed, salt=utf8("fincrypt/v1/hkdf"), info=utf8("recovery"), 256)` → AES-256-GCM                                              |
| Mnemonic               | 12 words / 128-bit entropy; NFKD-normalized on entry; shown once at signup; confirm = retype 3 random indices                                                                                                                 |
| OPAQUE                 | RFC 9807; `@serenity-kit/opaque` 1.1.0 pinned (see `OPAQUE-NOTES.md`); `userIdentifier` = lowercase email                                                                                                                     |
| Global                 | base64 = RFC 4648 with padding, via `toB64/fromB64` only; empty plaintext ⇒ RangeError; all decrypt failures throw ONE generic `DecryptError` (no tamper-vs-AAD oracle); error messages never contain key material or content |

## Signatures

```ts
// errors (I6)
class CryptoError extends Error { code: CryptoErrorCode }
class DecryptError extends CryptoError   // 'decryption failed' — the only decrypt error

// b64 (I5)
toB64(bytes: Uint8Array): string
fromB64(b64: string): Uint8Array         // normalizes base64url from external libs

// aead (I2)
RECORD_TYPES: readonly ['transactions', 'attachments', 'chat', 'accounts', 'vault']
type RecordType = typeof RECORD_TYPES[number]
buildAad(userId: string, type: RecordType, recordId: string): Uint8Array
buildAadString(userId: string, type: RecordType, recordId: string): string
encryptBytes(key: CryptoKey, plaintext: Uint8Array, aad: Uint8Array): Promise<Uint8Array>  // nonce‖ct‖tag
decryptBytes(key: CryptoKey, packed: Uint8Array, aad: Uint8Array): Promise<Uint8Array>     // throws DecryptError
importAesKey(raw: Uint8Array): Promise<CryptoKey>                                          // non-extractable, 32 B only

// envelope (no `v` field; byte-stable)
interface Envelope { record_id; type; nonce: Uint8Array; ciphertext: Uint8Array; aad: string; ts: string }
serializeEnvelope(env: Envelope): Uint8Array   // fixed key order
parseEnvelope(bytes: Uint8Array): Envelope     // shape-strict; unknown/missing fields rejected

// kdf
DEFAULT_KDF_PARAMS: KdfParams                  // {alg:'argon2id', version:19, m:65536, t:3, p:4}
generateKdfSalt(): Uint8Array                  // 32 B
argon2idDerive(pass: string, salt: Uint8Array, p: KdfParams, opts?): Promise<Uint8Array>
deriveKek(pass: string, salt: Uint8Array, p: KdfParams): Promise<CryptoKey>   // blocking — prefer worker
deriveKekOffThread(pass: string, salt: Uint8Array, p: KdfParams): Promise<{ kek: CryptoKey; offThread: boolean }>
serializeKdfParams(p: KdfParams): string       // exact jsonb
parseKdfParams(json: string): KdfParams        // version-guarded
importKek(bytes: Uint8Array): Promise<CryptoKey>

// key hierarchy (I3/I4)
type RawKey = Uint8Array                        // zeroizable DEK bytes
hkdfBits(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, bits: number): Uint8Array
hkdfSaltBytes(): Uint8Array                     // "fincrypt/v1/hkdf" (D1)
deriveSubkey(dek: RawKey, type: RecordType): Promise<CryptoKey>
generateDek(): RawKey
wrapDek(dek: RawKey, kek: CryptoKey, userId: string): Promise<Uint8Array>     // 60 B
unwrapDek(w: Uint8Array, kek: CryptoKey, userId: string): Promise<RawKey>     // throws WrapError
wrapWithRecovery(dek: RawKey, kek: CryptoKey, userId: string): Promise<Uint8Array>
unwrapWithRecovery(w: Uint8Array, kek: CryptoKey, userId: string): Promise<RawKey>
zeroize(...bufs: Array<Uint8Array | undefined>): void
zeroizeAll(obj: Record<string, unknown>): void  // best-effort — documented residual

// recovery (D4)
generateRecoveryPhrase(): { words: string[]; mnemonic: string }
normalizePhrase(input: string): string          // NFKD, lowercase, collapse whitespace
validateRecoveryPhrase(phrase: string): boolean
deriveRecoveryKek(mnemonic: string): Promise<CryptoKey>
wrapDekWithRecovery(dek: RawKey, mnemonic: string, userId: string): Promise<Uint8Array>
recoverDek(wrappedRecovery: Uint8Array, mnemonic: string, userId: string): Promise<RawKey>
pickConfirmIndices(rng?: () => number): [number, number, number]  // 3 distinct of 0..11

// opaque (wire format in OPAQUE-NOTES.md; password never on the wire, I1)
opaqueRegister(transport: Transport, email: string, password: string): Promise<RegistrationResult>
opaqueLogin(transport: Transport, email: string, password: string): Promise<LoginResult | undefined>
canonicalUserIdentifier(email: string): string

// lifecycle (§0 verbatim behaviors)
changePassphrase(args): Promise<PassphraseChangeResult>   // new salt, re-wrap BOTH, fresh nonces, NO re-encryption
recoverWithMnemonic(args): Promise<RecoverWithMnemonicResult>
rotateRecovery(args): Promise<RotateRecoveryResult>       // passphrase wrap untouched

// keystore (I7: memory-only; never localStorage/sessionStorage/IndexedDB/cookies)
useSessionKeys          // zustand store (React)
sessionKeys             // non-hook accessor: unlockWithPassphrase / unlockWithRecovery / getSubkey / lock / encryptRecord
startIdleTimer(minutes: number, onIdle: () => void): IdleTimerHandle & { reset(): void }  // DEFAULT OFF
```

## Invariants (I1–I8)

| #   | Invariant                                                                                                                                                    |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| I1  | Passphrase and mnemonic are never serialized into any outbound string, log, error, or persisted byte (wire-inspection + hygiene-scan tests)                  |
| I2  | AES-256-GCM, 96-bit random nonces, AAD mandatory and canonically derived; AAD mismatch fails decryption                                                      |
| I3  | Raw key bytes exist transiently only; long-lived keys are non-extractable CryptoKeys; JS zeroization is best-effort (GC residual documented in THREAT_MODEL) |
| I4  | Records are encrypted with HKDF subkeys only — the raw DEK never encrypts a record                                                                           |
| I5  | One canonical codec: RFC 4648 base64 with padding; no base64url, no hex                                                                                      |
| I6  | Typed `CryptoError` with a stable `code`; messages never contain key material or content                                                                     |
| I7  | No key material is ever persisted; the keystore is memory-only (eslint + CI grep + runtime storage-spy)                                                      |
| I8  | The public API surface is exactly `index.ts`'s export list — asserted by test                                                                                |

## Vectors

- `vectors/index.json` — RFC 5869 (HKDF), RFC 9106 (Argon2id), official BIP39, GCM KATs.
- `__vectors__/golden.json` — FROZEN end-to-end golden vectors; regenerate only with a THREAT_MODEL delta.
- Argon2id cross-verification: hash-wasm reproduces Go `x/crypto/argon2` and RustCrypto reference KAT tags byte-identically (no-secret vectors; hash-wasm's API cannot pass RFC 9106's `secret`+AD — recorded in `kdf.test.ts`).

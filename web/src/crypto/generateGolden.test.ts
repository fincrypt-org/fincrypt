/**
 * Golden vectors (C1.8): FROZEN committed fixtures.
 *
 * golden.json is generated ONCE (first run of this suite) with fully
 * fixed inputs, then treated as immutable. Every subsequent run
 * RE-VERIFIES it: passphrase KEK unwrap, recovery unwrap, and envelope
 * decryption must reproduce the recorded bytes exactly. P5's enclave
 * work targets the same file. Regenerating = crypto-core change =
 * THREAT_MODEL delta.
 */
import { beforeAll, describe, expect, it } from 'vitest'
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { ensureTestCrypto } from './test-env'
import { argon2idDerive, importKek, serializeKdfParams, parseKdfParams } from './kdf'
import {
  wrapDek,
  wrapWithRecovery,
  unwrapDek,
  unwrapWithRecovery,
  deriveSubkey,
  generateDek,
} from './keyHierarchy'
import { deriveRecoveryKek } from './recovery'
import { buildAad, buildAadString, decryptBytes, type RecordType } from './aead'
import { serializeEnvelope, type Envelope } from './envelope'
import { toB64, fromB64 } from './b64'

beforeAll(() => {
  ensureTestCrypto()
})

// ---- FIXED inputs (deterministic by construction; test params) ----
const TEST_PARAMS = { alg: 'argon2id' as const, version: 19 as const, m: 8192, t: 1, p: 1 }
const PASSPHRASE = 'golden-passphrase-v1'
const USER_ID = 'golden-user@fincrypt.test'

// Fixed salt: 32 bytes of 0x5a.
const SALT = new Uint8Array(32).fill(0x5a)
// Fixed DEK: deterministic byte pattern.
function fixedDek(): Uint8Array {
  const dek = new Uint8Array(32)
  for (let i = 0; i < 32; i++) dek[i] = (i * 7 + 3) % 256
  return dek
}
// Fixed mnemonic: from the committed official BIP39 fixture.
const FIXTURES: { 'bip39-official': Array<{ mnemonic: string }> } = JSON.parse(
  readFileSync(join(__dirname, 'vectors', 'index.json'), 'utf-8'),
)
const MNEMONIC = FIXTURES['bip39-official'][0]?.mnemonic ?? ''
// Fixed nonces (golden-only; prod uses random nonces per write).
function fixedNonce(label: string): Uint8Array {
  const nonce = new Uint8Array(12)
  nonce.set(new TextEncoder().encode(label).slice(0, 12))
  return nonce
}

interface GoldenFile {
  meta: { generated: string; note: string }
  user_id: string
  kdf_salt_b64: string
  kdf_params_json: string
  passphrase: string
  dek_b64: string
  mnemonic: string
  wrapped_dek_b64: string
  wrapped_dek_recovery_b64: string
  envelopes: Array<{ type: string; record_id: string; plaintext: string; envelope_json: string }>
}

const GOLDEN_PATH = join(__dirname, '__vectors__', 'golden.json')

const hex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, '0')).join('')

describe('golden vectors (C1.8, I8 byte-stability)', () => {
  it('verifies the frozen golden vectors (generates on first run)', async () => {
    expect(MNEMONIC).toBeTruthy()

    if (!existsSync(GOLDEN_PATH)) {
      // ---------- GENERATE (one-time) ----------
      const dek = fixedDek()
      const kek = await importKek(await argon2idDerive(PASSPHRASE, SALT, TEST_PARAMS))
      const wrappedDek = await wrapDek(dek, kek, USER_ID)
      const recoveryKek = await deriveRecoveryKek(MNEMONIC)
      const wrappedRecovery = await wrapWithRecovery(dek, recoveryKek, USER_ID)

      const envelopes: GoldenFile['envelopes'] = []
      for (const [type, recordId, label, plaintext] of [
        ['transactions', 'golden-tx-1', 'golden-tx1', 'PAYMENT|Grocery Mart|-42.50|EUR'],
        ['chat', 'golden-chat-1', 'golden-chat1', 'what did I spend this month?'],
      ] as const) {
        const t = type as RecordType
        const subkey = await deriveSubkey(dek, t)
        const aadBytes = buildAad(USER_ID, t, recordId)
        const nonce = fixedNonce(label)
        const ivCopy = new Uint8Array(nonce)
        const aadCopy = new Uint8Array(aadBytes)
        const ptBytes = new TextEncoder().encode(plaintext)
        const ct = new Uint8Array(
          await crypto.subtle.encrypt(
            {
              name: 'AES-GCM',
              iv: ivCopy as unknown as BufferSource,
              additionalData: aadCopy as unknown as BufferSource,
              tagLength: 128,
            },
            subkey,
            ptBytes as unknown as BufferSource,
          ),
        )
        const env: Envelope = {
          record_id: recordId,
          type: t,
          nonce,
          ciphertext: ct,
          aad: buildAadString(USER_ID, t, recordId),
          ts: '2026-09-07T00:00:00Z',
        }
        envelopes.push({
          type: t,
          record_id: recordId,
          plaintext,
          envelope_json: new TextDecoder().decode(serializeEnvelope(env)),
        })
      }

      const golden: GoldenFile = {
        meta: {
          generated: '2026-09-07',
          note: 'FROZEN golden vectors. Inputs fixed; regenerate only with a THREAT_MODEL delta.',
        },
        user_id: USER_ID,
        kdf_salt_b64: toB64(SALT),
        kdf_params_json: serializeKdfParams(TEST_PARAMS),
        passphrase: PASSPHRASE,
        dek_b64: toB64(dek),
        mnemonic: MNEMONIC,
        wrapped_dek_b64: toB64(wrappedDek),
        wrapped_dek_recovery_b64: toB64(wrappedRecovery),
        envelopes,
      }
      mkdirSync(join(__dirname, '__vectors__'), { recursive: true })
      writeFileSync(GOLDEN_PATH, JSON.stringify(golden, null, 2))
      expect(golden.envelopes.length).toBe(2)
      return
    }

    // ---------- VERIFY (every subsequent run) ----------
    const golden = JSON.parse(readFileSync(GOLDEN_PATH, 'utf-8')) as GoldenFile
    const params = parseKdfParams(golden.kdf_params_json)
    const salt = fromB64(golden.kdf_salt_b64)
    const dekExpected = fromB64(golden.dek_b64)

    // Passphrase KEK unwrap reproduces the exact DEK:
    const kek = await importKek(await argon2idDerive(golden.passphrase, salt, params))
    const dek = await unwrapDek(fromB64(golden.wrapped_dek_b64), kek, golden.user_id)
    expect(hex(dek)).toBe(hex(dekExpected))

    // Recovery unwrap reproduces the exact DEK:
    const recoveryKek = await deriveRecoveryKek(golden.mnemonic)
    expect(
      hex(
        await unwrapWithRecovery(
          fromB64(golden.wrapped_dek_recovery_b64),
          recoveryKek,
          golden.user_id,
        ),
      ),
    ).toBe(hex(dekExpected))

    // Envelopes decrypt byte-identically to the recorded plaintext:
    for (const v of golden.envelopes) {
      const env = JSON.parse(v.envelope_json) as {
        nonce: string
        ciphertext: string
        aad: string
        type: string
      }
      const t = env.type as RecordType
      const subkey = await deriveSubkey(dekExpected, t)
      const packed = new Uint8Array([...fromB64(env.nonce), ...fromB64(env.ciphertext)])
      const pt = await decryptBytes(subkey, packed, new TextEncoder().encode(env.aad))
      expect(new TextDecoder().decode(pt)).toBe(v.plaintext)

      // Byte-stability: raw WebCrypto encryption with the SAME fixed nonce
      // over the SAME AAD/inputs reproduces the recorded ciphertext exactly.
      const ctAgain = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: fromB64(env.nonce) as unknown as BufferSource,
          additionalData: new TextEncoder().encode(env.aad) as unknown as BufferSource,
          tagLength: 128,
        },
        subkey,
        new TextEncoder().encode(v.plaintext) as unknown as BufferSource,
      )
      expect(hex(new Uint8Array(ctAgain))).toBe(hex(fromB64(env.ciphertext)))
    }
  })
})

// generateDek is exported for the API surface; the golden DEK is fixed instead.
void generateDek

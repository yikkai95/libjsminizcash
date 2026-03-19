/**
 * Orchard note decryption (incoming, using IVK).
 *
 * For each Orchard action, trial-decrypt enc_ciphertext using:
 *   shared_secret = [ivk] * epk
 *   K_enc = BLAKE2b-256("Zcash_OrchardKDF", repr(shared_secret) || repr(epk))
 *   plaintext = ChaCha20Poly1305_Decrypt(K_enc, nonce=0, enc_ciphertext)
 */
import { blake2b } from '@noble/hashes/blake2.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import {
  PallasPoint,
  type PallasPointType,
  pointFromBytes,
  pointToBytes,
} from './pallas.js';
import type { OrchardIncomingViewingKey } from './keys.js';
import type { OrchardAction } from './transaction.js';

const KDF_PERSONAL = new TextEncoder().encode('Zcash_OrchardKDF');

export interface DecryptedNote {
  diversifier: Uint8Array; // 11 bytes
  value: bigint;           // zatoshis
  rseed: Uint8Array;       // 32 bytes
  memo: Uint8Array;        // 512 bytes
  memoText: string | null; // decoded UTF-8 memo, or null if empty/binary
  actionIndex: number;
  scope: 'external' | 'internal';
}

/**
 * Derive the symmetric encryption key from a DH shared secret and ephemeral key.
 */
function kdfOrchard(sharedSecret: Uint8Array, epk: Uint8Array): Uint8Array {
  const input = new Uint8Array(64);
  input.set(sharedSecret, 0);
  input.set(epk, 32);
  return blake2b(input, { dkLen: 32, personalization: KDF_PERSONAL });
}

/**
 * Decode memo field. Returns UTF-8 text if it looks like text, null otherwise.
 */
function decodeMemo(memo: Uint8Array): string | null {
  // All zeros = no memo
  if (memo.every((b) => b === 0)) return null;

  // Try to decode as UTF-8 text (find end of text, ignoring trailing zeros)
  let end = memo.length;
  while (end > 0 && memo[end - 1] === 0) end--;
  if (end === 0) return null;

  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(memo.subarray(0, end));
    // Check if it looks like printable text
    if (/^[\x20-\x7e\n\r\t\u00a0-\uffff]+$/.test(text)) {
      return text;
    }
  } catch {
    // Not valid UTF-8
  }
  return null;
}

/**
 * Try to decrypt a single Orchard action with the given IVK.
 * Returns the decrypted note, or null if decryption fails (not ours).
 */
export function tryDecryptAction(
  action: OrchardAction,
  ivk: OrchardIncomingViewingKey,
  actionIndex: number
): DecryptedNote | null {
  try {
    // Parse ephemeral key as a Pallas point
    const epk = pointFromBytes(action.ephemeralKey);
    if (epk.equals(PallasPoint.ZERO)) return null;

    // Compute shared secret: [ivk] * epk
    const sharedSecretPoint = epk.multiply(ivk.ivk);
    const sharedSecretBytes = pointToBytes(sharedSecretPoint);

    // Derive encryption key (use raw epk bytes from transaction, not re-serialized)
    const kEnc = kdfOrchard(sharedSecretBytes, action.ephemeralKey);

    // Decrypt with ChaCha20Poly1305 (nonce = 12 zero bytes)
    const nonce = new Uint8Array(12);
    const cipher = chacha20poly1305(kEnc, nonce);
    const plaintext = cipher.decrypt(action.encCiphertext);

    // Parse plaintext: leadByte(1) | d(11) | v(8) | rseed(32) | memo(512) = 564 bytes
    if (plaintext.length !== 564) return null;

    const leadByte = plaintext[0];
    if (leadByte !== 0x02) return null; // Must be Orchard note type

    const diversifier = plaintext.slice(1, 12);
    const valueBytes = plaintext.slice(12, 20);
    let value = 0n;
    for (let i = 7; i >= 0; i--) value = (value << 8n) | BigInt(valueBytes[i]);

    const rseed = plaintext.slice(20, 52);
    const memo = plaintext.slice(52, 564);
    const memoText = decodeMemo(memo);

    return { diversifier, value, rseed, memo, memoText, actionIndex, scope: 'external' };
  } catch {
    // Decryption failed — this action is not for us
    return null;
  }
}

/**
 * Try to decrypt all Orchard actions in a transaction using both external and internal IVKs.
 */
export function decryptTransaction(
  actions: OrchardAction[],
  externalIvk: OrchardIncomingViewingKey,
  internalIvk?: OrchardIncomingViewingKey
): DecryptedNote[] {
  const notes: DecryptedNote[] = [];
  for (let i = 0; i < actions.length; i++) {
    let note = tryDecryptAction(actions[i], externalIvk, i);
    if (note) {
      notes.push(note);
      continue;
    }
    if (internalIvk) {
      note = tryDecryptAction(actions[i], internalIvk, i);
      if (note) {
        note.scope = 'internal';
        notes.push(note);
      }
    }
  }
  return notes;
}

/**
 * Format a zatoshi value as ZEC string.
 */
export function formatZec(zatoshis: bigint): string {
  const negative = zatoshis < 0n;
  const abs = negative ? -zatoshis : zatoshis;
  const whole = abs / 100000000n;
  const frac = (abs % 100000000n).toString().padStart(8, '0');
  return `${negative ? '-' : ''}${whole}.${frac}`;
}

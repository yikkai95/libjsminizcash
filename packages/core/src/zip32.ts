/**
 * ZIP-32 key derivation for Orchard.
 * Derives Orchard spending keys from a BIP-39 seed.
 */
import { blake2b } from '@noble/hashes/blake2.js';
import { concatBytes } from '@noble/hashes/utils.js';

// Master key uses "ZcashIP32Orchard"; child derivation uses "Zcash_ExpandSeed" (PrfExpand)
const MKG_PERSONAL = new TextEncoder().encode('ZcashIP32Orchard');
const CKD_PERSONAL = new TextEncoder().encode('Zcash_ExpandSeed');

function zip32Master(seed: Uint8Array): { sk: Uint8Array; chainCode: Uint8Array } {
  const I = blake2b(seed, { dkLen: 64, personalization: MKG_PERSONAL });
  return {
    sk: I.slice(0, 32),
    chainCode: I.slice(32, 64),
  };
}

function zip32Child(
  parent: { sk: Uint8Array; chainCode: Uint8Array },
  index: number // full index WITH hardened bit (0x80000000)
): { sk: Uint8Array; chainCode: Uint8Array } {
  const indexBytes = new Uint8Array(4);
  indexBytes[0] = index & 0xff;
  indexBytes[1] = (index >> 8) & 0xff;
  indexBytes[2] = (index >> 16) & 0xff;
  indexBytes[3] = (index >>> 24) & 0xff;

  const input = concatBytes(parent.chainCode, new Uint8Array([0x81]), parent.sk, indexBytes);
  const I = blake2b(input, { dkLen: 64, personalization: CKD_PERSONAL });
  return {
    sk: I.slice(0, 32),
    chainCode: I.slice(32, 64),
  };
}

function hardened(index: number): number {
  return (index + 0x80000000) >>> 0;
}

/**
 * Derive an Orchard spending key from a BIP-39 seed.
 * Path: m/32'/coin_type'/account'
 *
 * @param seed - BIP-39 seed (>= 32 bytes)
 * @param coinType - 133 for mainnet, 1 for testnet
 * @param account - Account index (0-based)
 * @returns 32-byte Orchard spending key
 */
export function deriveOrchardSpendingKeyFromSeed(
  seed: Uint8Array,
  coinType: number,
  account: number
): Uint8Array {
  if (seed.length < 32) throw new Error('Seed must be at least 32 bytes');

  let key = zip32Master(seed);
  key = zip32Child(key, hardened(32));
  key = zip32Child(key, hardened(coinType));
  key = zip32Child(key, hardened(account));

  return key.sk;
}

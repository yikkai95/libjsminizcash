/**
 * Unified Address and Unified Full Viewing Key encoding (ZIP-316).
 * Uses Bech32m with F4Jumble.
 */
import { bech32m } from '@scure/base';
import { blake2b } from '@noble/hashes/blake2.js';
import { f4jumble, f4jumbleInv } from './f4jumble.js';
import {
  type OrchardFullViewingKey,
  type OrchardAddress,
  type Network,
  orchardAddressToBytes,
} from './keys.js';
import { pointToBytes, fpToBytes, frToBytes } from './pallas.js';

// Typecodes per ZIP-316
const TYPECODE_P2PKH = 0x00;
const TYPECODE_P2SH = 0x01;
const TYPECODE_SAPLING = 0x02;
const TYPECODE_ORCHARD = 0x03;

// HRPs per network
const UA_HRP: Record<Network, string> = { main: 'u', test: 'utest' };
const UFVK_HRP: Record<Network, string> = { main: 'uview', test: 'uviewtest' };

// Padding personalization
const PADDING_PERSONAL = new Uint8Array(16);
(() => {
  const prefix = new TextEncoder().encode('ZcashUA_Padding');
  PADDING_PERSONAL.set(prefix);
})();

function computePadding(hrp: string): Uint8Array {
  return blake2b(new TextEncoder().encode(hrp), {
    dkLen: 16,
    personalization: PADDING_PERSONAL,
  });
}

/** Write a CompactSize integer into a buffer. Returns the number of bytes written. */
function writeCompactSize(buf: Uint8Array, offset: number, value: number): number {
  if (value < 0xfd) {
    buf[offset] = value;
    return 1;
  } else if (value <= 0xffff) {
    buf[offset] = 0xfd;
    buf[offset + 1] = value & 0xff;
    buf[offset + 2] = (value >> 8) & 0xff;
    return 3;
  }
  throw new Error('CompactSize value too large');
}

function compactSizeBytes(value: number): number {
  return value < 0xfd ? 1 : 3;
}

/**
 * Encode an Orchard-only unified address.
 */
export function encodeUnifiedAddress(
  address: OrchardAddress,
  network: Network
): string {
  const hrp = UA_HRP[network];
  const addrBytes = orchardAddressToBytes(address);

  // Build raw encoding: typecode || length || data
  const tcSize = compactSizeBytes(TYPECODE_ORCHARD);
  const lenSize = compactSizeBytes(addrBytes.length);
  const rawLen = tcSize + lenSize + addrBytes.length;
  const padding = computePadding(hrp);
  const totalLen = rawLen + padding.length;

  const raw = new Uint8Array(totalLen);
  let offset = 0;
  offset += writeCompactSize(raw, offset, TYPECODE_ORCHARD);
  offset += writeCompactSize(raw, offset, addrBytes.length);
  raw.set(addrBytes, offset);
  offset += addrBytes.length;
  raw.set(padding, offset);

  const jumbled = f4jumble(raw);
  return bech32m.encode(hrp, bech32m.toWords(jumbled), false);
}

/**
 * Encode an Orchard-only Unified Full Viewing Key.
 *
 * FVK item format per ZIP-316: typecode || length || fvk_data
 * Orchard FVK data = ak (32 bytes) || nk (32 bytes) || rivk (32 bytes) = 96 bytes
 */
export function encodeUnifiedFVK(
  fvk: OrchardFullViewingKey,
  network: Network
): string {
  const hrp = UFVK_HRP[network];

  // Serialize FVK components
  const akBytes = pointToBytes(fvk.ak);
  const nkBytes = fpToBytes(fvk.nk);
  const rivkBytes = frToBytes(fvk.rivk);

  const fvkData = new Uint8Array(96);
  fvkData.set(akBytes, 0);
  fvkData.set(nkBytes, 32);
  fvkData.set(rivkBytes, 64);

  // Build raw encoding
  const tcSize = compactSizeBytes(TYPECODE_ORCHARD);
  const lenSize = compactSizeBytes(fvkData.length);
  const rawLen = tcSize + lenSize + fvkData.length;
  const padding = computePadding(hrp);
  const totalLen = rawLen + padding.length;

  const raw = new Uint8Array(totalLen);
  let offset = 0;
  offset += writeCompactSize(raw, offset, TYPECODE_ORCHARD);
  offset += writeCompactSize(raw, offset, fvkData.length);
  raw.set(fvkData, offset);
  offset += fvkData.length;
  raw.set(padding, offset);

  const jumbled = f4jumble(raw);
  return bech32m.encode(hrp, bech32m.toWords(jumbled), false);
}

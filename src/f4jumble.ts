/**
 * F4Jumble: 4-round Feistel construction from ZIP-316.
 * Used for encoding unified addresses and viewing keys.
 */
import { blake2b } from '@noble/hashes/blake2.js';

function gPersonal(i: number): Uint8Array {
  const personal = new Uint8Array(16);
  const prefix = new TextEncoder().encode('UA_F4Jumble_G');
  personal.set(prefix);
  personal[13] = i;
  // bytes 14-15 remain 0
  return personal;
}

function hPersonal(i: number, j: number): Uint8Array {
  const personal = new Uint8Array(16);
  const prefix = new TextEncoder().encode('UA_F4Jumble_H');
  personal[13] = i;
  personal[14] = j & 0xff;
  personal[15] = (j >> 8) & 0xff;
  return personal;
}

// G function: produces 64 bytes using BLAKE2b-512
function g(i: number, u: Uint8Array): Uint8Array {
  return blake2b(u, { dkLen: 64, personalization: gPersonal(i) });
}

// H function: produces `len` bytes by chaining BLAKE2b-512 calls
function h(i: number, u: Uint8Array, len: number): Uint8Array {
  const result = new Uint8Array(len);
  let offset = 0;
  for (let j = 0; offset < len; j++) {
    const chunk = blake2b(u, { dkLen: 64, personalization: hPersonal(i, j) });
    const toCopy = Math.min(64, len - offset);
    result.set(chunk.subarray(0, toCopy), offset);
    offset += toCopy;
  }
  return result;
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

/**
 * F4Jumble: encode raw bytes for unified address/viewing key encoding.
 * Input must be between 48 and 4194368 bytes.
 */
export function f4jumble(message: Uint8Array): Uint8Array {
  const l = message.length;
  if (l < 48 || l > 4194368) {
    throw new Error(`F4Jumble: invalid message length ${l}, must be in [48, 4194368]`);
  }

  const leftLen = Math.min(Math.floor(l / 2), 64);
  let a = message.slice(0, leftLen);
  let b = message.slice(leftLen);
  const rightLen = l - leftLen;

  b = xor(b, h(0, a, rightLen));
  a = xor(a, g(0, b).subarray(0, leftLen));
  b = xor(b, h(1, a, rightLen));
  a = xor(a, g(1, b).subarray(0, leftLen));

  const result = new Uint8Array(l);
  result.set(a, 0);
  result.set(b, leftLen);
  return result;
}

/**
 * F4Jumble inverse: decode unified address/viewing key bytes.
 */
export function f4jumbleInv(jumbled: Uint8Array): Uint8Array {
  const l = jumbled.length;
  if (l < 48 || l > 4194368) {
    throw new Error(`F4Jumble: invalid message length ${l}, must be in [48, 4194368]`);
  }

  const leftLen = Math.min(Math.floor(l / 2), 64);
  let a = jumbled.slice(0, leftLen);
  let b = jumbled.slice(leftLen);
  const rightLen = l - leftLen;

  a = xor(a, g(1, b).subarray(0, leftLen));
  b = xor(b, h(1, a, rightLen));
  a = xor(a, g(0, b).subarray(0, leftLen));
  b = xor(b, h(0, a, rightLen));

  const result = new Uint8Array(l);
  result.set(a, 0);
  result.set(b, leftLen);
  return result;
}

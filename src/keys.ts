/**
 * Orchard key derivation: SpendingKey → FullViewingKey → IncomingViewingKey → Address
 */
import { blake2b } from '@noble/hashes/blake2.js';
import {
  PallasPoint,
  type PallasPointType,
  Fp,
  Fr,
  Fp_ORDER,
  Fr_ORDER,
  hashToCurve,
  pointToBytes,
  fpToBytes,
  frToBytes,
} from './pallas.js';
import { sinsemillaShortCommit, fieldElementToBits } from './sinsemilla.js';
import { deriveOrchardSpendingKeyFromSeed } from './zip32.js';

// SpendAuth generator: hash_to_curve("z.cash:Orchard")("G"), NOT the standard Pallas base point
const SPEND_AUTH_GEN = hashToCurve('z.cash:Orchard')(new TextEncoder().encode('G'));

// PRF^expand(sk, t) = BLAKE2b-512(personal="Zcash_ExpandSeed", msg=sk || t)
// Note: sk goes into the MESSAGE, NOT as the BLAKE2b key parameter.
const EXPAND_SEED_PERSONAL = new TextEncoder().encode('Zcash_ExpandSeed');

function prfExpand(sk: Uint8Array, t: Uint8Array): Uint8Array {
  const msg = new Uint8Array(sk.length + t.length);
  msg.set(sk, 0);
  msg.set(t, sk.length);
  return blake2b(msg, { dkLen: 64, personalization: EXPAND_SEED_PERSONAL });
}

// Interpret 64 bytes as LE integer, reduce mod n
function toScalar(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i]);
  }
  return ((n % Fr_ORDER) + Fr_ORDER) % Fr_ORDER;
}

// Interpret 64 bytes as LE integer, reduce mod p
function toBase(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i]);
  }
  return ((n % Fp_ORDER) + Fp_ORDER) % Fp_ORDER;
}

export interface OrchardSpendingKey {
  sk: Uint8Array;
}

export interface OrchardFullViewingKey {
  ak: PallasPointType; // SpendValidatingKey (point)
  nk: bigint; // NullifierDerivingKey (base field element)
  rivk: bigint; // CommitIvkRandomness (scalar)
}

export interface OrchardIncomingViewingKey {
  ivk: bigint; // scalar
}

export interface OrchardAddress {
  d: Uint8Array; // 11-byte diversifier
  pkd: PallasPointType; // diversified transmission key (point)
}

/**
 * Derive Orchard spending key components from a raw 32-byte spending key.
 */
export function orchardSpendingKeyComponents(sk: Uint8Array): {
  ask: bigint;
  nk: bigint;
  rivk: bigint;
} {
  const ask = toScalar(prfExpand(sk, new Uint8Array([0x06])));
  if (ask === 0n) throw new Error('Invalid spending key: ask is zero');

  const nk = toBase(prfExpand(sk, new Uint8Array([0x07])));
  const rivk = toScalar(prfExpand(sk, new Uint8Array([0x08])));
  if (rivk === 0n) throw new Error('Invalid spending key: rivk is zero');

  return { ask, nk, rivk };
}

/**
 * Derive Orchard FullViewingKey from a spending key.
 */
export function deriveOrchardFVK(sk: Uint8Array): OrchardFullViewingKey {
  const { ask, nk, rivk } = orchardSpendingKeyComponents(sk);
  // reddsa VerificationKey = -[ask] * SpendAuthGen (negated per RedDSA convention)
  const ak = SPEND_AUTH_GEN.multiply(ask).negate();
  return { ak, nk, rivk };
}

/**
 * Derive the internal rivk for change outputs (Scope::Internal).
 * rivk_internal = ToScalar(PRF^expand(rivk, [0x83] || repr(ak) || repr(nk)))
 */
function deriveInternalRivk(fvk: OrchardFullViewingKey): bigint {
  const rivkBytes = frToBytes(fvk.rivk);
  const akBytes = pointToBytes(fvk.ak);
  const nkBytes = fpToBytes(fvk.nk);
  const msg = new Uint8Array(1 + 32 + 32);
  msg[0] = 0x83;
  msg.set(akBytes, 1);
  msg.set(nkBytes, 33);
  return toScalar(prfExpand(rivkBytes, msg));
}

function commitIvk(fvk: OrchardFullViewingKey, rivk: bigint): bigint {
  const akBytes = pointToBytes(fvk.ak);
  const nkBytes = fpToBytes(fvk.nk);

  // Message = ak_repr bits (255) || nk_repr bits (255) = 510 bits
  const akBits = fieldElementToBits(akBytes);
  const nkBits = fieldElementToBits(nkBytes);
  const messageBits = [...akBits, ...nkBits];

  const ivkBase = sinsemillaShortCommit(
    'z.cash:Orchard-CommitIvk',
    messageBits,
    rivk
  );

  return ivkBase % Fr_ORDER;
}

/**
 * Derive Orchard IncomingViewingKey from a FullViewingKey.
 * @param scope - 'external' for receiving addresses, 'internal' for change outputs
 */
export function deriveOrchardIVK(
  fvk: OrchardFullViewingKey,
  scope: 'external' | 'internal' = 'external'
): OrchardIncomingViewingKey {
  const rivk = scope === 'external' ? fvk.rivk : deriveInternalRivk(fvk);
  const ivk = commitIvk(fvk, rivk);
  if (ivk === 0n) throw new Error('Invalid IVK: zero');
  return { ivk };
}

/**
 * Derive an Orchard address at the given diversifier index.
 */
export function deriveOrchardAddress(
  ivk: OrchardIncomingViewingKey,
  diversifierIndex: bigint
): OrchardAddress {
  // Diversifier is 11 bytes (little-endian encoding of diversifier index)
  const d = new Uint8Array(11);
  let idx = diversifierIndex;
  for (let i = 0; i < 11; i++) {
    d[i] = Number(idx & 0xffn);
    idx >>= 8n;
  }

  // g_d = DiversifyHash(d) = GroupHash^P("z.cash:Orchard-gd", d)
  const diversifyHash = hashToCurve('z.cash:Orchard-gd');
  const gd = diversifyHash(d);

  // pk_d = [ivk] * g_d
  const pkd = gd.multiply(ivk.ivk);

  return { d, pkd };
}

/**
 * Encode an Orchard address as raw bytes (43 bytes: 11-byte diversifier + 32-byte pk_d).
 */
export function orchardAddressToBytes(addr: OrchardAddress): Uint8Array {
  const pkdBytes = pointToBytes(addr.pkd);
  const result = new Uint8Array(43);
  result.set(addr.d, 0);
  result.set(pkdBytes, 11);
  return result;
}

// --- High-level API ---

export type Network = 'main' | 'test';

function coinType(network: Network): number {
  return network === 'main' ? 133 : 1;
}

/**
 * Derive a complete set of Orchard keys from a BIP-39 seed.
 */
export function deriveOrchardKeys(
  seed: Uint8Array,
  network: Network,
  account: number
): {
  spendingKey: Uint8Array;
  fullViewingKey: OrchardFullViewingKey;
  incomingViewingKey: OrchardIncomingViewingKey;
} {
  const sk = deriveOrchardSpendingKeyFromSeed(seed, coinType(network), account);
  const fvk = deriveOrchardFVK(sk);
  const ivk = deriveOrchardIVK(fvk);
  return { spendingKey: sk, fullViewingKey: fvk, incomingViewingKey: ivk };
}

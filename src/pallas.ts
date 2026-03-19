/**
 * Pallas curve definition and hash-to-curve for Zcash Orchard.
 *
 * Pallas: y² = x³ + 5 over Fp
 * Used for Orchard shielded transactions in Zcash.
 */
import { weierstrass, mapToCurveSimpleSWU } from '@noble/curves/abstract/weierstrass.js';
import { Field } from '@noble/curves/abstract/modular.js';
import { isogenyMap, createHasher } from '@noble/curves/abstract/hash-to-curve.js';
import { blake2b } from '@noble/hashes/blake2.js';

// Pallas base field prime
export const Fp_ORDER = BigInt(
  '0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001'
);
// Pallas scalar field order
export const Fr_ORDER = BigInt(
  '0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001'
);

export const Fp = Field(Fp_ORDER, { isLE: true });
export const Fr = Field(Fr_ORDER, { isLE: true });

// Pallas curve: y² = x³ + 5, generator = (-1, 2)
export const PallasPoint = weierstrass(
  {
    p: Fp_ORDER,
    n: Fr_ORDER,
    h: 1n,
    a: 0n,
    b: 5n,
    Gx: Fp_ORDER - 1n, // -1 mod p
    Gy: 2n,
  },
  { Fp }
);

export type PallasPointType = InstanceType<typeof PallasPoint>;

// --- iso-Pallas parameters for hash-to-curve (SWU map + 3-isogeny) ---

const ISO_A = BigInt(
  '0x18354a2eb0ea8c9c49be2d7258370742b74134581a27a59f92bb4b0b657a014b'
);
const ISO_B = 1265n;
const ISO_Z = Fp.neg(13n); // Z = -13 mod p

// 3-isogeny map coefficients from iso-Pallas to Pallas
// Ascending degree order: [c_0, c_1, ..., c_n] (noble-curves reverses them for Horner)
const ISO_XNUM = [
  BigInt('0x1c71c71c71c71c71c71c71c71c71c71c8102eea8e7b06eb6eebec06955555580'), // x^0
  BigInt('0x17329b9ec525375398c7d7ac3d98fd13380af066cfeb6d690eb64faef37ea4f7'), // x^1
  BigInt('0x3509afd51872d88e267c7ffa51cf412a0f93b82ee4b994958cf863b02814fb76'), // x^2
  BigInt('0x0e38e38e38e38e38e38e38e38e38e38e4081775473d8375b775f6034aaaaaaab'), // x^3
];
const ISO_XDEN = [
  BigInt('0x325669becaecd5d11d13bf2a7f22b105b4abf9fb9a1fc81c2aa3af1eae5b6604'), // x^0
  BigInt('0x1d572e7ddc099cff5a607fcce0494a799c434ac1c96b6980c47f2ab668bcd71f'), // x^1
  1n, // x^2
];
const ISO_YNUM = [
  BigInt('0x025ed097b425ed097b425ed097b425ed0ac03e8e134eb3e493e53ab371c71c4f'), // x^0
  BigInt('0x3fb98ff0d2ddcadd303216cce1db9ff11765e924f745937802e2be87d225b234'), // x^1
  BigInt('0x1a84d7ea8c396c47133e3ffd28e7a09507c9dc17725cca4ac67c31d8140a7dbb'), // x^2
  BigInt('0x1a12f684bda12f684bda12f684bda12f7642b01ad461bad25ad985b5e38e38e4'), // x^3
];
const ISO_YDEN = [
  Fp_ORDER - 540n, // x^0 (-540 mod p)
  BigInt('0x17033d3c60c68173573b3d7f7d681310d976bbfabbc5661d4d90ab820b12320a'), // x^1
  BigInt('0x0c02c5bcca0e6b7f0790bfb3506defb65941a3a4a97aa1b35a28279b1d1b42ae'), // x^2
  1n, // x^3
];

const isoMapPallas = isogenyMap(Fp, [ISO_XNUM, ISO_XDEN, ISO_YNUM, ISO_YDEN]);
const swuMapIsoPallas = mapToCurveSimpleSWU(Fp, { A: ISO_A, B: ISO_B, Z: ISO_Z });

const pallasHasher = createHasher(
  PallasPoint,
  (scalars: bigint[]) => {
    const { x, y } = swuMapIsoPallas(scalars[0]);
    return isoMapPallas(x, y);
  },
  {
    DST: 'z.cash:test-pallas_XMD:BLAKE2b_SSWU_RO_', // default, overridden per call
    p: Fp_ORDER,
    m: 1,
    k: 128,
    expand: 'xmd',
    hash: blake2b,
  }
);

/**
 * Hash to a Pallas curve point using the Zcash hash-to-curve suite.
 * DST = `${domainPrefix}-pallas_XMD:BLAKE2b_SSWU_RO_`
 */
export function hashToCurve(domainPrefix: string): (msg: Uint8Array) => PallasPointType {
  const DST = `${domainPrefix}-pallas_XMD:BLAKE2b_SSWU_RO_`;
  return (msg: Uint8Array) => pallasHasher.hashToCurve(msg, { DST });
}

// --- Pallas point serialization (Zcash convention: 32-byte LE x + sign bit) ---

export function pointToBytes(point: PallasPointType): Uint8Array {
  if (point.equals(PallasPoint.ZERO)) {
    return new Uint8Array(32);
  }
  const { x, y } = point.toAffine();
  const bytes = Fp.toBytes(x);
  if (Fp.isOdd!(y)) {
    bytes[31] |= 0x80;
  }
  return bytes;
}

export function pointFromBytes(bytes: Uint8Array): PallasPointType {
  if (bytes.length !== 32) throw new Error('Point must be 32 bytes');
  if (bytes.every((b) => b === 0)) return PallasPoint.ZERO;

  const tmp = new Uint8Array(bytes);
  const signBit = (tmp[31] >> 7) & 1;
  tmp[31] &= 0x7f;
  const x = Fp.fromBytes(tmp);

  // y² = x³ + 5
  const y2 = Fp.add(Fp.pow(x, 3n), 5n);
  let y = Fp.sqrt(y2);
  if (Fp.isOdd!(y) !== (signBit === 1)) {
    y = Fp.neg(y);
  }
  return PallasPoint.fromAffine({ x, y });
}

// --- Utility: encode field element / scalar to 32-byte LE ---

export function fpToBytes(n: bigint): Uint8Array {
  return Fp.toBytes(n);
}

export function fpFromBytes(bytes: Uint8Array): bigint {
  return Fp.fromBytes(bytes);
}

export function frToBytes(n: bigint): Uint8Array {
  return Fr.toBytes(n);
}

export function frFromBytes(bytes: Uint8Array): bigint {
  return Fr.fromBytes(bytes);
}

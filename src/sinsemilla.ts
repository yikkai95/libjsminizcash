/**
 * Sinsemilla hash function for Zcash Orchard.
 * Used for commit_ivk and other commitments.
 */
import { PallasPoint, type PallasPointType, hashToCurve, Fp } from './pallas.js';

// Cache for Sinsemilla S table (1024 precomputed points, lazily computed)
const sTableCache = new Map<number, PallasPointType>();
const sHasher = hashToCurve('z.cash:SinsemillaS');

function getS(i: number): PallasPointType {
  let point = sTableCache.get(i);
  if (!point) {
    const buf = new Uint8Array(4);
    buf[0] = i & 0xff;
    buf[1] = (i >> 8) & 0xff;
    buf[2] = (i >> 16) & 0xff;
    buf[3] = (i >> 24) & 0xff;
    point = sHasher(buf);
    sTableCache.set(i, point);
  }
  return point;
}

/**
 * SinsemillaHash(D, M) where D is the domain separator and M is a bit array.
 * M must have length that is a multiple of 10.
 */
export function sinsemillaHash(
  domain: string,
  messageBits: boolean[]
): PallasPointType {
  if (messageBits.length % 10 !== 0) {
    throw new Error(`Sinsemilla message length must be multiple of 10, got ${messageBits.length}`);
  }

  const domainBytes = new TextEncoder().encode(domain);
  const Q = hashToCurve('z.cash:SinsemillaQ')(domainBytes);

  let acc = Q;
  const n = messageBits.length / 10;

  for (let i = 0; i < n; i++) {
    // Extract 10-bit piece (little-endian)
    let m = 0;
    for (let j = 0; j < 10; j++) {
      if (messageBits[i * 10 + j]) {
        m |= 1 << j;
      }
    }
    const S_i = getS(m);
    // acc = (acc + S_i) + acc = 2*acc + S_i
    acc = acc.add(S_i).add(acc);
  }

  return acc;
}

/**
 * SinsemillaCommit_r(D, M) = SinsemillaHash(D, M) + [r] * R
 * where R = GroupHash^P("z.cash:SinsemillaQ", D || "-r" as bytes)
 * Wait — R uses a DST derived from D, not the same one as Q.
 * Actually: R = hash_to_curve("<D>-r")(empty_bytes)
 */
export function sinsemillaCommit(
  domain: string,
  messageBits: boolean[],
  r: bigint
): PallasPointType {
  // CommitDomain uses "{domain}-M" for the hash and "{domain}-r" for the blinding
  const hashPoint = sinsemillaHash(domain + '-M', messageBits);
  const R = hashToCurve(domain + '-r')(new Uint8Array(0));
  return hashPoint.add(R.multiply(r));
}

/**
 * SinsemillaShortCommit_r(D, M) = Extract_P(SinsemillaCommit_r(D, M))
 * Extract_P returns the x-coordinate of the point.
 */
export function sinsemillaShortCommit(
  domain: string,
  messageBits: boolean[],
  r: bigint
): bigint {
  const point = sinsemillaCommit(domain, messageBits, r);
  return point.toAffine().x;
}

/**
 * Convert a 32-byte LE field element to 255 bits (dropping the top bit).
 */
export function fieldElementToBits(bytes: Uint8Array): boolean[] {
  const bits: boolean[] = [];
  for (let byteIdx = 0; byteIdx < 32; byteIdx++) {
    for (let bitIdx = 0; bitIdx < 8; bitIdx++) {
      bits.push(((bytes[byteIdx] >> bitIdx) & 1) === 1);
    }
  }
  // Return only 255 bits (drop the highest bit)
  return bits.slice(0, 255);
}

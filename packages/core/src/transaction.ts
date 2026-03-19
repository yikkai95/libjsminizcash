/**
 * Zcash v5 transaction parser (ZIP-225).
 * Extracts Orchard actions for decryption.
 */

export interface OrchardAction {
  cv: Uint8Array;           // 32 bytes - value commitment
  nullifier: Uint8Array;    // 32 bytes
  rk: Uint8Array;           // 32 bytes - randomized verification key
  cmx: Uint8Array;          // 32 bytes - extracted note commitment
  ephemeralKey: Uint8Array; // 32 bytes
  encCiphertext: Uint8Array; // 580 bytes
  outCiphertext: Uint8Array; // 80 bytes
}

export interface TransparentInput {
  prevoutHash: Uint8Array;
  prevoutIndex: number;
  scriptSig: Uint8Array;
  sequence: number;
}

export interface TransparentOutput {
  value: bigint; // zatoshis
  scriptPubKey: Uint8Array;
}

export interface ZcashTransaction {
  version: number;
  versionGroupId: number;
  consensusBranchId: number;
  lockTime: number;
  expiryHeight: number;
  transparentInputs: TransparentInput[];
  transparentOutputs: TransparentOutput[];
  nSpendsSapling: number;
  nOutputsSapling: number;
  orchardActions: OrchardAction[];
  orchardFlags: number;
  orchardValueBalance: bigint;
}

class Reader {
  private offset = 0;
  constructor(private data: Uint8Array) {}

  get remaining(): number {
    return this.data.length - this.offset;
  }

  readBytes(n: number): Uint8Array {
    if (this.offset + n > this.data.length) {
      throw new Error(`Read past end: need ${n} bytes at offset ${this.offset}, have ${this.data.length}`);
    }
    const result = this.data.slice(this.offset, this.offset + n);
    this.offset += n;
    return result;
  }

  readU8(): number {
    return this.readBytes(1)[0];
  }

  readU32LE(): number {
    const b = this.readBytes(4);
    return b[0] | (b[1] << 8) | (b[2] << 16) | ((b[3] << 24) >>> 0);
  }

  readI32LE(): number {
    return this.readU32LE() | 0;
  }

  readI64LE(): bigint {
    const b = this.readBytes(8);
    let n = 0n;
    for (let i = 7; i >= 0; i--) n = (n << 8n) | BigInt(b[i]);
    // Interpret as signed
    if (n >= 0x8000000000000000n) n -= 0x10000000000000000n;
    return n;
  }

  readCompactSize(): number {
    const first = this.readU8();
    if (first < 0xfd) return first;
    if (first === 0xfd) {
      const b = this.readBytes(2);
      return b[0] | (b[1] << 8);
    }
    if (first === 0xfe) return this.readU32LE();
    throw new Error('CompactSize > 32-bit not supported');
  }
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Parse a Zcash v5 transaction from raw hex.
 */
export function parseTransaction(rawHex: string): ZcashTransaction {
  const r = new Reader(hexToBytes(rawHex));

  // Header
  const header = r.readI32LE();
  const version = header & 0x7fffffff;
  const overwintered = (header & 0x80000000) !== 0;
  if (version !== 5 || !overwintered) {
    throw new Error(`Expected v5 overwintered transaction, got version=${version} overwintered=${overwintered}`);
  }

  const versionGroupId = r.readU32LE();
  const consensusBranchId = r.readU32LE();
  const lockTime = r.readU32LE();
  const expiryHeight = r.readU32LE();

  // Transparent inputs
  const nTxIn = r.readCompactSize();
  const transparentInputs: TransparentInput[] = [];
  for (let i = 0; i < nTxIn; i++) {
    const prevoutHash = r.readBytes(32);
    const prevoutIndex = r.readU32LE();
    const scriptSigLen = r.readCompactSize();
    const scriptSig = r.readBytes(scriptSigLen);
    const sequence = r.readU32LE();
    transparentInputs.push({ prevoutHash, prevoutIndex, scriptSig, sequence });
  }

  // Transparent outputs
  const nTxOut = r.readCompactSize();
  const transparentOutputs: TransparentOutput[] = [];
  for (let i = 0; i < nTxOut; i++) {
    const value = r.readI64LE();
    const scriptPubKeyLen = r.readCompactSize();
    const scriptPubKey = r.readBytes(scriptPubKeyLen);
    transparentOutputs.push({ value, scriptPubKey });
  }

  // Sapling spends
  const nSpendsSapling = r.readCompactSize();
  for (let i = 0; i < nSpendsSapling; i++) {
    r.readBytes(32); // cv
    r.readBytes(32); // nullifier
    r.readBytes(32); // rk
  }

  // Sapling outputs
  const nOutputsSapling = r.readCompactSize();
  for (let i = 0; i < nOutputsSapling; i++) {
    r.readBytes(32);  // cv
    r.readBytes(32);  // cmu
    r.readBytes(32);  // ephemeralKey
    r.readBytes(580); // encCiphertext
    r.readBytes(80);  // outCiphertext
  }

  // Sapling trailing data (if any spends or outputs)
  if (nSpendsSapling + nOutputsSapling > 0) {
    r.readBytes(8);  // valueBalanceSapling
    if (nSpendsSapling > 0) {
      r.readBytes(32); // anchorSapling
    }
    for (let i = 0; i < nSpendsSapling; i++) r.readBytes(192); // spendProofs
    for (let i = 0; i < nSpendsSapling; i++) r.readBytes(64);  // spendAuthSigs
    for (let i = 0; i < nOutputsSapling; i++) r.readBytes(192); // outputProofs
    r.readBytes(64); // bindingSigSapling
  }

  // Orchard actions
  const nActionsOrchard = r.readCompactSize();
  const orchardActions: OrchardAction[] = [];
  for (let i = 0; i < nActionsOrchard; i++) {
    const cv = r.readBytes(32);
    const nullifier = r.readBytes(32);
    const rk = r.readBytes(32);
    const cmx = r.readBytes(32);
    const ephemeralKey = r.readBytes(32);
    const encCiphertext = r.readBytes(580);
    const outCiphertext = r.readBytes(80);
    orchardActions.push({ cv, nullifier, rk, cmx, ephemeralKey, encCiphertext, outCiphertext });
  }

  let orchardFlags = 0;
  let orchardValueBalance = 0n;
  if (nActionsOrchard > 0) {
    orchardFlags = r.readU8();
    orchardValueBalance = r.readI64LE();
    r.readBytes(32); // anchorOrchard
    const sizeProofs = r.readCompactSize();
    r.readBytes(sizeProofs); // proofsOrchard
    for (let i = 0; i < nActionsOrchard; i++) r.readBytes(64); // spendAuthSigs
    r.readBytes(64); // bindingSigOrchard
  }

  return {
    version,
    versionGroupId,
    consensusBranchId,
    lockTime,
    expiryHeight,
    transparentInputs,
    transparentOutputs,
    nSpendsSapling,
    nOutputsSapling,
    orchardActions,
    orchardFlags,
    orchardValueBalance,
  };
}

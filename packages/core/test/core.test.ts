import { describe, it, expect } from 'vitest';
import {
  generateMnemonic,
  mnemonicToSeed,
  isValidMnemonic,
  deriveOrchardSpendingKeyFromSeed,
  deriveOrchardFVK,
  deriveOrchardIVK,
  deriveOrchardAddress,
  deriveOrchardKeys,
  orchardAddressToBytes,
  encodeUnifiedAddress,
  encodeUnifiedFVK,
} from '../src/index.js';
import { f4jumble, f4jumbleInv } from '../src/f4jumble.js';
import { deriveTransparentAddress } from '../src/transparent.js';

describe('Mnemonic', () => {
  it('generates a valid 24-word mnemonic', () => {
    const mnemonic = generateMnemonic(256);
    const words = mnemonic.split(' ');
    expect(words.length).toBe(24);
    expect(isValidMnemonic(mnemonic)).toBe(true);
  });

  it('generates a valid 12-word mnemonic', () => {
    const mnemonic = generateMnemonic(128);
    const words = mnemonic.split(' ');
    expect(words.length).toBe(12);
    expect(isValidMnemonic(mnemonic)).toBe(true);
  });

  it('converts mnemonic to 64-byte seed', () => {
    const mnemonic = generateMnemonic();
    const seed = mnemonicToSeed(mnemonic);
    expect(seed.length).toBe(64);
  });

  it('validates mnemonic correctly', () => {
    expect(isValidMnemonic('invalid mnemonic phrase here')).toBe(false);
  });

  it('produces deterministic seed from same mnemonic', () => {
    const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    const seed1 = mnemonicToSeed(mnemonic);
    const seed2 = mnemonicToSeed(mnemonic);
    expect(Buffer.from(seed1).toString('hex')).toBe(Buffer.from(seed2).toString('hex'));
  });
});

describe('ZIP-32 Key Derivation', () => {
  const testMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const seed = mnemonicToSeed(testMnemonic);

  it('derives a 32-byte spending key', () => {
    const sk = deriveOrchardSpendingKeyFromSeed(seed, 133, 0);
    expect(sk.length).toBe(32);
  });

  it('derives different keys for different accounts', () => {
    const sk0 = deriveOrchardSpendingKeyFromSeed(seed, 133, 0);
    const sk1 = deriveOrchardSpendingKeyFromSeed(seed, 133, 1);
    expect(Buffer.from(sk0).toString('hex')).not.toBe(Buffer.from(sk1).toString('hex'));
  });

  it('derives different keys for mainnet vs testnet', () => {
    const skMain = deriveOrchardSpendingKeyFromSeed(seed, 133, 0);
    const skTest = deriveOrchardSpendingKeyFromSeed(seed, 1, 0);
    expect(Buffer.from(skMain).toString('hex')).not.toBe(Buffer.from(skTest).toString('hex'));
  });

  it('throws on short seed', () => {
    expect(() => deriveOrchardSpendingKeyFromSeed(new Uint8Array(16), 133, 0)).toThrow();
  });
});

describe('Orchard Key Derivation', () => {
  const testMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const seed = mnemonicToSeed(testMnemonic);
  const sk = deriveOrchardSpendingKeyFromSeed(seed, 133, 0);

  it('derives FullViewingKey from spending key', () => {
    const fvk = deriveOrchardFVK(sk);
    expect(fvk.ak).toBeDefined();
    expect(typeof fvk.nk).toBe('bigint');
    expect(typeof fvk.rivk).toBe('bigint');
    expect(fvk.nk > 0n).toBe(true);
    expect(fvk.rivk > 0n).toBe(true);
  });

  it('derives IncomingViewingKey from FVK', () => {
    const fvk = deriveOrchardFVK(sk);
    const ivk = deriveOrchardIVK(fvk);
    expect(typeof ivk.ivk).toBe('bigint');
    expect(ivk.ivk > 0n).toBe(true);
  });

  it('derives an Orchard address', () => {
    const fvk = deriveOrchardFVK(sk);
    const ivk = deriveOrchardIVK(fvk);
    const address = deriveOrchardAddress(ivk, 0n);
    expect(address.d.length).toBe(11);
    expect(address.pkd).toBeDefined();
  });

  it('derives different addresses for different diversifier indices', () => {
    const fvk = deriveOrchardFVK(sk);
    const ivk = deriveOrchardIVK(fvk);
    const addr0 = orchardAddressToBytes(deriveOrchardAddress(ivk, 0n));
    const addr1 = orchardAddressToBytes(deriveOrchardAddress(ivk, 1n));
    expect(Buffer.from(addr0).toString('hex')).not.toBe(Buffer.from(addr1).toString('hex'));
  });

  it('address is 43 bytes (11-byte diversifier + 32-byte pk_d)', () => {
    const fvk = deriveOrchardFVK(sk);
    const ivk = deriveOrchardIVK(fvk);
    const address = deriveOrchardAddress(ivk, 0n);
    const bytes = orchardAddressToBytes(address);
    expect(bytes.length).toBe(43);
  });
});

describe('F4Jumble', () => {
  it('roundtrips correctly', () => {
    // Create a test message of appropriate length (>= 48 bytes)
    const msg = new Uint8Array(64);
    for (let i = 0; i < msg.length; i++) msg[i] = i & 0xff;
    const jumbled = f4jumble(msg);
    const recovered = f4jumbleInv(jumbled);
    expect(Buffer.from(recovered).toString('hex')).toBe(Buffer.from(msg).toString('hex'));
  });

  it('rejects messages shorter than 48 bytes', () => {
    expect(() => f4jumble(new Uint8Array(47))).toThrow();
  });

  it('produces different output from input', () => {
    const msg = new Uint8Array(64).fill(0x42);
    const jumbled = f4jumble(msg);
    expect(Buffer.from(jumbled).toString('hex')).not.toBe(Buffer.from(msg).toString('hex'));
  });
});

describe('Unified Encoding', () => {
  const testMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const seed = mnemonicToSeed(testMnemonic);

  it('encodes a unified address starting with "u1"', () => {
    const keys = deriveOrchardKeys(seed, 'main', 0);
    const address = deriveOrchardAddress(keys.incomingViewingKey, 0n);
    const ua = encodeUnifiedAddress(address, 'main');
    expect(ua.startsWith('u1')).toBe(true);
  });

  it('encodes a testnet unified address starting with "utest1"', () => {
    const keys = deriveOrchardKeys(seed, 'test', 0);
    const address = deriveOrchardAddress(keys.incomingViewingKey, 0n);
    const ua = encodeUnifiedAddress(address, 'test');
    expect(ua.startsWith('utest1')).toBe(true);
  });

  it('encodes a unified FVK starting with "uview1"', () => {
    const keys = deriveOrchardKeys(seed, 'main', 0);
    const ufvk = encodeUnifiedFVK(keys.fullViewingKey, 'main');
    expect(ufvk.startsWith('uview1')).toBe(true);
  });

  it('encodes a testnet unified FVK starting with "uviewtest1"', () => {
    const keys = deriveOrchardKeys(seed, 'test', 0);
    const ufvk = encodeUnifiedFVK(keys.fullViewingKey, 'test');
    expect(ufvk.startsWith('uviewtest1')).toBe(true);
  });
});

describe('Transparent Address', () => {
  const testMnemonic = 'card critic peace wonder sausage afraid uncle nominee oval prevent life dust photo purpose forget total child eager clean network whip trap rose vintage';
  const seed = mnemonicToSeed(testMnemonic);

  it('derives a mainnet t1 address', () => {
    const result = deriveTransparentAddress(seed, 'main', 0, 0);
    expect(result.address.startsWith('t1')).toBe(true);
    expect(result.publicKey.length).toBe(33);
    expect(result.privateKey.length).toBe(32);
  });

  it('derives a testnet tm address', () => {
    const result = deriveTransparentAddress(seed, 'test', 0, 0);
    expect(result.address.startsWith('tm')).toBe(true);
  });

  it('derives deterministic t-address from known mnemonic', () => {
    const r1 = deriveTransparentAddress(seed, 'main', 0, 0);
    const r2 = deriveTransparentAddress(seed, 'main', 0, 0);
    expect(r1.address).toBe(r2.address);
    expect(r1.address).toBe('t1aqyTy1fCpWiQ8SESwT7XQN7KzprNC89kg');
  });

  it('derives different addresses for different indices', () => {
    const r0 = deriveTransparentAddress(seed, 'main', 0, 0);
    const r1 = deriveTransparentAddress(seed, 'main', 0, 1);
    expect(r0.address).not.toBe(r1.address);
  });
});

describe('Full Pipeline', () => {
  it('generates mnemonic → seed → USK → UFVK → address → unified address', () => {
    const mnemonic = generateMnemonic();
    const seed = mnemonicToSeed(mnemonic);
    const keys = deriveOrchardKeys(seed, 'main', 0);
    const address = deriveOrchardAddress(keys.incomingViewingKey, 0n);
    const ua = encodeUnifiedAddress(address, 'main');
    const ufvk = encodeUnifiedFVK(keys.fullViewingKey, 'main');

    expect(ua.startsWith('u1')).toBe(true);
    expect(ufvk.startsWith('uview1')).toBe(true);
    expect(ua.length).toBeGreaterThan(10);
    expect(ufvk.length).toBeGreaterThan(10);

    console.log('Mnemonic:', mnemonic);
    console.log('Spending Key:', Buffer.from(keys.spendingKey).toString('hex'));
    console.log('Unified Address:', ua);
    console.log('Unified FVK:', ufvk);
  });

  it('deterministically derives the same keys from the same mnemonic', () => {
    const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    const seed = mnemonicToSeed(mnemonic);

    const keys1 = deriveOrchardKeys(seed, 'main', 0);
    const addr1 = deriveOrchardAddress(keys1.incomingViewingKey, 0n);
    const ua1 = encodeUnifiedAddress(addr1, 'main');

    const keys2 = deriveOrchardKeys(seed, 'main', 0);
    const addr2 = deriveOrchardAddress(keys2.incomingViewingKey, 0n);
    const ua2 = encodeUnifiedAddress(addr2, 'main');

    expect(ua1).toBe(ua2);
  });
});

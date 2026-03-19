/**
 * Zcash transparent (t-address) key derivation.
 * Uses BIP-44 path: m/44'/coin_type'/account'/scope/address_index
 * on the secp256k1 curve, identical to Bitcoin HD key derivation.
 */
import { HDKey } from '@scure/bip32';
import { sha256 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { base58check as createBase58check } from '@scure/base';
import type { Network } from './keys.js';

const base58check = createBase58check(sha256);

// BIP-44 path constants
const PURPOSE = 44;

function coinType(network: Network): number {
  return network === 'main' ? 133 : 1;
}

// Base58Check version prefixes for t-addresses
const P2PKH_PREFIX: Record<Network, [number, number]> = {
  main: [0x1c, 0xb8],
  test: [0x1d, 0x25],
};

/**
 * Hash160: RIPEMD-160(SHA-256(data))
 */
function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

/**
 * Derive a transparent private key from a BIP-39 seed.
 * Path: m/44'/coin_type'/account'/0/addressIndex
 */
export function deriveTransparentPrivateKey(
  seed: Uint8Array,
  network: Network,
  account: number,
  addressIndex: number = 0
): Uint8Array {
  const master = HDKey.fromMasterSeed(seed);
  const path = `m/44'/${coinType(network)}'/${account}'/0/${addressIndex}`;
  const child = master.derive(path);
  if (!child.privateKey) throw new Error('Failed to derive private key');
  return child.privateKey;
}

/**
 * Derive a transparent public key (compressed, 33 bytes) from a BIP-39 seed.
 */
export function deriveTransparentPublicKey(
  seed: Uint8Array,
  network: Network,
  account: number,
  addressIndex: number = 0
): Uint8Array {
  const master = HDKey.fromMasterSeed(seed);
  const path = `m/44'/${coinType(network)}'/${account}'/0/${addressIndex}`;
  const child = master.derive(path);
  if (!child.publicKey) throw new Error('Failed to derive public key');
  return child.publicKey;
}

/**
 * Encode a transparent P2PKH address from a compressed public key.
 */
export function encodeTransparentAddress(
  pubkey: Uint8Array,
  network: Network
): string {
  if (pubkey.length !== 33) throw new Error('Public key must be 33 bytes (compressed)');
  const pkHash = hash160(pubkey);
  const prefix = P2PKH_PREFIX[network];
  const payload = new Uint8Array(2 + 20);
  payload[0] = prefix[0];
  payload[1] = prefix[1];
  payload.set(pkHash, 2);
  return base58check.encode(payload);
}

/**
 * Derive a transparent address (t1... for mainnet, tm... for testnet) from a seed.
 */
export function deriveTransparentAddress(
  seed: Uint8Array,
  network: Network,
  account: number = 0,
  addressIndex: number = 0
): { address: string; publicKey: Uint8Array; privateKey: Uint8Array } {
  const master = HDKey.fromMasterSeed(seed);
  const path = `m/44'/${coinType(network)}'/${account}'/0/${addressIndex}`;
  const child = master.derive(path);
  if (!child.privateKey || !child.publicKey) throw new Error('Failed to derive key');
  const address = encodeTransparentAddress(child.publicKey, network);
  return { address, publicKey: child.publicKey, privateKey: child.privateKey };
}

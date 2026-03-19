/**
 * BIP-39 mnemonic generation and seed derivation.
 */
import { generateMnemonic as genMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

/**
 * Generate a new BIP-39 mnemonic phrase.
 * @param strength - Entropy bits: 128 (12 words), 160 (15 words), 192 (18 words), 224 (21 words), 256 (24 words)
 */
export function generateMnemonic(strength: 128 | 160 | 192 | 224 | 256 = 256): string {
  return genMnemonic(wordlist, strength);
}

/**
 * Convert a BIP-39 mnemonic to a 64-byte seed.
 * @param mnemonic - BIP-39 mnemonic phrase
 * @param passphrase - Optional passphrase (default: empty string)
 */
export function mnemonicToSeed(mnemonic: string, passphrase: string = ''): Uint8Array {
  return mnemonicToSeedSync(mnemonic, passphrase);
}

/**
 * Validate a BIP-39 mnemonic phrase.
 */
export function isValidMnemonic(mnemonic: string): boolean {
  return validateMnemonic(mnemonic, wordlist);
}

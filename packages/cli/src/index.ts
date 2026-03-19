#!/usr/bin/env node
import {
  generateMnemonic,
  mnemonicToSeed,
  isValidMnemonic,
  deriveOrchardKeys,
  deriveOrchardAddress,
  orchardAddressToBytes,
  encodeUnifiedAddress,
  encodeUnifiedFVK,
  type Network,
} from '@zcash-ts/core';
import { deriveTransparentAddress } from '@zcash-ts/core';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function usage() {
  console.log(`
zcash-keys — Zcash key derivation CLI

Usage:
  zcash-keys generate [--words 12|24] [--network main|test] [--account N]
  zcash-keys import <mnemonic> [--network main|test] [--account N]

Options:
  --words    Number of mnemonic words (default: 24)
  --network  main or test (default: main)
  --account  Account index (default: 0)
`);
}

function parseArgs(args: string[]): {
  command: string;
  mnemonic?: string;
  words: 128 | 256;
  network: Network;
  account: number;
} {
  const command = args[0] || 'help';
  let mnemonic: string | undefined;
  let words: 128 | 256 = 256;
  let network: Network = 'main';
  let account = 0;

  if (command === 'import') {
    // Collect mnemonic words until we hit a flag
    const mnemonicWords: string[] = [];
    let i = 1;
    while (i < args.length && !args[i].startsWith('--')) {
      mnemonicWords.push(args[i]);
      i++;
    }
    mnemonic = mnemonicWords.join(' ');

    // Parse remaining flags
    while (i < args.length) {
      if (args[i] === '--network' && args[i + 1]) {
        network = args[i + 1] as Network;
        i += 2;
      } else if (args[i] === '--account' && args[i + 1]) {
        account = parseInt(args[i + 1], 10);
        i += 2;
      } else {
        i++;
      }
    }
  } else {
    for (let i = 1; i < args.length; i++) {
      if (args[i] === '--words' && args[i + 1]) {
        words = parseInt(args[i + 1], 10) === 12 ? 128 : 256;
        i++;
      } else if (args[i] === '--network' && args[i + 1]) {
        network = args[i + 1] as Network;
        i++;
      } else if (args[i] === '--account' && args[i + 1]) {
        account = parseInt(args[i + 1], 10);
        i++;
      }
    }
  }

  return { command, mnemonic, words, network, account };
}

function deriveAndPrint(mnemonic: string, network: Network, account: number) {
  const seed = mnemonicToSeed(mnemonic);

  console.log('=== Mnemonic ===');
  console.log(mnemonic);
  console.log(`\nNetwork: ${network === 'main' ? 'mainnet' : 'testnet'}, Account: ${account}`);
  console.log(`Seed: ${toHex(seed)}`);

  // Transparent address
  console.log('\n=== Transparent (t-address) ===');
  const tResult = deriveTransparentAddress(seed, network, account, 0);
  console.log(`Path:        m/44'/${network === 'main' ? 133 : 1}'/${account}'/0/0`);
  console.log(`Private Key: ${toHex(tResult.privateKey)}`);
  console.log(`Public Key:  ${toHex(tResult.publicKey)}`);
  console.log(`Address:     ${tResult.address}`);

  // Orchard keys
  console.log('\n=== Orchard (unified) ===');
  const orchardKeys = deriveOrchardKeys(seed, network, account);
  console.log(`Spending Key: ${toHex(orchardKeys.spendingKey)}`);

  const address = deriveOrchardAddress(orchardKeys.incomingViewingKey, 0n);
  const ua = encodeUnifiedAddress(address, network);
  const ufvk = encodeUnifiedFVK(orchardKeys.fullViewingKey, network);
  console.log(`Orchard Address (raw): ${toHex(orchardAddressToBytes(address))}`);
  console.log(`Unified Address: ${ua}`);
  console.log(`Unified FVK:     ${ufvk}`);
}

const args = process.argv.slice(2);
const parsed = parseArgs(args);

switch (parsed.command) {
  case 'generate': {
    const mnemonic = generateMnemonic(parsed.words);
    deriveAndPrint(mnemonic, parsed.network, parsed.account);
    break;
  }
  case 'import': {
    if (!parsed.mnemonic || !isValidMnemonic(parsed.mnemonic)) {
      console.error('Error: Invalid or missing mnemonic phrase');
      process.exit(1);
    }
    deriveAndPrint(parsed.mnemonic, parsed.network, parsed.account);
    break;
  }
  default:
    usage();
}

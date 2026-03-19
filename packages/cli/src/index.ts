#!/usr/bin/env node
import {
  generateMnemonic,
  mnemonicToSeed,
  isValidMnemonic,
  deriveOrchardSpendingKeyFromSeed,
  deriveOrchardKeys,
  deriveOrchardFVK,
  deriveOrchardIVK,
  deriveOrchardAddress,
  orchardAddressToBytes,
  encodeUnifiedAddress,
  encodeUnifiedFVK,
  deriveTransparentAddress,
  createRpc,
  parseTransaction,
  decryptTransaction,
  formatZec,
  pointToBytes,
  fpToBytes,
  frToBytes,
  type Network,
  type OrchardFullViewingKey,
  type OrchardIncomingViewingKey,
} from '@zcash-ts/core';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function env(key: string): string | undefined {
  return process.env[key];
}

function usage() {
  console.log(`
zcash-keys — Zcash key derivation & transaction CLI

Usage:
  zcash-keys generate    [--words 12|24] [--network main|test] [--account N]
  zcash-keys import      <mnemonic...> [--network main|test] [--account N]
  zcash-keys addresses   [--mnemonic <words...>] [--seed-hex <hex>] [--network main|test] [--account N]
  zcash-keys decode-tx   <txid> [--mnemonic <words...>] [--seed-hex <hex>] [--network main|test] [--account N]
  zcash-keys scan        --start <height> [--end <height>] [--mnemonic <words...>] [--seed-hex <hex>] [--network main|test] [--account N]

Options:
  --mnemonic     BIP-39 mnemonic phrase (produces 64-byte seed)
  --seed-hex     Raw seed hex (32+ bytes, e.g. from base64 decode)
  --network      main or test (default: main)
  --account      Account index (default: 0)
  --start/--end  Block range for scan

Environment variables (from .env):
  PASSPHRASE       Default mnemonic (used if --mnemonic/--seed-hex not provided)
  TATUM_URL        Zcash RPC endpoint
  TATUM_KEY        API key for the RPC endpoint
  BIRTHDAY_HEIGHT  Default start height for scan
`);
}

interface ParsedArgs {
  command: string;
  mnemonic?: string;
  seedHex?: string;
  words: 128 | 256;
  network: Network;
  account: number;
  txid?: string;
  startHeight?: number;
  endHeight?: number;
}

function parseArgs(args: string[]): ParsedArgs {
  const command = args[0] || 'help';
  let mnemonic: string | undefined;
  let seedHex: string | undefined;
  let words: 128 | 256 = 256;
  let network: Network = 'main';
  let account = 0;
  let txid: string | undefined;
  let startHeight: number | undefined;
  let endHeight: number | undefined;

  // For import: collect bare words as mnemonic
  if (command === 'import') {
    const mnemonicWords: string[] = [];
    let i = 1;
    while (i < args.length && !args[i].startsWith('--')) {
      mnemonicWords.push(args[i]);
      i++;
    }
    mnemonic = mnemonicWords.join(' ');
    args = args.slice(0, 1).concat(args.slice(i));
  }

  // For decode-tx: first non-flag arg after command is txid
  if (command === 'decode-tx' && args[1] && !args[1].startsWith('--')) {
    txid = args[1];
    args = [args[0], ...args.slice(2)];
  }

  // Parse flags
  for (let i = 1; i < args.length; i++) {
    const flag = args[i];
    const next = args[i + 1];
    switch (flag) {
      case '--words':
        words = parseInt(next, 10) === 12 ? 128 : 256;
        i++;
        break;
      case '--network':
        network = next as Network;
        i++;
        break;
      case '--account':
        account = parseInt(next, 10);
        i++;
        break;
      case '--start':
        startHeight = parseInt(next, 10);
        i++;
        break;
      case '--end':
        endHeight = parseInt(next, 10);
        i++;
        break;
      case '--seed-hex':
        seedHex = next;
        i++;
        break;
      case '--mnemonic': {
        const mnemonicWords: string[] = [];
        i++;
        while (i < args.length && !args[i].startsWith('--')) {
          mnemonicWords.push(args[i]);
          i++;
        }
        i--;
        mnemonic = mnemonicWords.join(' ');
        break;
      }
    }
  }

  // Fallback to env
  if (!mnemonic && !seedHex && command !== 'generate') {
    mnemonic = env('PASSPHRASE')?.replace(/^"|"$/g, '');
  }
  if (startHeight === undefined && command === 'scan') {
    const bh = env('BIRTHDAY_HEIGHT');
    if (bh) startHeight = parseInt(bh, 10);
  }

  return { command, mnemonic, seedHex, words, network, account, txid, startHeight, endHeight };
}

/** Resolve seed from --seed-hex, --mnemonic, or PASSPHRASE env */
function resolveSeed(parsed: ParsedArgs): Uint8Array {
  if (parsed.seedHex) {
    const seed = Buffer.from(parsed.seedHex, 'hex');
    if (seed.length < 32) {
      console.error('Error: --seed-hex must be at least 32 bytes');
      process.exit(1);
    }
    return seed;
  }
  if (parsed.mnemonic && isValidMnemonic(parsed.mnemonic)) {
    return mnemonicToSeed(parsed.mnemonic);
  }
  console.error('Error: provide --mnemonic, --seed-hex, or set PASSPHRASE in .env');
  process.exit(1);
}

function deriveKeys(seed: Uint8Array, network: Network, account: number) {
  const coinType = network === 'main' ? 133 : 1;
  const sk = deriveOrchardSpendingKeyFromSeed(seed, coinType, account);
  const fvk = deriveOrchardFVK(sk);
  const extIvk = deriveOrchardIVK(fvk, 'external');
  const intIvk = deriveOrchardIVK(fvk, 'internal');
  return { sk, fvk, extIvk, intIvk };
}

function getRpc() {
  const url = env('TATUM_URL') || 'https://zcash-mainnet.gateway.tatum.io/';
  const apiKey = env('TATUM_KEY');
  return createRpc({ url, apiKey });
}

/** Classify decrypted notes into incoming (external) and change (internal) */
function classifyNotes(notes: ReturnType<typeof decryptTransaction>) {
  const incoming = notes.filter((n) => n.scope === 'external');
  const change = notes.filter((n) => n.scope === 'internal');
  return { incoming, change };
}

/** Print a decoded transaction's notes with Incoming/Outgoing labels */
function printTxNotes(txid: string, notes: ReturnType<typeof decryptTransaction>) {
  const { incoming, change } = classifyNotes(notes);

  if (incoming.length > 0) {
    for (const n of incoming) {
      console.log(`  Incoming   +${formatZec(n.value)} ZEC`);
      if (n.memoText) console.log(`    Memo: ${n.memoText}`);
    }
  }
  if (change.length > 0) {
    const changeTotal = change.reduce((s, n) => s + n.value, 0n);
    if (incoming.length === 0) {
      console.log(`  Outgoing   (change: ${formatZec(changeTotal)} ZEC)`);
    } else {
      console.log(`  Change     ${formatZec(changeTotal)} ZEC`);
    }
  }
}

// === Commands ===

function cmdGenerate(parsed: ParsedArgs) {
  const mnemonic = generateMnemonic(parsed.words);
  cmdImport({ ...parsed, mnemonic });
}

function cmdImport(parsed: ParsedArgs) {
  const seed = resolveSeed(parsed);
  const { sk, fvk, extIvk, intIvk } = deriveKeys(seed, parsed.network, parsed.account);

  if (parsed.mnemonic) {
    console.log('=== Mnemonic ===');
    console.log(parsed.mnemonic);
  }
  if (parsed.seedHex) {
    console.log('=== Seed ===');
    console.log(parsed.seedHex);
  }
  console.log(`\nNetwork: ${parsed.network === 'main' ? 'mainnet' : 'testnet'}, Account: ${parsed.account}`);

  // Transparent (only from BIP-39 mnemonic seeds)
  if (!parsed.seedHex) {
    const tResult = deriveTransparentAddress(seed, parsed.network, parsed.account, 0);
    console.log('\n=== Transparent ===');
    console.log(`Private Key: ${toHex(tResult.privateKey)}`);
    console.log(`Public Key:  ${toHex(tResult.publicKey)}`);
    console.log(`Address:     ${tResult.address}`);
  }

  // Orchard keys
  console.log('\n=== Orchard Keys ===');
  console.log(`Spending Key:  ${toHex(sk)}`);
  console.log(`ak:            ${toHex(pointToBytes(fvk.ak))}`);
  console.log(`nk:            ${toHex(fpToBytes(fvk.nk))}`);
  console.log(`rivk:          ${toHex(frToBytes(fvk.rivk))}`);
  console.log(`External IVK:  ${extIvk.ivk.toString(16)}`);
  console.log(`Internal IVK:  ${intIvk.ivk.toString(16)}`);

  // Orchard addresses
  const ufvk = encodeUnifiedFVK(fvk, parsed.network);
  console.log('\n=== Orchard Addresses ===');
  console.log(`Unified FVK:     ${ufvk}`);
  for (let j = 0n; j <= 2n; j++) {
    const addr = deriveOrchardAddress(extIvk, j);
    const ua = encodeUnifiedAddress(addr, parsed.network);
    console.log(`Address [${j}]:     ${ua}`);
    if (j === 0n) console.log(`  raw:           ${toHex(orchardAddressToBytes(addr))}`);
  }
}

function cmdAddresses(parsed: ParsedArgs) {
  const seed = resolveSeed(parsed);
  const { extIvk } = deriveKeys(seed, parsed.network, parsed.account);
  const net = parsed.network === 'main' ? 'mainnet' : 'testnet';

  console.log(`Network: ${net}, Account: ${parsed.account}\n`);

  // Transparent (only from BIP-39 mnemonic seeds)
  if (!parsed.seedHex) {
    const tResult = deriveTransparentAddress(seed, parsed.network, parsed.account, 0);
    console.log(`Transparent:     ${tResult.address}`);
  }

  // Orchard unified addresses
  for (let j = 0n; j <= 4n; j++) {
    const addr = deriveOrchardAddress(extIvk, j);
    const ua = encodeUnifiedAddress(addr, parsed.network);
    console.log(`Unified [${j}]:     ${ua}`);
  }
}

async function cmdDecodeTx(parsed: ParsedArgs) {
  if (!parsed.txid) {
    console.error('Error: txid required. Usage: zcash-keys decode-tx <txid>');
    process.exit(1);
  }
  const seed = resolveSeed(parsed);
  const { extIvk, intIvk } = deriveKeys(seed, parsed.network, parsed.account);
  const rpc = getRpc();

  console.log(`Fetching tx ${parsed.txid}...`);
  const rawHex = await rpc.getRawTransaction(parsed.txid);
  const tx = parseTransaction(rawHex);

  console.log(`${tx.orchardActions.length} Orchard actions, ${tx.transparentInputs.length} t-in, ${tx.transparentOutputs.length} t-out\n`);

  const notes = decryptTransaction(tx.orchardActions, extIvk, intIvk);
  if (notes.length === 0) {
    console.log('No decryptable notes found for this wallet.');
  } else {
    printTxNotes(parsed.txid, notes);
  }
}

async function cmdScan(parsed: ParsedArgs) {
  const seed = resolveSeed(parsed);
  if (parsed.startHeight === undefined) {
    console.error('Error: --start <height> required (or set BIRTHDAY_HEIGHT in .env)');
    process.exit(1);
  }

  const { extIvk, intIvk } = deriveKeys(seed, parsed.network, parsed.account);
  const rpc = getRpc();

  const endHeight = parsed.endHeight ?? (await rpc.getBlockCount());
  const startHeight = parsed.startHeight;

  console.log(`Scanning blocks ${startHeight} → ${endHeight}`);
  console.log('='.repeat(50));

  let totalValue = 0n;
  let txCount = 0;

  for (let height = startHeight; height <= endHeight; height++) {
    process.stdout.write(`\rBlock ${height}/${endHeight} (${txCount} tx found)`);

    try {
      const block = await rpc.getBlock(height);
      for (const txid of block.tx) {
        try {
          const rawHex = await rpc.getRawTransaction(txid);
          const tx = parseTransaction(rawHex);
          if (tx.orchardActions.length === 0) continue;

          const notes = decryptTransaction(tx.orchardActions, extIvk, intIvk);
          if (notes.length > 0) {
            txCount++;
            console.log(`\n\nBlock ${height} | TX ${txid}`);
            const { incoming, change } = classifyNotes(notes);
            if (incoming.length > 0) {
              for (const n of incoming) {
                console.log(`  Incoming   +${formatZec(n.value)} ZEC${n.memoText ? ` | Memo: ${n.memoText}` : ''}`);
                totalValue += n.value;
              }
            }
            if (change.length > 0) {
              const changeTotal = change.reduce((s, n) => s + n.value, 0n);
              if (incoming.length === 0) {
                // Only change = outgoing tx
                console.log(`  Outgoing   (change: ${formatZec(changeTotal)} ZEC)`);
              } else {
                console.log(`  Change     ${formatZec(changeTotal)} ZEC`);
              }
            }
          }
        } catch {
          // skip unparseable transactions (v4, etc.)
        }
      }
    } catch {
      // skip failed blocks (rate limit, etc.)
    }
  }

  console.log(`\n${'='.repeat(50)}`);
  console.log(`Scan complete: ${txCount} transactions found`);
  console.log(`Total decrypted value: ${formatZec(totalValue)} ZEC`);
}

// === Main ===

async function main() {
  // Load .env
  try {
    const { readFileSync } = await import('fs');
    const envPath = ['.env', '../.env', '../../.env'].find((p) => {
      try { readFileSync(p); return true; } catch { return false; }
    });
    if (envPath) {
      const lines = readFileSync(envPath, 'utf-8').split('\n');
      for (const line of lines) {
        const match = line.match(/^([A-Z_]+)=(.*)$/);
        if (match && !process.env[match[1]]) {
          process.env[match[1]] = match[2].replace(/^"|"$/g, '');
        }
      }
    }
  } catch {}

  const parsed = parseArgs(process.argv.slice(2));

  switch (parsed.command) {
    case 'generate':
      cmdGenerate(parsed);
      break;
    case 'import':
      cmdImport(parsed);
      break;
    case 'addresses':
      cmdAddresses(parsed);
      break;
    case 'decode-tx':
      await cmdDecodeTx(parsed);
      break;
    case 'scan':
      await cmdScan(parsed);
      break;
    default:
      usage();
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});

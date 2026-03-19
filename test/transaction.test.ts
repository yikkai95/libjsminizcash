import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { parseTransaction } from '../src/transaction.js';
import { decryptTransaction, formatZec } from '../src/decrypt.js';
import { mnemonicToSeed } from '../src/index.js';
import { deriveOrchardSpendingKeyFromSeed } from '../src/zip32.js';
import { deriveOrchardFVK, deriveOrchardIVK } from '../src/keys.js';

const MNEMONIC =
  'card critic peace wonder sausage afraid uncle nominee oval prevent life dust photo purpose forget total child eager clean network whip trap rose vintage';

const TX_HEX = readFileSync(
  resolve(__dirname, 'fixtures/tx_de111eae.hex'),
  'utf-8'
).trim();

describe('Transaction Parser', () => {
  it('parses a v5 Zcash transaction', () => {
    const tx = parseTransaction(TX_HEX);
    expect(tx.version).toBe(5);
    expect(tx.orchardActions.length).toBeGreaterThan(0);
    console.log(`Parsed tx: ${tx.transparentInputs.length} t-in, ${tx.transparentOutputs.length} t-out, ${tx.nSpendsSapling} sap-spend, ${tx.nOutputsSapling} sap-out, ${tx.orchardActions.length} orchard actions`);
  });

  it('extracts Orchard actions with correct field sizes', () => {
    const tx = parseTransaction(TX_HEX);
    for (const action of tx.orchardActions) {
      expect(action.cv.length).toBe(32);
      expect(action.nullifier.length).toBe(32);
      expect(action.rk.length).toBe(32);
      expect(action.cmx.length).toBe(32);
      expect(action.ephemeralKey.length).toBe(32);
      expect(action.encCiphertext.length).toBe(580);
      expect(action.outCiphertext.length).toBe(80);
    }
  });
});

describe('Orchard Decryption', () => {
  it('decrypts tx de111eae with the known mnemonic', () => {
    const seed = mnemonicToSeed(MNEMONIC);
    const sk = deriveOrchardSpendingKeyFromSeed(seed, 133, 0);
    const fvk = deriveOrchardFVK(sk);
    const externalIvk = deriveOrchardIVK(fvk, 'external');
    const internalIvk = deriveOrchardIVK(fvk, 'internal');
    const tx = parseTransaction(TX_HEX);

    const notes = decryptTransaction(tx.orchardActions, externalIvk, internalIvk);

    console.log(`Decrypted ${notes.length} note(s) from ${tx.orchardActions.length} actions:`);
    for (const note of notes) {
      console.log(`  Action #${note.actionIndex} [${note.scope}]: ${formatZec(note.value)} ZEC | Memo: ${note.memoText ?? '(none)'}`);
    }

    // Rust tool decrypts Action 0 as internal change: 980000 zatoshis (0.00980000 ZEC)
    expect(notes.length).toBeGreaterThan(0);

    const changeNote = notes.find((n) => n.scope === 'internal');
    expect(changeNote).toBeDefined();
    expect(changeNote!.value).toBe(980000n);
  });

  it('formats ZEC values correctly', () => {
    expect(formatZec(300000n)).toBe('0.00300000');
    expect(formatZec(100000000n)).toBe('1.00000000');
    expect(formatZec(-300000n)).toBe('-0.00300000');
    expect(formatZec(0n)).toBe('0.00000000');
  });
});

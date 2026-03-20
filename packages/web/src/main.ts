import {
  generateMnemonic,
  mnemonicToSeed,
  isValidMnemonic,
  deriveOrchardKeys,
  deriveOrchardIVK,
  deriveOrchardAddress,
  encodeUnifiedAddress,
  encodeUnifiedFVK,
  deriveTransparentAddress,
  createRpc,
  parseTransaction,
  decryptTransaction,
  type OrchardIncomingViewingKey,
} from '@zcash-ts/core';

/* ===== Constants ===== */
const SYNC_INTERVAL = 60_000;
const KEY = (k: string) => `atozcash_${k}`;

/* ===== DOM helpers ===== */
const $ = (s: string) => document.querySelector(s)!;

function escapeHtml(str: string): string {
  const el = document.createElement('span');
  el.textContent = str;
  return el.innerHTML;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/* ===== State ===== */
let syncTimer: ReturnType<typeof setInterval> | null = null;
let syncStatusTimer: ReturnType<typeof setInterval> | null = null;
let lastSyncTime: number | null = null;
let walletTAddress: string | null = null;
let walletExternalIvk: OrchardIncomingViewingKey | null = null;
let walletInternalIvk: OrchardIncomingViewingKey | null = null;

/* ===== Passkey ===== */
async function registerPasskey(): Promise<void> {
  await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: 'AtoZCash', id: location.hostname },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: 'wallet@atozcash',
        displayName: 'AtoZCash Wallet',
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      timeout: 60_000,
    },
  });
}

async function authenticatePasskey(): Promise<void> {
  await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: location.hostname,
      userVerification: 'required',
      timeout: 60_000,
    },
  });
}

/* ===== Error display ===== */
function showLoginError(msg: string): void {
  const el = $('#login-error');
  el.textContent = msg;
  el.classList.toggle('hidden', !msg);
}

function showImportError(msg: string): void {
  const el = $('#import-error');
  el.textContent = msg;
  el.classList.toggle('hidden', !msg);
}

/* ===== Wallet ===== */
function displayWallet(mnemonic: string): void {
  const seed = mnemonicToSeed(mnemonic);

  const keys = deriveOrchardKeys(seed, 'main', 0);
  const orchardAddr = deriveOrchardAddress(keys.incomingViewingKey, 0n);
  const unifiedAddress = encodeUnifiedAddress(orchardAddr, 'main');
  const unifiedFVK = encodeUnifiedFVK(keys.fullViewingKey, 'main');
  const { address: tAddress } = deriveTransparentAddress(seed, 'main', 0);

  // Store IVKs for Orchard scanning
  walletExternalIvk = keys.incomingViewingKey;
  walletInternalIvk = deriveOrchardIVK(keys.fullViewingKey, 'internal');

  $('#seed-phrase').textContent = mnemonic;
  $('#spending-key').textContent = toHex(keys.spendingKey);
  $('#viewing-key').textContent = unifiedFVK;
  $('#wallet-address').textContent = unifiedAddress;
  $('#wallet-t-address').textContent = tAddress;
  walletTAddress = tAddress;

  const birthday = localStorage.getItem(KEY('birthday'));
  if (birthday) {
    ($('#wallet-birthday') as HTMLInputElement).value = birthday;
    $('#birthday-row').classList.remove('hidden');
  } else {
    $('#birthday-row').classList.add('hidden');
  }

  // Load saved Tatum API key
  const savedApiKey = localStorage.getItem(KEY('rpc_api_key'));
  if (savedApiKey) {
    ($('#rpc-api-key') as HTMLInputElement).value = savedApiKey;
    $('#rpc-status').textContent = 'Saved';
  }

  showView('wallet');
  startSync();
}

/* ===== Tatum RPC ===== */
const TATUM_RPC_URL = 'https://zcash-mainnet.gateway.tatum.io';

function getTatumRpc() {
  const apiKey = localStorage.getItem(KEY('rpc_api_key'));
  if (!apiKey) return null;
  return createRpc({ url: TATUM_RPC_URL, apiKey });
}

$('#btn-save-rpc').addEventListener('click', () => {
  const apiKey = ($('#rpc-api-key') as HTMLInputElement).value.trim();
  if (apiKey) {
    localStorage.setItem(KEY('rpc_api_key'), apiKey);
    // Reset scan progress so it rescans from birthday
    localStorage.removeItem(KEY('synced_height'));
    localStorage.removeItem(KEY('shielded_txs'));
    $('#rpc-status').textContent = 'Saved. Will rescan from birthday on next sync.';
  } else {
    localStorage.removeItem(KEY('rpc_api_key'));
    $('#rpc-status').textContent = 'Enter an API key to enable scanning.';
  }
});

$('#btn-save-birthday').addEventListener('click', () => {
  const val = ($('#wallet-birthday') as HTMLInputElement).value.trim();
  if (!val || isNaN(Number(val)) || Number(val) < 0) return;
  const height = Math.floor(Number(val));
  localStorage.setItem(KEY('birthday'), String(height));
  // Reset scan progress to rescan from new birthday
  localStorage.removeItem(KEY('synced_height'));
  localStorage.removeItem(KEY('shielded_txs'));
  ($('#wallet-birthday') as HTMLInputElement).value = String(height);
});

/* ===== Import wallet ===== */
$('#btn-show-import').addEventListener('click', () => {
  $('#step-login').classList.add('hidden');
  $('#step-import').classList.remove('hidden');
  ($('#import-phrase') as HTMLTextAreaElement).value = '';
  ($('#btn-import') as HTMLButtonElement).disabled = true;
  showImportError('');
});

$('#btn-back-login').addEventListener('click', () => {
  $('#step-import').classList.add('hidden');
  $('#step-login').classList.remove('hidden');
});

$('#import-phrase').addEventListener('input', () => {
  const val = ($('#import-phrase') as HTMLTextAreaElement).value.trim();
  const wordCount = val.split(/\s+/).filter(Boolean).length;
  ($('#btn-import') as HTMLButtonElement).disabled = wordCount !== 12 && wordCount !== 24;
});

$('#btn-import').addEventListener('click', async () => {
  showImportError('');
  const birthdayVal = ($('#import-birthday') as HTMLInputElement).value.trim();
  if (!birthdayVal || isNaN(Number(birthdayVal)) || Number(birthdayVal) < 0) {
    showImportError('Please enter a valid wallet birthday height.');
    return;
  }
  const phrase = ($('#import-phrase') as HTMLTextAreaElement).value.trim().toLowerCase().replace(/\s+/g, ' ');
  if (!isValidMnemonic(phrase)) {
    showImportError('Invalid seed phrase. Check your words and try again.');
    return;
  }
  try {
    await registerPasskey();
    localStorage.setItem(KEY('mnemonic'), phrase);
    localStorage.setItem(KEY('birthday'), String(Math.floor(Number(birthdayVal))));
    displayWallet(phrase);
  } catch (e: any) {
    if (e.name !== 'NotAllowedError') showImportError(e.message);
  }
});

/* ===== Register / Login ===== */
$('#btn-register').addEventListener('click', async () => {
  showLoginError('');
  try {
    await registerPasskey();
    const mnemonic = generateMnemonic(256);
    localStorage.setItem(KEY('mnemonic'), mnemonic);
    displayWallet(mnemonic);
  } catch (e: any) {
    if (e.name !== 'NotAllowedError') showLoginError(e.message);
  }
});

$('#btn-login').addEventListener('click', async () => {
  showLoginError('');
  try {
    await authenticatePasskey();
    const mnemonic = localStorage.getItem(KEY('mnemonic'));
    if (!mnemonic) {
      showLoginError('No wallet found. Create a new wallet first.');
      return;
    }
    displayWallet(mnemonic);
  } catch (e: any) {
    if (e.name !== 'NotAllowedError') showLoginError(e.message);
  }
});

$('#btn-logout').addEventListener('click', () => {
  stopSync();
  walletExternalIvk = null;
  walletInternalIvk = null;
  showView('login');
});

/* ===== Orchard block scanning ===== */
async function scanOrchardBlocks(
  rpc: ReturnType<typeof createRpc>,
  from: number,
  to: number,
  statusEl: Element,
): Promise<void> {
  if (!walletExternalIvk) return;

  const shieldedTxs = loadShieldedTxs();
  const knownHashes = new Set(shieldedTxs.map(tx => tx.hash));

  for (let h = from; h <= to; h++) {
    statusEl.textContent = `Scanning block ${h.toLocaleString()} / ${to.toLocaleString()}\u2026`;

    try {
      const block = await rpc.getBlock(h) as { tx: string[]; height: number; time: number };
      console.log(`[scan] block ${h}: ${block.tx.length} txs`);
      for (const txid of block.tx) {
        if (knownHashes.has(txid)) continue;

        let rawHex: string;
        try { rawHex = await rpc.getRawTransaction(txid); }
        catch (e) { console.warn(`[scan] getRawTx failed ${txid}:`, e); continue; }

        let parsed;
        try { parsed = parseTransaction(rawHex); }
        catch (e) { console.log(`[scan] skip non-v5 tx ${txid}`); continue; }

        console.log(`[scan] v5 tx ${txid}: ${parsed.orchardActions.length} orchard actions`);
        if (parsed.orchardActions.length === 0) continue;

        const notes = decryptTransaction(
          parsed.orchardActions,
          walletExternalIvk!,
          walletInternalIvk ?? undefined,
        );
        console.log(`[scan] decrypted ${notes.length} notes from ${txid}`);

        for (const note of notes) {
          shieldedTxs.push({
            hash: txid,
            time: block.time ? new Date(block.time * 1000).toISOString() : '',
            balanceChange: Number(note.value) / 1e8,
            blockHeight: h,
            scope: note.scope,
            memo: note.memoText || undefined,
          });
          knownHashes.add(txid);
        }
        if (notes.length > 0) {
          saveShieldedTxs(shieldedTxs);
          renderTxList(getMergedTxs());
        }
      }
    } catch (e) {
      console.error(`[scan] block ${h} error:`, e);
    }

    // Update from-field with progress
    ($('#scan-from') as HTMLInputElement).value = String(h + 1);
  }

  saveShieldedTxs(shieldedTxs);
}

/* ===== Block sync ===== */
async function syncBlocks(): Promise<void> {
  const icon = $('#sync-icon');
  const statusEl = $('#sync-status');
  icon.classList.add('spin-sync');

  const rpc = getTatumRpc();
  if (!rpc) {
    statusEl.textContent = 'Set Tatum API key to enable sync.';
    icon.classList.remove('spin-sync');
    return;
  }

  const fromVal = ($('#scan-from') as HTMLInputElement).value.trim();
  const toVal = ($('#scan-to') as HTMLInputElement).value.trim();
  const from = fromVal ? Number(fromVal) : null;
  let to = toVal ? Number(toVal) : null;

  if (from === null || isNaN(from)) {
    statusEl.textContent = 'Enter a start block.';
    icon.classList.remove('spin-sync');
    return;
  }

  try {
    if (to === null || isNaN(to)) {
      to = await rpc.getBlockCount();
    }

    statusEl.textContent = `Scanning from ${from.toLocaleString()}\u2026`;
    await scanOrchardBlocks(rpc, from, to!, statusEl);
    statusEl.textContent = `Synced ${from.toLocaleString()} \u2192 ${to!.toLocaleString()}`;
  } catch (e: any) {
    console.error('RPC error:', e);
    statusEl.textContent = `RPC error: ${e.message}`;
  }

  renderTxList(getMergedTxs());

  lastSyncTime = Date.now();
  icon.classList.remove('spin-sync');
}

function updateSyncStatusText(): void {
  if (!lastSyncTime) return;
  const sec = Math.floor((Date.now() - lastSyncTime) / 1000);
  const el = $('#sync-status');
  const birthday = Number(localStorage.getItem(KEY('birthday')) || '0');
  const synced = Number(localStorage.getItem(KEY('synced_height')) || '0');
  const range = synced ? `${birthday.toLocaleString()} \u2192 ${synced.toLocaleString()}` : '';
  if (sec < 10) el.textContent = range ? `Synced ${range}` : 'Synced just now';
  else if (sec < 60) el.textContent = range ? `Synced ${range} \u00b7 ${sec}s ago` : `Synced ${sec}s ago`;
  else el.textContent = range ? `Synced ${range} \u00b7 ${Math.floor(sec / 60)}m ago` : `Synced ${Math.floor(sec / 60)}m ago`;
}

function startSync(): void {
  renderTxList(getMergedTxs());
}

function stopSync(): void {
  if (syncTimer) { clearInterval(syncTimer); syncTimer = null; }
  if (syncStatusTimer) { clearInterval(syncStatusTimer); syncStatusTimer = null; }
}

$('#btn-sync').addEventListener('click', syncBlocks);

/* ===== View management ===== */
function showView(name: 'login' | 'wallet'): void {
  $('#step-login').classList.add('hidden');
  $('#step-import').classList.add('hidden');
  $('#wallet-info').classList.add('hidden');
  $('#tx-section').classList.add('hidden');

  if (name === 'login') {
    $('#step-login').classList.remove('hidden');
  } else {
    $('#wallet-info').classList.remove('hidden');
    $('#tx-section').classList.remove('hidden');
  }
}

/* ===== Lookup single tx ===== */
$('#btn-lookup').addEventListener('click', async () => {
  const txid = ($('#lookup-txid') as HTMLInputElement).value.trim();
  const resultEl = $('#lookup-result');
  if (!txid) return;

  const rpc = getTatumRpc();
  if (!rpc) { resultEl.textContent = 'Set Tatum API key first.'; return; }
  if (!walletExternalIvk) { resultEl.textContent = 'No wallet loaded.'; return; }

  resultEl.textContent = 'Fetching...';
  try {
    const rawHex = await rpc.getRawTransaction(txid);
    const parsed = parseTransaction(rawHex);

    if (parsed.orchardActions.length === 0) {
      resultEl.textContent = 'No Orchard actions (Sapling/transparent only).';
      return;
    }

    const notes = decryptTransaction(
      parsed.orchardActions,
      walletExternalIvk,
      walletInternalIvk ?? undefined,
    );

    if (notes.length === 0) {
      resultEl.textContent = 'No notes decrypted — tx is not for this wallet.';
      return;
    }

    // Add to cache
    const shieldedTxs = loadShieldedTxs();
    const existing = new Set(shieldedTxs.map(t => t.hash + t.scope));
    let added = 0;
    for (const note of notes) {
      const key = txid + note.scope;
      if (existing.has(key)) continue;
      shieldedTxs.push({
        hash: txid,
        time: '',
        balanceChange: Number(note.value) / 1e8,
        scope: note.scope,
        memo: note.memoText || undefined,
      });
      added++;
    }
    if (added > 0) {
      saveShieldedTxs(shieldedTxs);
      renderTxList(getMergedTxs());
    }

    resultEl.textContent = `Found ${notes.length} note(s), ${added} new.`;
    ($('#lookup-txid') as HTMLInputElement).value = '';
  } catch (e: any) {
    resultEl.textContent = `Error: ${e.message}`;
  }
});

/* ===== Transactions ===== */
interface Tx {
  hash: string;
  time: string;
  balanceChange: number;
  blockHeight?: number;
  scope?: string;
  memo?: string;
}

function loadShieldedTxs(): Tx[] {
  try { return JSON.parse(localStorage.getItem(KEY('shielded_txs')) || '[]'); }
  catch { return []; }
}

function saveShieldedTxs(txs: Tx[]): void {
  localStorage.setItem(KEY('shielded_txs'), JSON.stringify(txs));
}

function getMergedTxs(): Tx[] {
  const txs = loadShieldedTxs();
  txs.sort((a, b) => {
    // Sort by block height desc first, fall back to time desc
    if (a.blockHeight && b.blockHeight && a.blockHeight !== b.blockHeight) {
      return b.blockHeight - a.blockHeight;
    }
    if (a.time && b.time) return b.time.localeCompare(a.time);
    return (b.blockHeight ?? 0) - (a.blockHeight ?? 0);
  });
  return txs;
}

function renderTxList(txs: Tx[]): void {
  const list = $('#tx-list');
  if (!txs || !txs.length) {
    list.innerHTML = '<p class="text-sm text-neutral-300 py-6 text-center">No transactions yet</p>';
    return;
  }

  // Update header with count
  const header = document.querySelector('#tx-section > p');
  if (header) header.textContent = `Transactions (${txs.length})`;

  let html = '';
  for (const tx of txs) {
    const isIncoming = tx.scope === 'external';
    const amount = tx.balanceChange.toFixed(8);
    const shortHash = escapeHtml(tx.hash.slice(0, 12) + '\u2026' + tx.hash.slice(-8));

    let dateStr = '';
    if (tx.time) {
      const d = new Date(tx.time);
      dateStr = d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
        + ' ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    }
    const blockStr = tx.blockHeight ? `#${tx.blockHeight.toLocaleString()}` : '';

    let label: string, labelColor: string, labelIcon: string, amountColor: string, amountLabel: string;
    if (isIncoming) {
      label = 'Incoming';
      labelColor = 'text-green-500';
      labelIcon = '\u2193';
      amountColor = 'text-green-600';
      amountLabel = `+${amount} ZEC`;
    } else {
      label = 'Outgoing';
      labelColor = 'text-red-400';
      labelIcon = '\u2191';
      amountColor = 'text-neutral-500';
      amountLabel = `change ${amount} ZEC`;
    }

    const txUrl = `https://cipherscan.app/tx/${encodeURIComponent(tx.hash)}`;

    html += `<a href="${txUrl}" target="_blank" rel="noopener" class="block border-b border-neutral-100 py-3 hover:bg-neutral-50 -mx-1 px-1 transition-colors cursor-pointer">
      <div class="flex justify-between items-start mb-1">
        <div>
          <span class="text-xs font-semibold ${labelColor}">${labelIcon} ${label}</span>
          <span class="font-mono text-[10px] text-neutral-300 ml-2">${shortHash}</span>
        </div>
        <span class="text-sm font-semibold tabular-nums ${amountColor}">${amountLabel}</span>
      </div>
      <div class="flex justify-between text-[10px] text-neutral-400">
        <span>${escapeHtml(dateStr)}</span>
        <span class="font-mono tabular-nums">${blockStr}</span>
      </div>`;

    if (tx.memo) {
      html += `<p class="text-[10px] text-neutral-500 mt-1.5 bg-neutral-50 px-2 py-1 rounded">${escapeHtml(tx.memo)}</p>`;
    }

    html += `</a>`;
  }
  list.innerHTML = html;
}

/* ===== Init ===== */
showView('login');

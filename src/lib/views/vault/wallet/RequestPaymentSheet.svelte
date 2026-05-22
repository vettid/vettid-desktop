<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { onMount, onDestroy } from 'svelte';
  import type { Connection } from '../../../types';
  import { modal } from '../../../actions/modal';
  import { peerName } from '../../../connectionName';

  // --- Request payment sheet ------------------------------------------
  //
  // Sends a payment request to one of the user's connections via the
  // vault's `wallet.request-payment` op. The connection list is loaded
  // with the same `list_connections` command ConnectionsList.svelte
  // uses. The op currently routes through the non-phone-required path
  // server-side, but the pending-approval listener is kept as a safety
  // net in case the vault gates it later — the UI handles both.

  interface WalletItem {
    wallet_id: string;
    label: string;
    network: string;
  }

  interface Props {
    wallet: WalletItem;
    onClose: () => void;
    onSent?: () => void;
  }

  let { wallet, onClose, onSent }: Props = $props();

  // ---- connection list ----------------------------------------------
  let connections = $state<Connection[]>([]);
  let connLoading = $state(true);
  let connError = $state('');

  async function loadConnections() {
    connLoading = true;
    connError = '';
    try {
      const resp: any = await invoke('list_connections');
      if (resp?.success && resp?.data) {
        const all = (resp.data.connections ?? []) as Connection[];
        // Only active connections can receive a payment request.
        connections = all.filter((c) => c.status === 'active');
      } else {
        connError = resp?.error || 'Failed to load connections';
      }
    } catch (e) {
      connError = String(e);
    } finally {
      connLoading = false;
    }
  }

  onMount(() => { loadConnections(); });

  // ---- form state ----------------------------------------------------
  let connectionId = $state('');
  let satsInput = $state('');
  let btcInput = $state('');
  let memo = $state('');

  // Send state. Declared ahead of the derived `canSend` that reads it.
  let sending = $state(false);
  let errorMessage = $state('');
  let done = $state(false);
  // Safety net: if the vault ever routes wallet.request-payment through
  // phone approval, surface a waiting indicator instead of a frozen
  // spinner.
  let pendingRequestId = $state<string | null>(null);

  let amountSats = $derived(parseSats(satsInput));
  let canSend = $derived(!!connectionId && amountSats > 0 && !sending);

  function parseSats(v: string): number {
    const n = Math.floor(Number(v.replace(/[, ]/g, '')));
    return Number.isFinite(n) && n > 0 ? n : 0;
  }
  function onSatsInput(v: string) {
    const cleaned = v.replace(/[^\d]/g, '');
    satsInput = cleaned;
    const s = parseSats(cleaned);
    btcInput = s > 0 ? satsToBtcString(s) : '';
  }
  function onBtcInput(v: string) {
    if (v !== '' && !/^\d*\.?\d{0,8}$/.test(v)) return;
    btcInput = v;
    const btc = Number(v);
    satsInput = Number.isFinite(btc) && btc > 0 ? String(Math.round(btc * 1e8)) : '';
  }
  function satsToBtcString(sats: number): string {
    const whole = Math.floor(sats / 1e8);
    const frac = (sats % 1e8).toString().padStart(8, '0').replace(/0+$/, '');
    return frac ? `${whole}.${frac}` : String(whole);
  }
  function fmtSats(sats: number): string {
    return `${sats.toLocaleString()} sat`;
  }

  // ---- send ----------------------------------------------------------
  let unlistenPending: UnlistenFn | null = null;

  onMount(() => {
    listen<any>('vault:operation-pending-approval', (e) => {
      const payload = e.payload ?? {};
      if (payload.operation !== 'wallet.request-payment') return;
      pendingRequestId = payload.request_id ?? null;
    }).then((fn) => { unlistenPending = fn; });
  });

  async function sendRequest() {
    if (sending || !canSend) return;
    sending = true;
    errorMessage = '';
    try {
      const resp: any = await invoke('request_payment', {
        connectionId,
        walletId: wallet.wallet_id,
        amountSats,
        memo: memo.trim() ? memo.trim() : null,
      });
      pendingRequestId = null;
      if (resp?.success) {
        done = true;
        onSent?.();
        return;
      }
      errorMessage = resp?.error || 'The payment request was not sent.';
    } catch (e) {
      pendingRequestId = null;
      errorMessage = String(e);
    } finally {
      sending = false;
    }
  }

  async function cancelInFlight() {
    const rid = pendingRequestId;
    pendingRequestId = null;
    if (rid) {
      try { await invoke('cancel_pending_operation', { requestId: rid }); } catch (_) {}
    }
  }

  onDestroy(() => {
    if (unlistenPending) unlistenPending();
  });

  function tryClose() {
    if (sending) return;
    onClose();
  }
</script>

<div class="modal-backdrop" onclick={tryClose} role="presentation"></div>
<div
  class="modal req-modal"
  role="dialog"
  aria-modal="true"
  aria-label="Request payment"
  use:modal={{ onEscape: tryClose }}
>
  <header class="modal-head">
    <h2>Request payment</h2>
    <button class="x-btn" onclick={tryClose} disabled={sending} aria-label="Close">✕</button>
  </header>

  {#if done}
    <div class="body success">
      <div class="success-icon">✓</div>
      <p class="success-title">Request sent</p>
      <p class="success-sub">Your connection will see the payment request in their feed.</p>
      <button class="btn primary full" onclick={onClose}>Done</button>
    </div>
  {:else}
    <div class="body">
      <p class="lead">Send a payment request to one of your connections.</p>

      <label class="field">
        <span class="field-label">Connection</span>
        {#if connLoading}
          <div class="conn-status">Loading connections…</div>
        {:else if connError}
          <div class="conn-status err">{connError}</div>
        {:else if connections.length === 0}
          <div class="conn-status">No active connections to request from.</div>
        {:else}
          <select bind:value={connectionId}>
            <option value="" disabled selected>Select a connection…</option>
            {#each connections as c (c.connection_id)}
              <option value={c.connection_id}>{peerName(c)}</option>
            {/each}
          </select>
        {/if}
      </label>

      <div class="amount-row">
        <label class="field amount-field">
          <span class="field-label">Amount (sats)</span>
          <input
            type="text"
            inputmode="numeric"
            value={satsInput}
            oninput={(e) => onSatsInput((e.currentTarget as HTMLInputElement).value)}
            placeholder="0"
            data-autofocus
          />
        </label>
        <label class="field amount-field">
          <span class="field-label">Amount (BTC)</span>
          <input
            type="text"
            inputmode="decimal"
            value={btcInput}
            oninput={(e) => onBtcInput((e.currentTarget as HTMLInputElement).value)}
            placeholder="0.0"
          />
        </label>
      </div>

      <label class="field">
        <span class="field-label">Memo (optional)</span>
        <input type="text" bind:value={memo} placeholder="What is this for?" maxlength="140" />
      </label>

      {#if amountSats > 0}
        <div class="summary">
          <div class="sum-row"><span>Into wallet</span><span>{wallet.label || 'Wallet'}</span></div>
          <div class="sum-row total"><span>Requested amount</span><span>{fmtSats(amountSats)}</span></div>
        </div>
      {/if}

      {#if sending && pendingRequestId}
        <div class="pending">
          <span class="spinner-sm"></span>
          <div class="pending-text">
            <span class="pending-title">Approve on your phone</span>
            <span class="pending-meta">Waiting for approval…</span>
          </div>
          <button class="btn ghost small" onclick={cancelInFlight}>Cancel</button>
        </div>
      {/if}

      {#if errorMessage}
        <div class="error">{errorMessage}</div>
      {/if}
    </div>
    <div class="modal-actions">
      <button class="btn ghost" onclick={tryClose} disabled={sending}>Cancel</button>
      <button class="btn primary" onclick={sendRequest} disabled={!canSend}>
        {sending ? 'Sending…' : 'Send request'}
      </button>
    </div>
  {/if}
</div>

<style>
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
    z-index: 100;
    backdrop-filter: blur(2px);
  }
  .modal {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    z-index: 101;
    background: var(--surface);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 12px;
    width: 420px;
    max-width: calc(100vw - 48px);
    max-height: calc(100vh - 64px);
    display: flex;
    flex-direction: column;
    box-shadow: 0 18px 50px rgba(0, 0, 0, 0.5);
  }
  .modal-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 18px 22px 10px;
  }
  .modal-head h2 { font-size: 1.05rem; margin: 0; font-weight: 600; }
  .x-btn {
    background: transparent;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    font-size: 0.95rem;
    padding: 2px 6px;
    border-radius: 4px;
  }
  .x-btn:hover:not(:disabled) { background: rgba(255, 255, 255, 0.08); color: var(--text); }
  .x-btn:disabled { opacity: 0.4; cursor: not-allowed; }

  .body { padding: 4px 22px 8px; overflow-y: auto; }
  .lead { font-size: 0.85rem; color: var(--text-muted); margin: 4px 0 14px; }

  .field {
    display: flex;
    flex-direction: column;
    gap: 6px;
    margin-bottom: 14px;
  }
  .field-label {
    font-size: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .field input,
  .field select {
    background: var(--bg);
    border: 1px solid rgba(255, 255, 255, 0.08);
    color: var(--text);
    padding: 8px 12px;
    border-radius: 6px;
    font-size: 0.95rem;
    outline: none;
    width: 100%;
    box-sizing: border-box;
  }
  .field input:focus,
  .field select:focus { border-color: var(--accent); }

  .conn-status {
    font-size: 0.85rem;
    color: var(--text-muted);
    padding: 8px 2px;
  }
  .conn-status.err { color: var(--error); }

  .amount-row { display: flex; gap: 10px; }
  .amount-field { flex: 1; min-width: 0; }

  .summary {
    background: var(--bg);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 8px;
    padding: 10px 12px;
    margin-bottom: 8px;
  }
  .sum-row {
    display: flex;
    justify-content: space-between;
    font-size: 0.85rem;
    color: var(--text-muted);
    padding: 3px 0;
  }
  .sum-row.total {
    color: var(--text);
    font-weight: 600;
    border-top: 1px dashed rgba(255, 255, 255, 0.08);
    margin-top: 4px;
    padding-top: 7px;
  }

  .pending {
    display: flex;
    align-items: center;
    gap: 12px;
    background: rgba(255, 152, 0, 0.1);
    border: 1px solid rgba(255, 152, 0, 0.3);
    border-radius: 8px;
    padding: 12px 14px;
    margin-bottom: 10px;
  }
  .pending-text { flex: 1; display: flex; flex-direction: column; }
  .pending-title { font-weight: 600; font-size: 0.88rem; }
  .pending-meta { font-size: 0.78rem; color: var(--text-muted); }
  .spinner-sm {
    width: 16px;
    height: 16px;
    border: 2px solid rgba(255, 152, 0, 0.3);
    border-top-color: var(--warning);
    border-radius: 50%;
    animation: req-spin 0.8s linear infinite;
    flex-shrink: 0;
  }
  @keyframes req-spin { to { transform: rotate(360deg); } }

  .error {
    background: rgba(244, 67, 54, 0.1);
    border: 1px solid rgba(244, 67, 54, 0.25);
    color: var(--error);
    padding: 10px 14px;
    border-radius: 6px;
    font-size: 0.85rem;
    margin-bottom: 8px;
  }

  .modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    padding: 12px 22px 18px;
    border-top: 1px solid rgba(255, 255, 255, 0.05);
    margin-top: 6px;
  }
  .btn {
    padding: 8px 16px;
    border-radius: 6px;
    cursor: pointer;
    font: inherit;
    font-size: 0.9rem;
    border: 1px solid transparent;
  }
  .btn.small { padding: 4px 10px; font-size: 0.78rem; }
  .btn.full { width: 100%; }
  .btn.ghost {
    background: transparent;
    color: var(--text-muted);
    border-color: rgba(255, 255, 255, 0.1);
  }
  .btn.ghost:hover:not(:disabled) { background: rgba(255, 255, 255, 0.05); }
  .btn.primary {
    background: var(--accent);
    color: #1a1a1a;
    font-weight: 600;
  }
  .btn.primary:hover:not(:disabled) { background: var(--accent-hover); }
  .btn:disabled { opacity: 0.45; cursor: not-allowed; }

  .success { text-align: center; padding-bottom: 22px; }
  .success-icon {
    width: 56px;
    height: 56px;
    margin: 8px auto 14px;
    border-radius: 50%;
    background: rgba(64, 196, 99, 0.15);
    color: #6bc77b;
    font-size: 1.8rem;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .success-title { font-size: 1.1rem; font-weight: 600; margin: 0 0 4px; }
  .success-sub { font-size: 0.85rem; color: var(--text-muted); margin: 0 0 16px; }
</style>

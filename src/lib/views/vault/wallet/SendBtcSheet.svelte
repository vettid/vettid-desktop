<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { onMount, onDestroy } from 'svelte';

  // --- Send BTC sheet -------------------------------------------------
  //
  // A modal over the Wallets tab. Two stages:
  //   1. Form    — pick source wallet, destination, amount, fee tier.
  //   2. Confirm — a distinct review screen; nothing is submitted until
  //                the user explicitly presses Confirm & Send.
  //
  // `wallet.send` is phone-required: the vault returns a
  // `pending_approval` ack, then the final result once the human taps
  // Approve. The pending state mirrors the SensitiveDataChip pattern —
  // we listen for `vault:operation-pending-approval` to capture the
  // request_id so the user can Cancel a request in flight.

  interface WalletItem {
    wallet_id: string;
    label: string;
    address: string;
    network: string;
    cached_balance_sats: number;
  }

  interface Props {
    wallets: WalletItem[];
    // Wallet the Send action was launched from. May be empty when
    // opened from a global "Send" button — then the picker shows.
    preselectedWalletId?: string;
    onClose: () => void;
    // Called after a successful broadcast so the parent can refresh
    // balances/history.
    onSent?: () => void;
  }

  let { wallets, preselectedWalletId = '', onClose, onSent }: Props = $props();

  // ---- form state ----------------------------------------------------
  // The parent mounts a fresh SendBtcSheet each time the sheet opens,
  // so capturing the initial prop values here is intentional — the
  // props don't change for the lifetime of this component instance.
  // svelte-ignore state_referenced_locally
  let walletId = $state(
    preselectedWalletId && wallets.some((w) => w.wallet_id === preselectedWalletId)
      ? preselectedWalletId
      : wallets[0]?.wallet_id ?? ''
  );
  let toAddress = $state('');
  // Amount is held canonically in sats; the BTC field is a derived
  // mirror the user can also type into. `amountField` tracks which
  // input the user last edited so we don't clobber their text mid-type.
  let satsInput = $state('');
  let btcInput = $state('');
  let feeTier = $state<'economy' | 'normal' | 'priority'>('normal');

  let stage = $state<'form' | 'confirm'>('form');

  // Send / phone-approval state. Declared here (ahead of the derived
  // values that reference `sending`) so the lexical ordering is valid.
  let sending = $state(false);
  let pendingRequestId = $state<string | null>(null);
  let pendingElapsed = $state(0);
  let pendingStartedAt = 0;
  let errorMessage = $state('');
  // Set on a successful broadcast — flips the sheet to the success view.
  let sentTxid = $state<string | null>(null);

  // ---- fee estimates -------------------------------------------------
  interface FeeRates {
    economy: number;
    normal: number;
    priority: number;
  }
  let feeRates = $state<FeeRates | null>(null);
  let feeError = $state('');

  async function loadFees() {
    try {
      const resp: any = await invoke('get_fee_estimates');
      if (resp?.success && resp?.data) {
        const d = resp.data;
        // mempool.space returns fastestFee / halfHourFee / hourFee /
        // economyFee / minimumFee. Map to our three tiers, tolerating
        // alternative field names the vault might pass through.
        const fast = Number(d.fastestFee ?? d.priority ?? d.fast ?? 0);
        const half = Number(d.halfHourFee ?? d.normal ?? d.standard ?? d.medium ?? 0);
        const hour = Number(d.hourFee ?? d.economyFee ?? d.economy ?? d.slow ?? 0);
        if (fast > 0 || half > 0 || hour > 0) {
          feeRates = {
            priority: fast || half || hour || 1,
            normal: half || fast || hour || 1,
            economy: hour || half || fast || 1,
          };
          return;
        }
      }
      feeError = resp?.error || 'Could not load fee estimates — using defaults.';
      feeRates = { priority: 10, normal: 5, economy: 2 };
    } catch (e) {
      feeError = 'Could not load fee estimates — using defaults.';
      feeRates = { priority: 10, normal: 5, economy: 2 };
    }
  }

  onMount(() => { loadFees(); });

  // ---- derived values ------------------------------------------------
  let selectedWallet = $derived(wallets.find((w) => w.wallet_id === walletId) ?? null);
  let amountSats = $derived(parseSats(satsInput));
  let feeRate = $derived(feeRates ? feeRates[feeTier] : 0);

  // Rough fee estimate: a typical single-input P2WPKH spend is ~140
  // vbytes. The enclave computes the exact fee at sign time — this is
  // a pre-flight estimate so the user sees a realistic total.
  const TYPICAL_VBYTES = 140;
  let estFeeSats = $derived(feeRate > 0 ? feeRate * TYPICAL_VBYTES : 0);
  let totalSats = $derived(amountSats + estFeeSats);
  let balanceSats = $derived(selectedWallet?.cached_balance_sats ?? 0);
  let remainingSats = $derived(balanceSats - totalSats);

  // ---- validation ----------------------------------------------------
  let addressValid = $derived(isPlausibleBtcAddress(toAddress.trim()));
  let amountValid = $derived(amountSats > 0);
  // Total (amount + estimated fee) must fit inside the cached balance.
  let fundsValid = $derived(amountSats > 0 && totalSats <= balanceSats);
  let canReview = $derived(
    !!walletId && addressValid && amountValid && fundsValid && !sending
  );

  let addressFeedback = $derived.by(() => {
    const a = toAddress.trim();
    if (a.length === 0) return '';
    if (addressValid) return 'Address looks valid.';
    return 'This does not look like a Bitcoin address.';
  });
  let amountFeedback = $derived.by(() => {
    if (satsInput.trim().length === 0) return '';
    if (amountSats <= 0) return 'Enter an amount greater than zero.';
    if (totalSats > balanceSats) return 'Amount plus fee exceeds the wallet balance.';
    return '';
  });

  // ---- amount conversion --------------------------------------------
  function parseSats(v: string): number {
    const n = Math.floor(Number(v.replace(/[, ]/g, '')));
    return Number.isFinite(n) && n > 0 ? n : 0;
  }
  function onSatsInput(v: string) {
    // Integers only for sats.
    const cleaned = v.replace(/[^\d]/g, '');
    satsInput = cleaned;
    const s = parseSats(cleaned);
    btcInput = s > 0 ? satsToBtcString(s) : '';
  }
  function onBtcInput(v: string) {
    // Decimal, max 8 places.
    if (v !== '' && !/^\d*\.?\d{0,8}$/.test(v)) return;
    btcInput = v;
    const btc = Number(v);
    if (Number.isFinite(btc) && btc > 0) {
      satsInput = String(Math.round(btc * 1e8));
    } else {
      satsInput = '';
    }
  }
  function satsToBtcString(sats: number): string {
    const whole = Math.floor(sats / 1e8);
    const frac = (sats % 1e8).toString().padStart(8, '0').replace(/0+$/, '');
    return frac ? `${whole}.${frac}` : String(whole);
  }
  function fmtBtc(sats: number): string {
    return `${satsToBtcString(Math.abs(sats))} BTC`;
  }
  function fmtSats(sats: number): string {
    return `${sats.toLocaleString()} sat`;
  }
  function shortAddr(addr: string): string {
    if (addr.length <= 16) return addr;
    return `${addr.slice(0, 10)}…${addr.slice(-8)}`;
  }

  // Basic BTC-address sanity check. Not a full checksum validation —
  // the enclave/wallet does the authoritative check at sign time —
  // but enough to catch typos and obviously-wrong input before the
  // user reaches the confirm step.
  function isPlausibleBtcAddress(a: string): boolean {
    if (!a) return false;
    // Bech32 / bech32m (mainnet bc1, testnet tb1, regtest bcrt1).
    if (/^(bc1|tb1|bcrt1)[02-9ac-hj-np-z]{8,87}$/i.test(a)) return true;
    // Legacy base58 P2PKH / P2SH (mainnet 1.. / 3.., testnet m../n../2..).
    if (/^[123mn][1-9A-HJ-NP-Za-km-z]{25,39}$/.test(a)) return true;
    return false;
  }

  // ---- send / phone approval ----------------------------------------
  let unlistenPending: UnlistenFn | null = null;
  let pendingTicker: ReturnType<typeof setInterval> | null = null;

  onMount(() => {
    listen<any>('vault:operation-pending-approval', (e) => {
      const payload = e.payload ?? {};
      if (payload.operation !== 'wallet.send') return;
      pendingRequestId = payload.request_id ?? null;
      pendingStartedAt = Date.now();
      pendingElapsed = 0;
    }).then((fn) => { unlistenPending = fn; });
  });

  $effect(() => {
    if (sending && pendingRequestId) {
      pendingTicker = setInterval(() => {
        pendingElapsed = Math.floor((Date.now() - pendingStartedAt) / 1000);
      }, 500);
      return () => {
        if (pendingTicker) clearInterval(pendingTicker);
        pendingTicker = null;
      };
    }
  });

  function clearPending() {
    pendingRequestId = null;
    pendingElapsed = 0;
    pendingStartedAt = 0;
  }

  async function confirmSend() {
    if (sending || !selectedWallet) return;
    sending = true;
    errorMessage = '';
    try {
      const resp: any = await invoke('send_btc', {
        walletId: selectedWallet.wallet_id,
        toAddress: toAddress.trim(),
        amountSats,
        feeRate: feeRate > 0 ? feeRate : null,
      });
      clearPending();
      if (resp?.success) {
        sentTxid = String(
          resp?.data?.txid ?? resp?.data?.transaction_id ?? resp?.data?.tx_id ?? ''
        );
        onSent?.();
        return;
      }
      errorMessage =
        resp?.error ||
        (resp?.data?.status === 'denied'
          ? 'You denied the transaction on your phone.'
          : 'The transaction was not completed.');
    } catch (e) {
      clearPending();
      const msg = String(e);
      if (msg.includes('Phone approval timed out'))
        errorMessage = 'Phone approval timed out. Try again when you have your phone handy.';
      else if (msg.toLowerCase().includes('cancelled'))
        errorMessage = 'Transaction cancelled.';
      else if (msg.includes('did not acknowledge'))
        errorMessage = 'Vault is not responding — try again in a moment.';
      else errorMessage = msg;
    } finally {
      sending = false;
    }
  }

  async function cancelInFlight() {
    const rid = pendingRequestId;
    clearPending();
    if (rid) {
      try { await invoke('cancel_pending_operation', { requestId: rid }); } catch (_) {}
    }
    // The await in confirmSend() will wake with a Cancelled error and
    // set errorMessage; nothing more to do here.
  }

  function feeTierLabel(t: typeof feeTier): string {
    return t === 'priority' ? 'Priority' : t === 'normal' ? 'Normal' : 'Economy';
  }
  function feeTierEta(t: typeof feeTier): string {
    return t === 'priority' ? '~10 min' : t === 'normal' ? '~30 min' : '~1 hour';
  }

  onDestroy(() => {
    if (unlistenPending) unlistenPending();
    if (pendingTicker) clearInterval(pendingTicker);
  });

  // Closing while a request is in flight is blocked by the UI (the
  // backdrop click + ✕ are disabled) so an approval can't be orphaned
  // silently. Callers re-open if needed.
  function tryClose() {
    if (sending) return;
    onClose();
  }
</script>

<div class="modal-backdrop" onclick={tryClose} role="presentation"></div>
<div class="modal send-modal" role="dialog" aria-modal="true" aria-label="Send Bitcoin">
  <header class="modal-head">
    <h2>Send Bitcoin</h2>
    <button class="x-btn" onclick={tryClose} disabled={sending} aria-label="Close">✕</button>
  </header>

  {#if sentTxid !== null}
    <!-- Success view ------------------------------------------------ -->
    <div class="success">
      <div class="success-icon">✓</div>
      <p class="success-title">Transaction sent</p>
      <p class="success-sub">Your transaction has been broadcast to the network.</p>
      {#if sentTxid}
        <div class="txid-box">
          <div class="detail-label">Transaction ID</div>
          <div class="txid mono">{sentTxid}</div>
        </div>
      {/if}
      <button class="btn primary full" onclick={onClose}>Done</button>
    </div>
  {:else if stage === 'form'}
    <!-- Stage 1: form ------------------------------------------------ -->
    <div class="body">
      {#if wallets.length > 1}
        <label class="field">
          <span class="field-label">From wallet</span>
          <select bind:value={walletId}>
            {#each wallets as w (w.wallet_id)}
              <option value={w.wallet_id}>{w.label || 'Untitled'} — {fmtBtc(w.cached_balance_sats)}</option>
            {/each}
          </select>
        </label>
      {:else if selectedWallet}
        <div class="single-wallet">
          <div class="sw-label">{selectedWallet.label || 'Untitled wallet'}</div>
          <div class="sw-balance">{fmtBtc(selectedWallet.cached_balance_sats)} available</div>
        </div>
      {/if}

      <label class="field">
        <span class="field-label">Recipient address</span>
        <input
          class="mono"
          type="text"
          bind:value={toAddress}
          placeholder="bc1q…"
          spellcheck="false"
          autocapitalize="off"
        />
        {#if addressFeedback}
          <span class="feedback" class:ok={addressValid} class:bad={!addressValid && toAddress.trim().length > 0}>
            {addressFeedback}
          </span>
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
      {#if amountFeedback}
        <span class="feedback bad block">{amountFeedback}</span>
      {/if}

      <div class="field">
        <span class="field-label">Network fee</span>
        {#if feeError}<span class="feedback bad block">{feeError}</span>{/if}
        <div class="fee-tiers">
          {#each (['priority', 'normal', 'economy'] as const) as tier}
            <button
              type="button"
              class="fee-tier"
              class:selected={feeTier === tier}
              onclick={() => (feeTier = tier)}
            >
              <span class="ft-name">{feeTierLabel(tier)}</span>
              <span class="ft-eta">{feeTierEta(tier)}</span>
              <span class="ft-rate">{feeRates ? `${feeRates[tier]} sat/vB` : '…'}</span>
            </button>
          {/each}
        </div>
      </div>

      {#if amountSats > 0 && selectedWallet}
        <div class="summary">
          <div class="sum-row"><span>Amount</span><span>{fmtSats(amountSats)}</span></div>
          <div class="sum-row"><span>Est. network fee</span><span>~{fmtSats(estFeeSats)}</span></div>
          <div class="sum-row total"><span>Total</span><span>{fmtSats(totalSats)}</span></div>
          <div class="sum-row" class:bad={remainingSats < 0}>
            <span>Balance after</span>
            <span>{remainingSats < 0 ? '—' : fmtSats(remainingSats)}</span>
          </div>
        </div>
      {/if}
    </div>
    <div class="modal-actions">
      <button class="btn ghost" onclick={tryClose}>Cancel</button>
      <button class="btn primary" disabled={!canReview} onclick={() => (stage = 'confirm')}>
        Review
      </button>
    </div>
  {:else}
    <!-- Stage 2: confirm -------------------------------------------- -->
    <div class="body">
      <p class="confirm-lead">Review the details below. Nothing is sent until you press Confirm.</p>
      <div class="confirm-card">
        <div class="cc-row"><span>From</span><span>{selectedWallet?.label || 'Wallet'}</span></div>
        <div class="cc-row"><span>To</span><span class="mono" title={toAddress.trim()}>{shortAddr(toAddress.trim())}</span></div>
        <div class="cc-row"><span>Amount</span><span>{fmtBtc(amountSats)}</span></div>
        <div class="cc-row sub"><span></span><span>{fmtSats(amountSats)}</span></div>
        <div class="cc-row"><span>Fee tier</span><span>{feeTierLabel(feeTier)} ({feeRate} sat/vB)</span></div>
        <div class="cc-row"><span>Est. fee</span><span>~{fmtSats(estFeeSats)}</span></div>
        <div class="cc-divider"></div>
        <div class="cc-row total"><span>Total</span><span>{fmtSats(totalSats)}</span></div>
        <div class="cc-row sub"><span>Balance after</span><span>{fmtSats(remainingSats)}</span></div>
      </div>

      {#if sending}
        <div class="pending">
          <span class="spinner-sm"></span>
          <div class="pending-text">
            <span class="pending-title">Approve on your phone</span>
            <span class="pending-meta">
              {#if pendingRequestId}Waiting… {pendingElapsed}s{:else}Sending request…{/if}
            </span>
          </div>
          {#if pendingRequestId}
            <button class="btn ghost small" onclick={cancelInFlight}>Cancel</button>
          {/if}
        </div>
      {/if}

      {#if errorMessage}
        <div class="error">{errorMessage}</div>
      {/if}
    </div>
    <div class="modal-actions">
      <button class="btn ghost" onclick={() => (stage = 'form')} disabled={sending}>Back</button>
      <button class="btn primary" onclick={confirmSend} disabled={sending}>
        {sending ? 'Sending…' : 'Confirm & Send'}
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
    padding: 0;
    width: 460px;
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
    padding: 18px 22px 12px;
  }
  .modal-head h2 {
    font-size: 1.05rem;
    margin: 0;
    font-weight: 600;
  }
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

  .body {
    padding: 4px 22px 8px;
    overflow-y: auto;
  }

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
  .mono {
    font-family: 'JetBrains Mono', 'Consolas', monospace;
    font-size: 0.85rem;
  }

  .amount-row {
    display: flex;
    gap: 10px;
  }
  .amount-field { flex: 1; min-width: 0; }

  .feedback {
    font-size: 0.75rem;
    color: var(--text-muted);
  }
  .feedback.ok { color: #6bc77b; }
  .feedback.bad { color: var(--error); }
  .feedback.block { display: block; margin: -6px 0 12px; }

  .single-wallet {
    background: var(--bg);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 8px;
    padding: 10px 12px;
    margin-bottom: 14px;
  }
  .sw-label { font-weight: 600; color: var(--text); }
  .sw-balance { font-size: 0.8rem; color: var(--text-muted); margin-top: 2px; }

  .fee-tiers {
    display: flex;
    gap: 8px;
  }
  .fee-tier {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
    background: var(--bg);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 8px;
    padding: 8px 6px;
    cursor: pointer;
    color: var(--text);
    font: inherit;
    text-align: center;
  }
  .fee-tier:hover { border-color: rgba(255, 255, 255, 0.2); }
  .fee-tier.selected {
    border-color: var(--accent);
    background: var(--accent-muted);
  }
  .ft-name { font-size: 0.82rem; font-weight: 600; }
  .ft-eta { font-size: 0.7rem; color: var(--text-muted); }
  .ft-rate { font-size: 0.72rem; color: var(--accent); margin-top: 2px; }

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
  .sum-row.bad span { color: var(--error); }

  .confirm-lead {
    font-size: 0.85rem;
    color: var(--text-muted);
    margin: 4px 0 14px;
  }
  .confirm-card {
    background: var(--bg);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 8px;
    padding: 12px 14px;
    margin-bottom: 12px;
  }
  .cc-row {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    font-size: 0.9rem;
    padding: 5px 0;
  }
  .cc-row > span:first-child { color: var(--text-muted); }
  .cc-row > span:last-child { color: var(--text); font-weight: 500; text-align: right; }
  .cc-row.sub { padding-top: 0; }
  .cc-row.sub > span { font-size: 0.78rem; color: var(--text-muted); font-weight: 400; }
  .cc-row.total { font-size: 1rem; }
  .cc-row.total > span:last-child { color: var(--accent); font-weight: 700; }
  .cc-divider {
    height: 1px;
    background: rgba(255, 255, 255, 0.08);
    margin: 6px 0;
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
    animation: send-spin 0.8s linear infinite;
    flex-shrink: 0;
  }
  @keyframes send-spin { to { transform: rotate(360deg); } }

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

  .success {
    padding: 12px 22px 22px;
    text-align: center;
  }
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
  .txid-box {
    background: var(--bg);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 8px;
    padding: 10px 12px;
    margin-bottom: 18px;
    text-align: left;
  }
  .detail-label {
    font-size: 0.7rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 4px;
  }
  .txid {
    word-break: break-all;
    font-size: 0.8rem;
    color: var(--text);
  }
</style>

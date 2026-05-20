<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';
  import { secretsUnlockStore, isSecretsUnlocked } from '../../stores/secrets';

  // Read the shared lock state from the Sensitive Data chip in the
  // header. Public wallet info (label, address, balance, history) is
  // always visible; future sensitive actions (Send BTC, View seed
  // backup) gate on this. The chip is the single unlock surface for
  // the whole vault.
  let unlockState = $derived($secretsUnlockStore);
  let unlocked = $derived(isSecretsUnlocked(unlockState));

  // Module-level cache so tab navigation away + back doesn't re-fire
  // wallet.list. Mirrors the pattern in PersonalData.svelte. Cleared
  // on session end (App.svelte remounts).
  const cache: { wallets: WalletItem[]; ts: number } | null = (window as any).__wallets_cache ?? null;

  interface WalletItem {
    wallet_id: string;
    label: string;
    address: string;
    network: string;
    cached_balance_sats: number;
    balance_updated_at: number;
    is_public: boolean;
    is_archived: boolean;
  }

  let wallets = $state<WalletItem[]>(cache?.wallets ?? []);
  let loading = $state(cache === null);
  let refreshing = $state(false);
  let errorMessage = $state('');

  async function load() {
    if (wallets.length) {
      refreshing = true;
    } else {
      loading = true;
    }
    errorMessage = '';
    try {
      const resp: any = await invoke('list_wallets');
      if (!resp?.success || !resp?.data) {
        errorMessage = resp?.error || 'Failed to load wallets';
        return;
      }
      const arr = (resp.data.wallets ?? []) as WalletItem[];
      wallets = arr.filter((w) => !w.is_archived);
      (window as any).__wallets_cache = { wallets, ts: Date.now() };
    } catch (e) {
      errorMessage = `Failed to load wallets: ${e}`;
    } finally {
      loading = false;
      refreshing = false;
    }
  }

  // onMount, NOT $effect: load() reads `wallets` in its entry guard
  // and then writes a fresh `wallets` array, so an $effect would
  // register it as a dependency and re-fire itself in a tight loop.
  onMount(() => { load(); });

  // Sats → BTC with 8 decimals; locale-aware grouping on the integer
  // side so balances stay readable.
  function fmtBtc(sats: number): string {
    const sign = sats < 0 ? '-' : '';
    const abs = Math.abs(sats);
    const whole = Math.floor(abs / 1e8);
    const frac = (abs % 1e8).toString().padStart(8, '0').replace(/0+$/, '') || '0';
    return `${sign}${whole.toLocaleString()}.${frac} BTC`;
  }
  function fmtSats(sats: number): string {
    return `${sats.toLocaleString()} sat`;
  }
  function shortAddr(addr: string): string {
    if (addr.length <= 12) return addr;
    return `${addr.slice(0, 6)}…${addr.slice(-6)}`;
  }

  async function copyAddress(addr: string) {
    try {
      await navigator.clipboard.writeText(addr);
    } catch (e) {
      // Clipboard may be denied in some Tauri configs — fall back silently.
    }
  }

  // Expand state + per-wallet auxiliary data fetched on-demand when
  // a card is expanded. Kept in component state — not cached across
  // navigations because tx history is the freshest data; users
  // expect it to reflect recent activity.
  let expandedId = $state<string | null>(null);
  let detailLoading = $state<Record<string, boolean>>({});
  let detailError = $state<Record<string, string>>({});
  interface Tx {
    txid: string;
    confirmations: number;
    amount_sats: number; // signed: + receive, - send
    timestamp: number;
  }
  let txByWallet = $state<Record<string, Tx[]>>({});
  let refreshingId = $state<string | null>(null);

  async function toggleExpand(w: WalletItem) {
    if (expandedId === w.wallet_id) {
      expandedId = null;
      return;
    }
    expandedId = w.wallet_id;
    if (txByWallet[w.wallet_id] !== undefined) return; // already loaded
    detailLoading = { ...detailLoading, [w.wallet_id]: true };
    detailError = { ...detailError, [w.wallet_id]: '' };
    try {
      const resp: any = await invoke('get_wallet_transactions', { walletId: w.wallet_id });
      if (resp?.success && resp?.data) {
        const arr = (resp.data.transactions ?? resp.data.history ?? []) as Tx[];
        txByWallet = { ...txByWallet, [w.wallet_id]: arr.slice(0, 10) };
      } else {
        detailError = { ...detailError, [w.wallet_id]: resp?.error || 'Failed to load history' };
      }
    } catch (e) {
      detailError = { ...detailError, [w.wallet_id]: `Failed to load history: ${e}` };
    } finally {
      detailLoading = { ...detailLoading, [w.wallet_id]: false };
    }
  }

  async function refreshBalance(w: WalletItem, event: MouseEvent) {
    event.stopPropagation();
    refreshingId = w.wallet_id;
    try {
      const resp: any = await invoke('get_wallet_balance', { walletId: w.wallet_id });
      if (resp?.success && resp?.data) {
        const sats = Number(resp.data.total_sats ?? resp.data.confirmed_sats ?? 0);
        wallets = wallets.map((x) => (x.wallet_id === w.wallet_id ? { ...x, cached_balance_sats: sats, balance_updated_at: Math.floor(Date.now() / 1000) } : x));
        (window as any).__wallets_cache = { wallets, ts: Date.now() };
      }
    } catch (e) {
      // Non-fatal — leave the cached value alone.
    } finally {
      refreshingId = null;
    }
  }

  function fmtTime(unix: number): string {
    if (!unix) return '';
    const d = new Date(unix * 1000);
    return d.toLocaleString();
  }
  function fmtRelative(unix: number): string {
    if (!unix) return 'never';
    const diff = Math.floor(Date.now() / 1000) - unix;
    if (diff < 60) return 'just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  }
  function fmtAmount(sats: number): string {
    const sign = sats > 0 ? '+' : sats < 0 ? '−' : '';
    const abs = Math.abs(sats);
    return `${sign}${abs.toLocaleString()} sat`;
  }
</script>

<div class="wallets-view">
  <header>
    <h1>Wallets {#if refreshing}<span class="refresh-dot" title="Refreshing"></span>{/if}</h1>
  </header>

  {#if loading}
    <div class="loading-wrap"><span class="spinner"></span></div>
  {:else}
    {#if errorMessage}<div class="error">{errorMessage}</div>{/if}

    {#if wallets.length === 0 && !errorMessage}
      <div class="empty">
        <p>No wallets yet.</p>
        <p class="hint">Create a wallet from the VettID app on your phone — desktop wallet management is read-only for now.</p>
      </div>
    {:else}
      <div class="list">
        {#each wallets as w (w.wallet_id)}
          {@const isExpanded = expandedId === w.wallet_id}
          <article class="card" class:expanded={isExpanded}>
            <button class="card-head-btn" onclick={() => toggleExpand(w)} aria-expanded={isExpanded}>
              <header class="card-head">
                <div class="head-left">
                  <div class="label">{w.label || 'Untitled wallet'}</div>
                  <div class="address-inline mono">{shortAddr(w.address)}</div>
                </div>
                <div class="head-right">
                  <div class="balance">{fmtBtc(w.cached_balance_sats)}</div>
                  <div class="sats">{fmtSats(w.cached_balance_sats)}</div>
                </div>
              </header>
              <div class="card-meta">
                <span class="network">{w.network || 'BTC'}</span>
                {#if w.is_public}<span class="pill public">Public</span>{/if}
                <span class="updated">balance {fmtRelative(w.balance_updated_at)}</span>
                <span class="caret">{isExpanded ? '▾' : '▸'}</span>
              </div>
            </button>

            {#if isExpanded}
              <div class="card-detail">
                <div class="detail-section">
                  <div class="detail-label">Receive address</div>
                  <div class="address-full">
                    <span class="mono">{w.address}</span>
                    <button class="copy-btn" onclick={() => copyAddress(w.address)}>copy</button>
                  </div>
                </div>

                <div class="detail-section">
                  <div class="detail-head">
                    <div class="detail-label">Balance</div>
                    <button class="refresh-btn" onclick={(e) => refreshBalance(w, e)} disabled={refreshingId === w.wallet_id}>
                      {refreshingId === w.wallet_id ? '…' : 'Refresh'}
                    </button>
                  </div>
                  <div class="detail-balance">
                    <span class="big">{fmtBtc(w.cached_balance_sats)}</span>
                    <span class="muted">{fmtSats(w.cached_balance_sats)}</span>
                  </div>
                </div>

                <div class="detail-section">
                  <div class="detail-label">Recent activity</div>
                  {#if detailLoading[w.wallet_id]}
                    <div class="tx-loading"><span class="spinner small"></span></div>
                  {:else if detailError[w.wallet_id]}
                    <div class="tx-error">{detailError[w.wallet_id]}</div>
                  {:else if (txByWallet[w.wallet_id]?.length ?? 0) === 0}
                    <div class="tx-empty">No transactions yet.</div>
                  {:else}
                    <ul class="tx-list">
                      {#each txByWallet[w.wallet_id] as tx (tx.txid)}
                        <li class="tx-row">
                          <span class="tx-amount {tx.amount_sats >= 0 ? 'in' : 'out'}">{fmtAmount(tx.amount_sats)}</span>
                          <span class="tx-time">{fmtTime(tx.timestamp)}</span>
                          <span class="tx-conf">{tx.confirmations > 0 ? `${tx.confirmations} conf` : 'pending'}</span>
                        </li>
                      {/each}
                    </ul>
                  {/if}
                </div>
              </div>
            {/if}
          </article>
        {/each}
      </div>
      <p class="hint footer-hint">
        {#if unlocked}
          Sensitive actions (Send BTC, view seed backup) are available while the chip above is Unlocked.
        {:else}
          🔒 Unlock <strong>Sensitive Data</strong> in the header above to enable Send BTC and seed-backup viewing.
        {/if}
        Receive is always available — copy any address above and share with the sender.
      </p>
    {/if}
  {/if}
</div>

<style>
  .wallets-view { padding: 24px; max-width: 720px; margin: 0 auto; }
  header { display: flex; align-items: center; gap: 12px; margin-bottom: 20px; }
  header h1 { flex: 1; font-size: 1.3rem; margin: 0; }

  .list {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .card {
    background: var(--surface);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 10px;
    overflow: hidden;
  }
  .card.expanded { border-color: rgba(255, 255, 255, 0.14); }
  .card-head-btn {
    width: 100%;
    background: transparent;
    border: 0;
    text-align: left;
    cursor: pointer;
    padding: 14px;
    color: inherit;
    font: inherit;
  }
  .card-head-btn:hover { background: rgba(255, 255, 255, 0.03); }
  .card-head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
  }
  .head-left {
    min-width: 0;
    flex: 1;
  }
  .head-right {
    text-align: right;
    flex-shrink: 0;
  }
  .label {
    font-weight: 600;
    color: var(--text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .address-inline {
    font-size: 0.8rem;
    color: var(--text-muted);
    margin-top: 2px;
  }
  .balance {
    font-size: 1.2rem;
    font-weight: 600;
    color: var(--accent);
    line-height: 1.1;
  }
  .sats {
    font-size: 0.75rem;
    color: var(--text-muted);
    margin-top: 2px;
  }
  .card-meta {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 10px;
    font-size: 0.75rem;
    color: var(--text-muted);
  }
  .network {
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .updated { flex: 1; }
  .caret { margin-left: auto; font-size: 0.9rem; }
  .pill {
    background: rgba(64, 196, 99, 0.15);
    color: #6bc77b;
    border: 1px solid rgba(107, 199, 123, 0.3);
    border-radius: 4px;
    padding: 1px 7px;
    font-size: 0.7rem;
  }
  .mono {
    font-family: 'JetBrains Mono', 'Consolas', monospace;
    font-size: 0.85rem;
  }
  .card-detail {
    padding: 14px 14px 16px;
    border-top: 1px solid rgba(255, 255, 255, 0.06);
    background: rgba(0, 0, 0, 0.15);
  }
  .detail-section { margin-bottom: 14px; }
  .detail-section:last-child { margin-bottom: 0; }
  .detail-label {
    font-size: 0.7rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 6px;
  }
  .detail-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 6px;
  }
  .address-full {
    display: flex;
    align-items: center;
    gap: 8px;
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 5px;
    padding: 8px 10px;
  }
  .address-full .mono {
    flex: 1;
    min-width: 0;
    word-break: break-all;
  }
  .copy-btn {
    background: rgba(255, 255, 255, 0.08);
    border: 1px solid rgba(255, 255, 255, 0.1);
    color: var(--text-muted);
    border-radius: 4px;
    padding: 3px 9px;
    font-size: 0.7rem;
    cursor: pointer;
    flex-shrink: 0;
  }
  .copy-btn:hover {
    background: rgba(255, 255, 255, 0.15);
    color: var(--text);
  }
  .refresh-btn {
    background: rgba(255, 255, 255, 0.08);
    border: 1px solid rgba(255, 255, 255, 0.1);
    color: var(--text);
    border-radius: 4px;
    padding: 3px 10px;
    font-size: 0.75rem;
    cursor: pointer;
  }
  .refresh-btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .detail-balance {
    display: flex;
    align-items: baseline;
    gap: 10px;
  }
  .detail-balance .big {
    font-size: 1.1rem;
    color: var(--accent);
    font-weight: 600;
  }
  .detail-balance .muted {
    color: var(--text-muted);
    font-size: 0.85rem;
  }
  .tx-list {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .tx-row {
    display: flex;
    gap: 12px;
    padding: 6px 0;
    border-bottom: 1px dashed rgba(255, 255, 255, 0.05);
    font-size: 0.85rem;
  }
  .tx-row:last-child { border-bottom: none; }
  .tx-amount {
    font-weight: 600;
    min-width: 120px;
  }
  .tx-amount.in { color: #6bc77b; }
  .tx-amount.out { color: #ff8a65; }
  .tx-time { color: var(--text-muted); flex: 1; }
  .tx-conf { color: var(--text-muted); font-size: 0.75rem; }
  .tx-empty, .tx-error { color: var(--text-muted); font-size: 0.85rem; padding: 6px 0; }
  .tx-loading { padding: 12px 0; display: flex; justify-content: center; }
  .spinner.small {
    width: 18px;
    height: 18px;
    border-width: 2px;
  }

  .empty {
    text-align: center;
    padding: 60px 16px;
    color: var(--text-muted);
  }
  .hint {
    color: var(--text-muted);
    font-size: 0.85rem;
  }
  .footer-hint {
    margin-top: 16px;
    text-align: center;
  }
  .error {
    background: rgba(244, 67, 54, 0.1);
    border: 1px solid rgba(244, 67, 54, 0.25);
    color: var(--error);
    padding: 12px 16px;
    border-radius: 6px;
    margin-bottom: 12px;
  }

  .loading-wrap { display: flex; justify-content: center; padding: 48px 0; }
  .spinner {
    width: 28px;
    height: 28px;
    border: 3px solid rgba(255, 255, 255, 0.1);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: wallet-spin 0.9s linear infinite;
  }
  @keyframes wallet-spin { to { transform: rotate(360deg); } }
  .refresh-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    margin-left: 8px;
    border-radius: 50%;
    background: var(--accent);
    opacity: 0.7;
    animation: wallet-pulse 1.2s ease-in-out infinite;
    vertical-align: middle;
  }
  @keyframes wallet-pulse {
    0%, 100% { opacity: 0.3; }
    50% { opacity: 0.85; }
  }
</style>

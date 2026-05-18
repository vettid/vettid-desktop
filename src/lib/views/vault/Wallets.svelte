<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';

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

  $effect(() => { load(); });

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
      <div class="grid">
        {#each wallets as w (w.wallet_id)}
          <article class="card">
            <header class="card-head">
              <div class="label">{w.label || 'Untitled wallet'}</div>
              <div class="network">{w.network || 'BTC'}</div>
            </header>
            <div class="balance">{fmtBtc(w.cached_balance_sats)}</div>
            <div class="sats">{fmtSats(w.cached_balance_sats)}</div>
            <div class="address-row">
              <button class="address" onclick={() => copyAddress(w.address)} title={w.address}>
                <span class="mono">{shortAddr(w.address)}</span>
                <span class="copy-hint">copy</span>
              </button>
            </div>
            {#if w.is_public}
              <div class="pill public">Public</div>
            {/if}
          </article>
        {/each}
      </div>
      <p class="hint footer-hint">
        Balances are cached snapshots from the vault. Send + Receive require phone approval —
        use the VettID app for those flows.
      </p>
    {/if}
  {/if}
</div>

<style>
  .wallets-view { padding: 24px; max-width: 720px; margin: 0 auto; }
  header { display: flex; align-items: center; gap: 12px; margin-bottom: 20px; }
  header h1 { flex: 1; font-size: 1.3rem; margin: 0; }

  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 12px;
  }
  .card {
    background: var(--surface);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 10px;
    padding: 14px;
    display: flex;
    flex-direction: column;
    gap: 4px;
    position: relative;
  }
  .card-head {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 8px;
  }
  .label {
    font-weight: 600;
    color: var(--text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .network {
    font-size: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .balance {
    font-size: 1.2rem;
    font-weight: 600;
    margin-top: 4px;
    color: var(--accent);
  }
  .sats {
    font-size: 0.8rem;
    color: var(--text-muted);
  }
  .address-row {
    margin-top: 10px;
    display: flex;
  }
  .address {
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 6px;
    color: var(--text);
    padding: 6px 10px;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font: inherit;
  }
  .address:hover {
    background: rgba(255, 255, 255, 0.1);
  }
  .mono {
    font-family: 'JetBrains Mono', 'Consolas', monospace;
    font-size: 0.85rem;
  }
  .copy-hint {
    font-size: 0.7rem;
    color: var(--text-muted);
  }
  .pill {
    position: absolute;
    top: 14px;
    right: 14px;
    background: rgba(64, 196, 99, 0.15);
    color: #6bc77b;
    border: 1px solid rgba(107, 199, 123, 0.3);
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 0.7rem;
  }
  .pill.public {
    /* default green is fine — keep this hook for non-public types later */
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

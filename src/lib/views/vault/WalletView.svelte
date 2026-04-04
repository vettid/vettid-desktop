<script lang="ts">
    import { invoke } from '@tauri-apps/api/core';
    import type { WalletInfo, TxHistoryEntry, VaultOpResponse } from '../../types';

    let wallets: WalletInfo[] = $state([]);
    let selectedWallet: WalletInfo | null = $state(null);
    let transactions: TxHistoryEntry[] = $state([]);
    let loading = $state(true);
    let error = $state('');

    async function loadWallets() {
        loading = true;
        error = '';
        try {
            const resp: VaultOpResponse = await invoke('list_wallets');
            if (resp.success && resp.data) {
                const data = resp.data as { wallets?: WalletInfo[] };
                wallets = data.wallets ?? [];
            } else {
                error = resp.error ?? 'Failed to load wallets';
            }
        } catch (e) {
            error = String(e);
        }
        loading = false;
    }

    async function selectWallet(wallet: WalletInfo) {
        selectedWallet = wallet;
        try {
            const resp: VaultOpResponse = await invoke('get_transaction_history', { walletId: wallet.wallet_id });
            if (resp.success && resp.data) {
                const data = resp.data as { transactions?: TxHistoryEntry[] };
                transactions = data.transactions ?? [];
            }
        } catch (e) {
            console.error('Failed to load transactions:', e);
        }
    }

    function formatBtc(sats: number): string {
        return (sats / 100_000_000).toFixed(8) + ' BTC';
    }

    $effect(() => { loadWallets(); });
</script>

<div class="wallet-view">
    <div class="header">
        <h3>Wallets</h3>
        <button class="refresh" aria-label="Refresh" onclick={loadWallets}>↻</button>
    </div>

    {#if loading}
        <div class="status">Loading wallets...</div>
    {:else if error}
        <div class="status error">{error}</div>
    {:else if wallets.length === 0}
        <div class="status">No wallets. Create one from your phone.</div>
    {:else}
        <div class="wallet-list">
            {#each wallets as wallet}
                <button
                    class="wallet-card"
                    class:active={selectedWallet?.wallet_id === wallet.wallet_id}
                    onclick={() => selectWallet(wallet)}
                >
                    <div class="wallet-label">{wallet.label}</div>
                    <div class="wallet-balance">{formatBtc(wallet.cached_balance_sats)}</div>
                    <div class="wallet-meta">
                        <span class="network {wallet.network}">{wallet.network}</span>
                        {#if wallet.is_public}<span class="public">Public</span>{/if}
                    </div>
                </button>
            {/each}
        </div>

        {#if selectedWallet}
            <div class="tx-section">
                <h4>Transactions — {selectedWallet.label}</h4>
                {#if transactions.length === 0}
                    <div class="status">No transactions yet</div>
                {:else}
                    <ul class="tx-list">
                        {#each transactions as tx}
                            <li class="tx-item">
                                <span class="tx-direction {tx.direction}">
                                    {tx.direction === 'received' ? '↓' : '↑'}
                                </span>
                                <span class="tx-amount {tx.direction}">
                                    {tx.direction === 'received' ? '+' : '-'}{formatBtc(tx.amount_sats)}
                                </span>
                                <span class="tx-status">
                                    {tx.confirmed ? '✓' : '⏳'}
                                </span>
                                {#if tx.block_time}
                                    <span class="tx-time">{new Date(tx.block_time).toLocaleDateString()}</span>
                                {/if}
                            </li>
                        {/each}
                    </ul>
                {/if}
            </div>
        {/if}
    {/if}
</div>

<style>
    .wallet-view { height: 100%; overflow-y: auto; }
    .header { display: flex; justify-content: space-between; align-items: center; padding: 0 0 12px; }
    .header h3 { margin: 0; }
    .refresh { background: none; border: 1px solid var(--border); border-radius: 4px; cursor: pointer; padding: 4px 8px; }
    .status { color: var(--text-secondary); padding: 24px; text-align: center; }
    .status.error { color: var(--danger); }
    .wallet-list { display: flex; gap: 12px; flex-wrap: wrap; }
    .wallet-card { text-align: left; padding: 16px; border: 1px solid var(--border); border-radius: 8px; background: none; cursor: pointer; min-width: 200px; }
    .wallet-card:hover { background: var(--bg-hover); }
    .wallet-card.active { border-color: var(--accent); background: var(--accent-bg); }
    .wallet-label { font-weight: 600; }
    .wallet-balance { font-family: monospace; margin: 4px 0; }
    .wallet-meta { display: flex; gap: 6px; font-size: 0.8em; }
    .network { padding: 1px 5px; border-radius: 3px; }
    .network.mainnet { background: #fff3e0; color: #e65100; }
    .network.testnet { background: #e3f2fd; color: #1565c0; }
    .public { color: var(--text-secondary); }
    .tx-section { margin-top: 20px; }
    .tx-section h4 { margin: 0 0 8px; }
    .tx-list { list-style: none; padding: 0; }
    .tx-item { display: flex; gap: 12px; align-items: center; padding: 8px 0; border-bottom: 1px solid var(--border); font-size: 0.9em; }
    .tx-direction { font-size: 1.2em; }
    .tx-direction.received { color: #2e7d32; }
    .tx-direction.sent { color: var(--text-secondary); }
    .tx-amount { font-family: monospace; }
    .tx-amount.received { color: #2e7d32; }
    .tx-status { font-size: 0.8em; }
    .tx-time { color: var(--text-secondary); font-size: 0.85em; margin-left: auto; }
</style>

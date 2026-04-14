<script lang="ts">
    import { invoke } from '@tauri-apps/api/core';
    import type { WalletInfo, TxHistoryEntry, VaultOpResponse } from '../../types';

    type Mode = 'history' | 'send' | 'receive' | 'create';

    let wallets = $state<WalletInfo[]>([]);
    let selectedWallet = $state<WalletInfo | null>(null);
    let transactions = $state<TxHistoryEntry[]>([]);
    let mode = $state<Mode>('history');

    let loading = $state(true);
    let txLoading = $state(false);
    let error = $state('');

    // Send-form state
    let sendTo = $state('');
    let sendAmount = $state(''); // BTC string for UX; we convert to sats on submit
    let sendFeeRate = $state<number | null>(null);
    let sending = $state(false);
    let sendStatus = $state('');

    // Receive
    let receiveAddress = $state('');
    let copyHint = $state('');

    // Create-wallet form
    let createLabel = $state('');
    let createNetwork = $state<'mainnet' | 'testnet'>('mainnet');
    let creating = $state(false);
    let createStatus = $state('');

    // Fee estimates
    let feeEstimates = $state<{ slow: number; standard: number; fast: number } | null>(null);

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
        mode = 'history';
        sendStatus = '';
        copyHint = '';
        await loadTransactions(wallet.wallet_id);
    }

    async function loadTransactions(walletId: string) {
        txLoading = true;
        try {
            const resp: VaultOpResponse = await invoke('get_transaction_history', { walletId });
            if (resp.success && resp.data) {
                const data = resp.data as { transactions?: TxHistoryEntry[] };
                transactions = data.transactions ?? [];
            } else {
                transactions = [];
            }
        } catch (e) {
            console.error('Failed to load transactions:', e);
            transactions = [];
        }
        txLoading = false;
    }

    async function openReceive() {
        if (!selectedWallet) return;
        mode = 'receive';
        receiveAddress = selectedWallet.address;
        try {
            const resp: VaultOpResponse = await invoke('get_wallet_address', {
                walletId: selectedWallet.wallet_id,
            });
            if (resp.success && resp.data) {
                const data = resp.data as { address?: string };
                if (data.address) receiveAddress = data.address;
            }
        } catch (e) {
            console.warn('Failed to refresh receive address:', e);
        }
    }

    async function copyAddress() {
        try {
            await navigator.clipboard.writeText(receiveAddress);
            copyHint = 'Copied to clipboard';
            setTimeout(() => (copyHint = ''), 2000);
        } catch (e) {
            copyHint = 'Copy failed — select and copy manually';
        }
    }

    async function openSend() {
        if (!selectedWallet) return;
        mode = 'send';
        sendStatus = '';
        sendTo = '';
        sendAmount = '';
        sendFeeRate = null;
        try {
            const resp: VaultOpResponse = await invoke('get_fee_estimates');
            if (resp.success && resp.data) {
                feeEstimates = resp.data as { slow: number; standard: number; fast: number };
                sendFeeRate = feeEstimates.standard;
            }
        } catch (e) {
            console.warn('Failed to fetch fee estimates:', e);
        }
    }

    async function submitSend() {
        if (!selectedWallet || sending) return;
        const sats = Math.round(parseFloat(sendAmount) * 100_000_000);
        if (!Number.isFinite(sats) || sats <= 0) {
            sendStatus = 'Invalid amount';
            return;
        }
        if (!sendTo.trim()) {
            sendStatus = 'Address is required';
            return;
        }
        const ok = confirm(
            `Send ${formatBtc(sats)} to ${sendTo}?\nThis requires phone approval to sign.`,
        );
        if (!ok) return;
        sending = true;
        sendStatus = '';
        try {
            const resp: VaultOpResponse = await invoke('send_btc', {
                walletId: selectedWallet.wallet_id,
                toAddress: sendTo.trim(),
                amountSats: sats,
                feeRate: sendFeeRate ?? null,
            });
            if (resp.success) {
                sendStatus = 'Transaction broadcast.';
                await loadTransactions(selectedWallet.wallet_id);
                mode = 'history';
            } else if (resp.pending_approval) {
                sendStatus = 'Waiting for phone approval to sign…';
            } else {
                sendStatus = resp.error ?? 'Send failed';
            }
        } catch (e) {
            sendStatus = String(e);
        }
        sending = false;
    }

    async function submitCreate() {
        if (creating || !createLabel.trim()) return;
        creating = true;
        createStatus = '';
        try {
            const resp: VaultOpResponse = await invoke('create_wallet', {
                label: createLabel.trim(),
                network: createNetwork,
            });
            if (resp.success) {
                createStatus = 'Wallet created.';
                createLabel = '';
                await loadWallets();
                mode = 'history';
            } else if (resp.pending_approval) {
                createStatus = 'Waiting for phone approval to generate keys…';
            } else {
                createStatus = resp.error ?? 'Create failed';
            }
        } catch (e) {
            createStatus = String(e);
        }
        creating = false;
    }

    function formatBtc(sats: number): string {
        return (sats / 100_000_000).toFixed(8) + ' BTC';
    }

    $effect(() => { loadWallets(); });
</script>

<div class="wallet-view">
    <div class="header">
        <h3>Wallets</h3>
        <div class="header-actions">
            <button class="action-btn" onclick={() => { mode = 'create'; selectedWallet = null; }}>+ New</button>
            <button class="refresh" aria-label="Refresh" onclick={loadWallets}>↻</button>
        </div>
    </div>

    {#if loading}
        <div class="status">Loading wallets…</div>
    {:else if error}
        <div class="status error">{error}</div>
    {:else if mode === 'create'}
        <section class="card">
            <h4>Create wallet</h4>
            <label class="field">
                <span>Label</span>
                <input bind:value={createLabel} placeholder="Savings, hot wallet, …" />
            </label>
            <label class="field">
                <span>Network</span>
                <select bind:value={createNetwork}>
                    <option value="mainnet">Mainnet</option>
                    <option value="testnet">Testnet</option>
                </select>
            </label>
            <p class="hint">Key generation runs inside the enclave and requires phone approval.</p>
            <div class="form-actions">
                <button class="cancel" onclick={() => mode = 'history'}>Cancel</button>
                <button class="primary" onclick={submitCreate} disabled={creating || !createLabel.trim()}>
                    {creating ? 'Creating…' : 'Create (requires phone)'}
                </button>
            </div>
            {#if createStatus}<p class="status-line">{createStatus}</p>{/if}
        </section>
    {:else if wallets.length === 0}
        <div class="status">No wallets yet. Use “+ New” or create one from your phone.</div>
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
            <div class="wallet-actions">
                <button class:active={mode === 'history'} onclick={() => mode = 'history'}>Activity</button>
                <button class:active={mode === 'send'} onclick={openSend}>Send</button>
                <button class:active={mode === 'receive'} onclick={openReceive}>Receive</button>
            </div>

            {#if mode === 'history'}
                <section class="card">
                    {#if txLoading}
                        <div class="status">Loading…</div>
                    {:else if transactions.length === 0}
                        <div class="status">No transactions yet</div>
                    {:else}
                        <ul class="tx-list">
                            {#each transactions as tx}
                                <li class="tx-item">
                                    <span class="tx-direction {tx.direction}">
                                        {tx.direction === 'received' ? '↓' : '↑'}
                                    </span>
                                    <div class="tx-mid">
                                        <span class="tx-amount {tx.direction}">
                                            {tx.direction === 'received' ? '+' : '-'}{formatBtc(tx.amount_sats)}
                                        </span>
                                        <span class="tx-id mono">{tx.txid.slice(0, 16)}…</span>
                                    </div>
                                    <span class="tx-status" title={tx.confirmed ? 'Confirmed' : 'Pending'}>
                                        {tx.confirmed ? '✓' : '⏳'}
                                    </span>
                                    {#if tx.block_time}
                                        <span class="tx-time">{new Date(tx.block_time).toLocaleDateString()}</span>
                                    {/if}
                                </li>
                            {/each}
                        </ul>
                    {/if}
                </section>
            {:else if mode === 'receive'}
                <section class="card">
                    <h4>Receive to {selectedWallet.label}</h4>
                    <div class="address-box">
                        <span class="mono address">{receiveAddress || selectedWallet.address}</span>
                        <button class="copy" onclick={copyAddress}>Copy</button>
                    </div>
                    {#if copyHint}<p class="status-line">{copyHint}</p>{/if}
                    <p class="hint">Share this address to receive payments. The vault generates fresh addresses on each request.</p>
                </section>
            {:else if mode === 'send'}
                <section class="card">
                    <h4>Send from {selectedWallet.label}</h4>
                    <label class="field">
                        <span>Recipient address</span>
                        <input bind:value={sendTo} placeholder="bc1q… or 1…" class="mono" />
                    </label>
                    <label class="field">
                        <span>Amount (BTC)</span>
                        <input bind:value={sendAmount} type="text" inputmode="decimal" placeholder="0.00010000" class="mono" />
                    </label>
                    {#if feeEstimates}
                        <div class="fee-row">
                            <span>Fee rate</span>
                            <div class="fee-options">
                                <button
                                    class:active={sendFeeRate === feeEstimates.slow}
                                    onclick={() => sendFeeRate = feeEstimates!.slow}
                                >Slow ({feeEstimates.slow} sat/vB)</button>
                                <button
                                    class:active={sendFeeRate === feeEstimates.standard}
                                    onclick={() => sendFeeRate = feeEstimates!.standard}
                                >Standard ({feeEstimates.standard})</button>
                                <button
                                    class:active={sendFeeRate === feeEstimates.fast}
                                    onclick={() => sendFeeRate = feeEstimates!.fast}
                                >Fast ({feeEstimates.fast})</button>
                            </div>
                        </div>
                    {/if}
                    <div class="form-actions">
                        <button class="cancel" onclick={() => mode = 'history'}>Cancel</button>
                        <button class="primary" onclick={submitSend} disabled={sending || !sendTo.trim() || !sendAmount.trim()}>
                            {sending ? 'Submitting…' : 'Send (requires phone)'}
                        </button>
                    </div>
                    {#if sendStatus}<p class="status-line">{sendStatus}</p>{/if}
                </section>
            {/if}
        {/if}
    {/if}
</div>

<style>
    .wallet-view { height: 100%; overflow-y: auto; }
    .header { display: flex; justify-content: space-between; align-items: center; padding: 0 0 12px; }
    .header h3 { margin: 0; }
    .header-actions { display: flex; gap: 8px; }
    .action-btn { background: var(--accent); color: #000; border: none; border-radius: 4px; padding: 6px 12px; cursor: pointer; font-weight: 500; }
    .refresh { background: none; border: 1px solid var(--border); border-radius: 4px; cursor: pointer; padding: 4px 8px; color: inherit; }

    .status { color: var(--text-secondary); padding: 24px; text-align: center; }
    .status.error { color: var(--danger); }

    .wallet-list { display: flex; gap: 10px; flex-wrap: wrap; }
    .wallet-card {
        text-align: left; padding: 14px; border: 1px solid var(--border); border-radius: 8px;
        background: var(--surface, #1a1a1a); cursor: pointer; min-width: 200px;
        color: inherit; font: inherit;
    }
    .wallet-card:hover { background: var(--surface-hover, #222); }
    .wallet-card.active { border-color: var(--accent); background: rgba(255, 193, 37, 0.08); }
    .wallet-label { font-weight: 600; }
    .wallet-balance { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin: 4px 0; }
    .wallet-meta { display: flex; gap: 6px; font-size: 0.75em; }
    .network { padding: 1px 6px; border-radius: 3px; text-transform: uppercase; }
    .network.mainnet { background: rgba(230, 81, 0, 0.2); color: #ff9800; }
    .network.testnet { background: rgba(21, 101, 192, 0.2); color: #64b5f6; }
    .public { color: var(--text-secondary); }

    .wallet-actions { display: flex; gap: 6px; margin: 16px 0 8px; }
    .wallet-actions button {
        background: none; border: 1px solid var(--border); border-radius: 4px;
        padding: 6px 14px; cursor: pointer; color: inherit; font: inherit;
    }
    .wallet-actions button.active { background: var(--accent); color: #000; border-color: var(--accent); font-weight: 500; }

    .card {
        background: var(--surface, #1a1a1a);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
    }
    .card h4 { margin: 0 0 12px; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); }

    .field { display: flex; flex-direction: column; gap: 4px; margin-bottom: 12px; }
    .field span { font-size: 0.85em; color: var(--text-secondary); }
    .field input, .field select {
        background: #1c1c1c; color: inherit;
        border: 1px solid var(--border); border-radius: 4px;
        padding: 8px 10px; font: inherit;
    }
    .field input.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }

    .fee-row { display: flex; flex-direction: column; gap: 6px; margin-bottom: 12px; }
    .fee-row > span { font-size: 0.85em; color: var(--text-secondary); }
    .fee-options { display: flex; gap: 6px; flex-wrap: wrap; }
    .fee-options button {
        background: #1c1c1c; color: inherit; font: inherit;
        border: 1px solid var(--border); border-radius: 4px;
        padding: 6px 10px; cursor: pointer; font-size: 0.85em;
    }
    .fee-options button.active { background: var(--accent); color: #000; border-color: var(--accent); }

    .form-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 8px; }
    .cancel, .primary {
        padding: 8px 14px; border-radius: 4px; cursor: pointer; font: inherit;
        border: 1px solid var(--border);
    }
    .cancel { background: transparent; color: inherit; }
    .primary { background: var(--accent); color: #000; border-color: var(--accent); font-weight: 500; }
    .cancel:disabled, .primary:disabled { opacity: 0.5; cursor: not-allowed; }

    .address-box {
        display: flex; gap: 8px; align-items: center;
        padding: 10px; background: #1c1c1c; border-radius: 4px; border: 1px solid var(--border);
    }
    .address { flex: 1; word-break: break-all; }
    .copy {
        background: var(--accent); color: #000; border: none; border-radius: 4px;
        padding: 6px 12px; cursor: pointer; font-weight: 500;
    }

    .status-line { font-size: 0.85em; color: var(--text-primary); margin: 8px 0 0; }
    .hint { font-size: 0.8em; color: var(--text-secondary); margin: 8px 0 0; }

    .tx-list { list-style: none; padding: 0; margin: 0; }
    .tx-item {
        display: flex; gap: 10px; align-items: center;
        padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.06);
        font-size: 0.9em;
    }
    .tx-item:last-child { border-bottom: none; }
    .tx-direction { font-size: 1.2em; }
    .tx-direction.received { color: #4caf50; }
    .tx-direction.sent { color: var(--text-secondary); }
    .tx-mid { display: flex; flex-direction: column; flex: 1; min-width: 0; }
    .tx-amount { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    .tx-amount.received { color: #4caf50; }
    .tx-id { font-size: 0.75em; color: var(--text-secondary); }
    .tx-time { color: var(--text-secondary); font-size: 0.8em; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
</style>

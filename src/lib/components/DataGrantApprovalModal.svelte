<script lang="ts">
    import { invoke } from '@tauri-apps/api/core';
    import { listen, type UnlistenFn } from '@tauri-apps/api/event';
    import { onMount, onDestroy } from 'svelte';
    import { modal } from '../actions/modal';
    import {
        listPending,
        approveRequest,
        denyRequest,
        type PendingRequestSummary,
    } from '../grants';
    import type { Connection } from '../types';

    // App-level modal — surfaces incoming grant requests so the user
    // can approve or deny without going to a dedicated screen. Polls
    // grant.list-pending on mount and whenever a
    // `connection.data-request-received` push lands (routed by the
    // listener through `vault:connection-event`).

    let pending = $state<PendingRequestSummary[]>([]);
    let peerNames = $state<Record<string, string>>({});
    let activeIndex = $state(0);
    let busy = $state(false);
    let error = $state('');
    // Inline state for the approval form — user can tighten down
    // duration / max-uses below what the peer asked for.
    let expiresAtChoice = $state<'1h' | '24h' | '7d' | '30d' | 'never'>('24h');
    let maxUsesChoice = $state<'1' | '5' | 'unlimited'>('1');
    let denyReason = $state('');
    let mode = $state<'approve' | 'deny'>('approve');

    let unlisten: UnlistenFn | null = null;
    let dismissedRequestIds = $state(new Set<string>());

    function visiblePending(): PendingRequestSummary[] {
        return pending.filter((p) => !dismissedRequestIds.has(p.request_id));
    }

    let visible = $derived(visiblePending());
    let active = $derived(visible[activeIndex] ?? null);
    let open = $derived(active !== null);

    async function refresh() {
        try {
            pending = await listPending();
            // Reset to the first non-dismissed when the list changes.
            activeIndex = 0;
        } catch (e) {
            console.warn('grant.list-pending failed', e);
        }
    }

    async function loadPeerNames() {
        try {
            const resp: any = await invoke('list_connections');
            const conns = (resp?.data?.connections ?? []) as Connection[];
            const map: Record<string, string> = {};
            for (const c of conns) {
                if (c.peer_guid) {
                    map[c.peer_guid] = c.peer_profile?.full_name
                        ?? c.peer_alias
                        ?? c.peer_guid.slice(0, 8);
                }
                if (c.connection_id) {
                    map[c.connection_id] = c.peer_profile?.full_name
                        ?? c.peer_alias
                        ?? c.connection_id.slice(0, 8);
                }
            }
            peerNames = map;
        } catch (e) {
            console.warn('list_connections failed', e);
        }
    }

    onMount(() => {
        void refresh();
        void loadPeerNames();
        listen<{ subject: string; payload_b64: string }>('vault:connection-event', (event) => {
            const subject = event.payload?.subject ?? '';
            if (subject.includes('data-request-received') || subject.includes('data-grant')) {
                void refresh();
            }
        }).then((fn) => { unlisten = fn; });
    });

    onDestroy(() => { unlisten?.(); });

    function peerLabel(p: PendingRequestSummary): string {
        return peerNames[p.connection_id] ?? peerNames[p.requester_guid] ?? p.requester_guid.slice(0, 12);
    }

    function expiresAtSeconds(): number | undefined {
        const now = Math.floor(Date.now() / 1000);
        switch (expiresAtChoice) {
            case '1h': return now + 3600;
            case '24h': return now + 86400;
            case '7d': return now + 604800;
            case '30d': return now + 2592000;
            case 'never': return undefined;
        }
    }

    function maxUsesValue(): number | undefined {
        if (maxUsesChoice === 'unlimited') return undefined;
        return parseInt(maxUsesChoice, 10);
    }

    async function approve() {
        if (!active || busy) return;
        busy = true;
        error = '';
        try {
            await approveRequest(active.request_id, expiresAtSeconds(), maxUsesValue());
            dismissedRequestIds.add(active.request_id);
            dismissedRequestIds = new Set(dismissedRequestIds);
            mode = 'approve';
            await refresh();
        } catch (e) {
            error = String(e);
        }
        busy = false;
    }

    async function deny() {
        if (!active || busy) return;
        busy = true;
        error = '';
        try {
            await denyRequest(active.request_id, denyReason.trim() || undefined);
            dismissedRequestIds.add(active.request_id);
            dismissedRequestIds = new Set(dismissedRequestIds);
            denyReason = '';
            mode = 'approve';
            await refresh();
        } catch (e) {
            error = String(e);
        }
        busy = false;
    }

    function dismiss() {
        // Snooze — does not approve or deny on the vault. Just hides
        // this row until the next push or a refresh re-loads pending.
        if (!active) return;
        dismissedRequestIds.add(active.request_id);
        dismissedRequestIds = new Set(dismissedRequestIds);
        mode = 'approve';
    }

    function formatItemKind(k: string): string {
        if (k === 'data') return '📇 Personal data';
        if (k === 'secret') return '🔑 Secret';
        if (k === 'wallet') return '₿ Wallet';
        if (k === 'handler') return '🧩 Handler';
        return k;
    }
</script>

{#if open && active}
    <div class="modal-backdrop" role="presentation"></div>
    <div
        class="modal"
        role="dialog"
        aria-modal="true"
        aria-label="Data request"
        use:modal={{ onEscape: dismiss }}
    >
        <header class="modal-head">
            <div class="head-text">
                <h2>Data request</h2>
                <p class="head-sub">from {peerLabel(active)}</p>
            </div>
            {#if visible.length > 1}
                <span class="count-pill">{activeIndex + 1} of {visible.length}</span>
            {/if}
            <button class="x-btn" onclick={dismiss} aria-label="Snooze">✕</button>
        </header>

        <div class="body">
            <div class="item-card">
                <div class="kind">{formatItemKind(active.item_kind)}</div>
                <div class="label">{active.item_label || active.item_ref}</div>
                {#if active.items.length > 1}
                    <ul class="item-list">
                        {#each active.items as item}
                            <li>
                                <span class="kind-mini">{formatItemKind(item.item_kind)}</span>
                                {item.item_label || item.item_ref}
                            </li>
                        {/each}
                    </ul>
                {/if}
            </div>

            {#if active.reason}
                <div class="reason"><span class="lbl">Reason:</span> {active.reason}</div>
            {/if}

            {#if mode === 'approve'}
                <div class="form">
                    <label class="field">
                        <span class="field-label">Expires</span>
                        <select bind:value={expiresAtChoice}>
                            <option value="1h">1 hour</option>
                            <option value="24h">24 hours</option>
                            <option value="7d">7 days</option>
                            <option value="30d">30 days</option>
                            <option value="never">Never</option>
                        </select>
                    </label>
                    <label class="field">
                        <span class="field-label">Max uses</span>
                        <select bind:value={maxUsesChoice}>
                            <option value="1">1</option>
                            <option value="5">5</option>
                            <option value="unlimited">Unlimited</option>
                        </select>
                    </label>
                </div>
            {:else}
                <label class="field">
                    <span class="field-label">Reason (optional)</span>
                    <input
                        type="text"
                        bind:value={denyReason}
                        placeholder="Why are you denying?"
                        maxlength="140"
                    />
                </label>
            {/if}

            {#if error}<div class="error">{error}</div>{/if}
        </div>

        <div class="actions">
            {#if mode === 'approve'}
                <button class="btn ghost" onclick={() => (mode = 'deny')} disabled={busy}>Deny</button>
                <button class="btn primary" onclick={approve} disabled={busy}>
                    {busy ? 'Approving…' : 'Approve'}
                </button>
            {:else}
                <button class="btn ghost" onclick={() => (mode = 'approve')} disabled={busy}>Back</button>
                <button class="btn danger" onclick={deny} disabled={busy}>
                    {busy ? 'Denying…' : 'Confirm deny'}
                </button>
            {/if}
        </div>
    </div>
{/if}

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
        width: 460px;
        max-width: calc(100vw - 48px);
        max-height: calc(100vh - 64px);
        display: flex;
        flex-direction: column;
        box-shadow: 0 18px 50px rgba(0, 0, 0, 0.5);
    }
    .modal-head {
        display: flex;
        align-items: flex-start;
        gap: 12px;
        padding: 18px 22px 10px;
    }
    .head-text { flex: 1; }
    .modal-head h2 { font-size: 1.05rem; margin: 0; font-weight: 600; }
    .head-sub { font-size: 0.85rem; color: var(--text-secondary); margin: 2px 0 0; }
    .count-pill {
        font-size: 0.75em;
        padding: 3px 8px;
        border-radius: 999px;
        background: rgba(255,193,37,0.15);
        color: var(--accent);
    }
    .x-btn {
        background: transparent;
        border: none;
        color: var(--text-secondary);
        cursor: pointer;
        font-size: 1rem;
        padding: 2px 8px;
        border-radius: 4px;
    }
    .x-btn:hover { background: rgba(255,255,255,0.06); color: var(--text); }

    .body { padding: 6px 22px 12px; overflow-y: auto; }

    .item-card {
        background: rgba(255, 193, 37, 0.06);
        border: 1px solid rgba(255, 193, 37, 0.25);
        border-radius: 8px;
        padding: 12px 14px;
        margin-bottom: 12px;
    }
    .kind { font-size: 0.78rem; color: var(--accent); text-transform: uppercase; letter-spacing: 0.04em; }
    .label { font-size: 1.05rem; font-weight: 500; margin-top: 4px; }
    .item-list {
        list-style: none;
        margin: 8px 0 0;
        padding: 0;
        display: flex;
        flex-direction: column;
        gap: 4px;
    }
    .item-list li {
        font-size: 0.85rem;
        display: flex;
        gap: 8px;
        align-items: baseline;
    }
    .kind-mini {
        color: var(--text-secondary);
        font-size: 0.75em;
        width: 110px;
        flex-shrink: 0;
    }

    .reason {
        background: rgba(255,255,255,0.04);
        border-radius: 6px;
        padding: 8px 12px;
        margin-bottom: 12px;
        font-size: 0.88rem;
    }
    .reason .lbl { color: var(--text-secondary); margin-right: 6px; }

    .form { display: flex; gap: 10px; }
    .field { flex: 1; display: flex; flex-direction: column; gap: 6px; margin-bottom: 12px; }
    .field-label { font-size: 0.72rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; }
    .field input, .field select {
        background: var(--bg);
        border: 1px solid rgba(255,255,255,0.08);
        color: var(--text);
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 0.92rem;
        outline: none;
        width: 100%;
        box-sizing: border-box;
    }
    .field input:focus, .field select:focus { border-color: var(--accent); }

    .error {
        background: rgba(244, 67, 54, 0.12);
        border: 1px solid rgba(244, 67, 54, 0.3);
        color: #ef5350;
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 0.85rem;
        margin-top: 8px;
    }

    .actions {
        display: flex;
        gap: 8px;
        padding: 12px 22px 18px;
        justify-content: flex-end;
        border-top: 1px solid rgba(255,255,255,0.05);
    }
    .btn {
        font: inherit;
        font-size: 0.9rem;
        padding: 8px 16px;
        border-radius: 6px;
        border: 1px solid transparent;
        cursor: pointer;
    }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn.ghost {
        background: transparent;
        color: var(--text-secondary);
        border-color: rgba(255,255,255,0.1);
    }
    .btn.ghost:hover:not(:disabled) { background: rgba(255,255,255,0.05); }
    .btn.primary {
        background: var(--accent);
        color: #1a1a1a;
        font-weight: 600;
    }
    .btn.primary:hover:not(:disabled) { background: var(--accent-hover); }
    .btn.danger {
        background: #c62828;
        color: #fff;
        font-weight: 600;
    }
    .btn.danger:hover:not(:disabled) { background: #b71c1c; }
</style>

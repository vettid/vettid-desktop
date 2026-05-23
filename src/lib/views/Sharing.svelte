<script lang="ts">
    import { invoke } from '@tauri-apps/api/core';
    import { listen, type UnlistenFn } from '@tauri-apps/api/event';
    import { onMount, onDestroy } from 'svelte';
    import {
        listInbound,
        listOutbound,
        listMyRequests,
        revokeGrant,
        fetchRemoteValue,
        type GrantSummary,
        type OutgoingRequestSummary,
    } from '../grants';
    import type { Connection } from '../types';

    // Three-tab data-sharing dashboard, mirroring Android GrantsScreen.
    //   Granted to me   → list_inbound  (peers have given me access)
    //   I have granted  → list_outbound (I have given peers access)
    //   My requests     → list_my_requests (pending + responded)
    // Incoming pending requests are handled by DataGrantApprovalModal
    // at the app level; this screen surfaces the steady-state grants.

    type TabId = 'granted-to-me' | 'i-have-granted' | 'my-requests';
    const tabs: { id: TabId; label: string }[] = [
        { id: 'granted-to-me', label: 'Granted to me' },
        { id: 'i-have-granted', label: 'I have granted' },
        { id: 'my-requests', label: 'My requests' },
    ];
    let activeTab = $state<TabId>('granted-to-me');

    let inbound = $state<GrantSummary[]>([]);
    let outbound = $state<GrantSummary[]>([]);
    let myRequests = $state<OutgoingRequestSummary[]>([]);
    let loading = $state(true);
    let error = $state('');

    // Peer name resolution — once per page load, off connection.list.
    let peerByGuid = $state<Record<string, string>>({});
    let peerByConn = $state<Record<string, string>>({});

    // Per-grant action state — fetch / revoke in flight.
    let actionState = $state<Record<string, { busy: boolean; msg?: string; err?: string }>>({});
    // Per-grant revealed value (after grant.fetch-remote). Sticky for
    // the page session — refresh clears.
    let revealed = $state<Record<string, string>>({});

    let unlisten: UnlistenFn | null = null;

    function peerLabel(connId: string, guid?: string): string {
        return peerByConn[connId] ?? (guid ? peerByGuid[guid] : '') ?? connId.slice(0, 8);
    }

    async function loadAll() {
        loading = true;
        error = '';
        try {
            const [conns, ib, ob, mr] = await Promise.all([
                invoke('list_connections') as Promise<any>,
                listInbound(),
                listOutbound(),
                listMyRequests(),
            ]);
            const list = (conns?.data?.connections ?? []) as Connection[];
            const cg: Record<string, string> = {};
            const cc: Record<string, string> = {};
            for (const c of list) {
                const name = c.peer_profile?.full_name ?? c.peer_alias ?? c.connection_id?.slice(0, 8) ?? '?';
                if (c.peer_guid) cg[c.peer_guid] = name;
                if (c.connection_id) cc[c.connection_id] = name;
            }
            peerByGuid = cg;
            peerByConn = cc;
            inbound = ib;
            outbound = ob;
            myRequests = mr;
        } catch (e) {
            error = String(e);
        }
        loading = false;
    }

    onMount(() => {
        void loadAll();
        // Live refresh on any grant lifecycle push.
        listen<{ subject: string; payload_b64: string }>('vault:connection-event', (event) => {
            const subject = event.payload?.subject ?? '';
            if (subject.includes('data-grant') || subject.includes('data-request')) {
                void loadAll();
            }
        }).then((fn) => { unlisten = fn; });
    });

    onDestroy(() => { unlisten?.(); });

    function fmtExpires(unix: number): string {
        if (!unix) return 'never';
        const d = new Date(unix * 1000);
        const diff = unix * 1000 - Date.now();
        if (diff < 0) return 'expired';
        const days = Math.floor(diff / 86400000);
        if (days >= 1) return `in ${days}d`;
        const hrs = Math.floor(diff / 3600000);
        if (hrs >= 1) return `in ${hrs}h`;
        const min = Math.max(1, Math.floor(diff / 60000));
        return `in ${min}m`;
    }

    function fmtDate(unix: number): string {
        if (!unix) return '';
        return new Date(unix * 1000).toLocaleString();
    }

    async function doFetch(g: GrantSummary) {
        actionState = { ...actionState, [g.grant_id]: { busy: true } };
        try {
            const data = (await fetchRemoteValue(g.grant_id)) as Record<string, unknown>;
            const value = (data?.value ?? data?.data ?? data?.payload) as unknown;
            const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
            revealed = { ...revealed, [g.grant_id]: text };
            actionState = { ...actionState, [g.grant_id]: { busy: false } };
            // Bump uses-so-far locally; the next push will reconcile.
            inbound = inbound.map((x) =>
                x.grant_id === g.grant_id ? { ...x, uses_so_far: x.uses_so_far + 1 } : x,
            );
        } catch (e) {
            actionState = {
                ...actionState,
                [g.grant_id]: { busy: false, err: String(e) },
            };
        }
    }

    async function doRevoke(g: GrantSummary) {
        const ok = confirm(`Revoke grant for "${g.item_label}"? The peer will lose access immediately.`);
        if (!ok) return;
        actionState = { ...actionState, [g.grant_id]: { busy: true } };
        try {
            await revokeGrant(g.grant_id);
            // Pull from local lists; the push will reconcile too.
            outbound = outbound.filter((x) => x.grant_id !== g.grant_id);
            actionState = { ...actionState, [g.grant_id]: { busy: false } };
        } catch (e) {
            actionState = {
                ...actionState,
                [g.grant_id]: { busy: false, err: String(e) },
            };
        }
    }

    function kindIcon(k: string): string {
        if (k === 'data') return '📇';
        if (k === 'secret') return '🔑';
        if (k === 'wallet') return '₿';
        if (k === 'handler') return '🧩';
        return '•';
    }
</script>

<div class="sharing">
    <header class="hero">
        <h1>Sharing</h1>
        <p class="sub">Who has access to what — data you've shared with peers, and access peers have given you.</p>
    </header>

    <nav class="tabs" role="tablist">
        {#each tabs as tab}
            <button
                role="tab"
                aria-selected={activeTab === tab.id}
                class:active={activeTab === tab.id}
                onclick={() => (activeTab = tab.id)}
            >{tab.label}</button>
        {/each}
    </nav>

    {#if loading}
        <div class="status">Loading…</div>
    {:else if error}
        <div class="status error">{error}</div>
    {:else}
        {#if activeTab === 'granted-to-me'}
            {#if inbound.length === 0}
                <div class="empty">No active grants. Request access from a peer's profile to see them here.</div>
            {:else}
                <ul class="list">
                    {#each inbound as g (g.grant_id)}
                        {@const action = actionState[g.grant_id]}
                        <li class="card">
                            <div class="card-head">
                                <span class="icon">{kindIcon(g.item_kind)}</span>
                                <div class="title-block">
                                    <div class="title">{g.item_label || g.item_ref}</div>
                                    <div class="sub-line">from {peerLabel(g.connection_id, g.granter_guid)}</div>
                                </div>
                                <span class="status-pill {g.status}">{g.status}</span>
                            </div>
                            <dl class="meta">
                                <dt>Mode</dt><dd>{g.mode}</dd>
                                <dt>Expires</dt><dd>{fmtExpires(g.expires_at)}</dd>
                                <dt>Uses</dt><dd>{g.uses_so_far}{g.max_uses ? ` / ${g.max_uses}` : ''}</dd>
                                {#if g.last_fetched}<dt>Last fetched</dt><dd>{fmtDate(g.last_fetched)}</dd>{/if}
                            </dl>
                            {#if revealed[g.grant_id]}
                                <pre class="revealed">{revealed[g.grant_id]}</pre>
                            {/if}
                            <div class="row-actions">
                                <button
                                    class="btn primary"
                                    onclick={() => doFetch(g)}
                                    disabled={action?.busy || g.status !== 'active'}
                                >{action?.busy ? 'Fetching…' : (revealed[g.grant_id] ? 'Fetch again' : 'Fetch value')}</button>
                            </div>
                            {#if action?.err}<div class="row-err">{action.err}</div>{/if}
                        </li>
                    {/each}
                </ul>
            {/if}
        {:else if activeTab === 'i-have-granted'}
            {#if outbound.length === 0}
                <div class="empty">You haven't granted any access yet. Pending requests show up here once you approve them.</div>
            {:else}
                <ul class="list">
                    {#each outbound as g (g.grant_id)}
                        {@const action = actionState[g.grant_id]}
                        <li class="card">
                            <div class="card-head">
                                <span class="icon">{kindIcon(g.item_kind)}</span>
                                <div class="title-block">
                                    <div class="title">{g.item_label || g.item_ref}</div>
                                    <div class="sub-line">to {peerLabel(g.connection_id, g.requester_guid)}</div>
                                </div>
                                <span class="status-pill {g.status}">{g.status}</span>
                            </div>
                            <dl class="meta">
                                <dt>Mode</dt><dd>{g.mode}</dd>
                                <dt>Expires</dt><dd>{fmtExpires(g.expires_at)}</dd>
                                <dt>Uses</dt><dd>{g.uses_so_far}{g.max_uses ? ` / ${g.max_uses}` : ''}</dd>
                                {#if g.last_fetched}<dt>Last fetched</dt><dd>{fmtDate(g.last_fetched)}</dd>{/if}
                            </dl>
                            <div class="row-actions">
                                <button
                                    class="btn danger"
                                    onclick={() => doRevoke(g)}
                                    disabled={action?.busy || g.status !== 'active'}
                                >{action?.busy ? 'Revoking…' : 'Revoke'}</button>
                            </div>
                            {#if action?.err}<div class="row-err">{action.err}</div>{/if}
                        </li>
                    {/each}
                </ul>
            {/if}
        {:else if activeTab === 'my-requests'}
            {#if myRequests.length === 0}
                <div class="empty">No outgoing requests. Browse a peer's profile to request access.</div>
            {:else}
                <ul class="list">
                    {#each myRequests as r (r.request_id)}
                        <li class="card">
                            <div class="card-head">
                                <span class="icon">{kindIcon(r.item_kind)}</span>
                                <div class="title-block">
                                    <div class="title">{r.item_label || r.item_ref}</div>
                                    <div class="sub-line">to {peerLabel(r.connection_id)}</div>
                                </div>
                                <span class="status-pill {r.status}">{r.status}</span>
                            </div>
                            <dl class="meta">
                                <dt>Mode</dt><dd>{r.mode}</dd>
                                {#if r.reason}<dt>Reason</dt><dd>{r.reason}</dd>{/if}
                                <dt>Sent</dt><dd>{fmtDate(r.created_at)}</dd>
                                {#if r.responded_at}<dt>Responded</dt><dd>{fmtDate(r.responded_at)}</dd>{/if}
                                {#if r.status === 'denied' && r.denial_reason}
                                    <dt>Denial reason</dt><dd>{r.denial_reason}</dd>
                                {/if}
                            </dl>
                        </li>
                    {/each}
                </ul>
            {/if}
        {/if}
    {/if}
</div>

<style>
    .sharing { padding: 24px; max-width: 860px; margin: 0 auto; height: 100%; box-sizing: border-box; overflow-y: auto; }
    .hero h1 { margin: 0 0 4px; font-size: 1.4rem; }
    .sub { color: var(--text-secondary); font-size: 0.9rem; margin: 0 0 18px; }

    .tabs {
        display: flex;
        gap: 6px;
        border-bottom: 1px solid var(--border);
        margin-bottom: 16px;
    }
    .tabs button {
        background: none;
        border: none;
        color: var(--text-secondary);
        padding: 8px 14px;
        font: inherit;
        font-size: 0.92rem;
        cursor: pointer;
        border-bottom: 2px solid transparent;
        margin-bottom: -1px;
    }
    .tabs button.active { color: var(--accent); border-bottom-color: var(--accent); }

    .status { padding: 32px; text-align: center; color: var(--text-secondary); }
    .status.error { color: var(--danger); }
    .empty {
        padding: 32px 16px;
        text-align: center;
        color: var(--text-secondary);
        background: var(--surface);
        border: 1px dashed var(--border);
        border-radius: 8px;
    }

    .list {
        list-style: none;
        padding: 0;
        margin: 0;
        display: flex;
        flex-direction: column;
        gap: 10px;
    }
    .card {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 14px 16px;
    }
    .card-head {
        display: flex;
        gap: 12px;
        align-items: center;
        margin-bottom: 10px;
    }
    .icon { font-size: 1.4em; }
    .title-block { flex: 1; min-width: 0; }
    .title { font-size: 0.98rem; font-weight: 500; }
    .sub-line { font-size: 0.78rem; color: var(--text-secondary); margin-top: 2px; }
    .status-pill {
        font-size: 0.7em;
        padding: 2px 8px;
        border-radius: 999px;
        background: rgba(46,125,50,0.18);
        color: #4caf50;
        text-transform: capitalize;
    }
    .status-pill.revoked, .status-pill.denied { background: rgba(198,40,40,0.18); color: #ef5350; }
    .status-pill.expired, .status-pill.pending { background: rgba(255,152,0,0.18); color: #ff9800; }

    .meta { display: grid; grid-template-columns: 110px 1fr; gap: 4px 12px; margin: 0 0 10px; font-size: 0.85rem; }
    .meta dt { color: var(--text-secondary); }
    .meta dd { margin: 0; word-break: break-word; }

    .revealed {
        background: var(--bg);
        border: 1px solid var(--border);
        border-radius: 6px;
        padding: 10px 12px;
        margin: 6px 0 10px;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        font-size: 0.82rem;
        white-space: pre-wrap;
        word-break: break-word;
        max-height: 200px;
        overflow-y: auto;
    }

    .row-actions { display: flex; gap: 8px; justify-content: flex-end; }
    .row-err {
        margin-top: 8px;
        padding: 6px 8px;
        background: rgba(244,67,54,0.12);
        border: 1px solid rgba(244,67,54,0.3);
        border-radius: 4px;
        color: #ef5350;
        font-size: 0.78rem;
    }
    .btn {
        font: inherit;
        font-size: 0.85rem;
        padding: 6px 14px;
        border-radius: 6px;
        cursor: pointer;
        border: 1px solid transparent;
    }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn.primary {
        background: var(--accent);
        color: #1a1a1a;
        font-weight: 600;
    }
    .btn.primary:hover:not(:disabled) { background: var(--accent-hover); }
    .btn.danger {
        background: transparent;
        color: #ef5350;
        border-color: rgba(244,67,54,0.4);
    }
    .btn.danger:hover:not(:disabled) { background: rgba(244,67,54,0.12); }
</style>

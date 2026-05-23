<script lang="ts">
    import { onMount } from 'svelte';
    import { invoke } from '@tauri-apps/api/core';
    import type { Connection, VaultOpResponse } from '../../types';
    import { selectedConnectionStore } from '../../stores/navigation';
    import { connectionsStore } from '../../stores/vault';
    import { peerName } from '../../connectionName';
    import { formatRelativeOrAbsolute } from '../../time';
    import Avatar from '../../components/Avatar.svelte';
    import StatusChip from '../../components/StatusChip.svelte';

    // The vault store owns the canonical list — it's refreshed by
    // initVaultListeners() on connection/message push events, so reading
    // from the store gives us live updates without an extra subscription
    // here. The local invoke below is just for explicit error-handling
    // on the initial load (the store's loadConnections() is silent on
    // failure by design — the listeners are best-effort).
    let connections = $derived($connectionsStore);
    let loading = $state(true);
    let error = $state('');
    let search = $state('');

    type SortOrder = 'recent' | 'alpha' | 'created';
    let sort: SortOrder = $state('recent');

    // Active vs archived split — mirrors Android's Connection History
    // screen. Active (status active|pending) is the main list; archived
    // (revoked|expired) sits behind a "Connection history" card at the
    // bottom and gets its own view.
    type ViewMode = 'active' | 'history';
    let viewMode: ViewMode = $state('active');
    function isArchived(c: Connection): boolean {
        return c.status === 'revoked' || c.status === 'expired';
    }
    let historyCount = $derived(connections.filter(isArchived).length);

    // Highlight the currently-selected connection's card. Read via
    // $derived so the highlight tracks the store across the parent
    // shell's swap to/from Conversation/Detail.
    let selectedId = $derived($selectedConnectionStore?.connection_id);

    function openConnection(conn: Connection): void {
        selectedConnectionStore.set(conn);
    }

    async function loadConnections() {
        loading = connections.length === 0;
        error = '';
        try {
            const resp: VaultOpResponse = await invoke('list_connections');
            if (resp.success && resp.data) {
                const data = resp.data as { connections?: Connection[] };
                // Write into the shared store so anything else subscribed
                // (notifications, etc.) sees the fresh list too.
                connectionsStore.set(data.connections ?? []);
            } else {
                error = resp.error ?? 'Failed to load connections';
            }
        } catch (e) {
            error = String(e);
        }
        loading = false;
    }

    // Subtitle preference mirrors Android: a recent message preview if
    // we have one; otherwise the most recent activity title; otherwise
    // when the connection was made.
    function subtitle(c: Connection): string {
        if (c.last_message_preview) {
            const when = formatRelativeOrAbsolute(c.last_message_at);
            return when ? `${c.last_message_preview} · ${when}` : c.last_message_preview;
        }
        if (c.last_activity_title) {
            const when = formatRelativeOrAbsolute(c.last_activity_at);
            return when ? `${c.last_activity_title} · ${when}` : c.last_activity_title;
        }
        const when = formatRelativeOrAbsolute(c.created_at);
        return when ? `Connected ${when}` : '';
    }

    function lastActivityTs(c: Connection): number {
        const ts = [c.last_message_at, c.last_activity_at, c.last_active_at, c.created_at]
            .map((s) => (s ? Date.parse(s) : 0))
            .filter((n) => !Number.isNaN(n) && n > 0);
        return ts.length ? Math.max(...ts) : 0;
    }

    let visible = $derived.by(() => {
        const base = connections.filter((c) =>
            viewMode === 'history' ? isArchived(c) : !isArchived(c),
        );
        const q = search.trim().toLowerCase();
        const filtered = q
            ? base.filter((c) => peerName(c).toLowerCase().includes(q))
            : base.slice();
        switch (sort) {
            case 'alpha':
                filtered.sort((a, b) => peerName(a).localeCompare(peerName(b)));
                break;
            case 'created':
                filtered.sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
                break;
            case 'recent':
            default:
                // Unread floats to the top, then most-recent-activity
                // descending — same rule the Android list uses.
                filtered.sort((a, b) => {
                    const au = (a.unread_count ?? 0) > 0 ? 1 : 0;
                    const bu = (b.unread_count ?? 0) > 0 ? 1 : 0;
                    if (au !== bu) return bu - au;
                    return lastActivityTs(b) - lastActivityTs(a);
                });
                break;
        }
        return filtered;
    });

    function typeBadge(c: Connection): string {
        // Only flag the non-peer kinds; peer is the default and would
        // just add visual noise.
        if (c.connection_type === 'agent') return 'agent';
        if (c.connection_type === 'device') return 'device';
        return '';
    }

    onMount(() => { loadConnections(); });
</script>

<div class="connections-list">
    <div class="header">
        <div class="header-left">
            {#if viewMode === 'history'}
                <button class="back-btn" onclick={() => (viewMode = 'active')} aria-label="Back to connections">←</button>
            {/if}
            <h3>{viewMode === 'history' ? 'Connection history' : 'Connections'}</h3>
        </div>
        <button class="refresh" aria-label="Refresh" onclick={loadConnections}>↻</button>
    </div>

    <div class="toolbar">
        <input
            type="search"
            class="search"
            placeholder="Search"
            aria-label="Search connections"
            bind:value={search}
        />
        <select class="sort" bind:value={sort} aria-label="Sort connections">
            <option value="recent">Recent</option>
            <option value="alpha">A–Z</option>
            <option value="created">Date added</option>
        </select>
    </div>

    {#if loading && connections.length === 0}
        <div class="status">Loading connections…</div>
    {:else if error}
        <div class="status error">{error}</div>
    {:else if visible.length === 0}
        {#if search.trim()}
            <div class="status">No connections match "{search}".</div>
        {:else if viewMode === 'history'}
            <div class="empty">
                <div class="empty-icon" aria-hidden="true">🗄️</div>
                <p class="empty-title">No connection history</p>
                <p class="empty-hint">
                    Revoked, declined, and expired connections will show up here.
                </p>
            </div>
        {:else}
            <div class="empty">
                <div class="empty-icon" aria-hidden="true">👥</div>
                <p class="empty-title">No connections yet</p>
                <p class="empty-hint">
                    New connections are created from your VettID phone app —
                    invite or scan from there and they'll show up here.
                </p>
            </div>
        {/if}
    {:else}
        <ul class="list">
            {#each visible as conn (conn.connection_id)}
                {@const unread = conn.unread_count ?? 0}
                {@const missed = conn.missed_call_count ?? 0}
                {@const tBadge = typeBadge(conn)}
                <li>
                    <button
                        type="button"
                        class="card"
                        class:selected={selectedId === conn.connection_id}
                        class:needs-attention={conn.needs_attention}
                        onclick={() => openConnection(conn)}
                    >
                        <Avatar name={peerName(conn)} photo={conn.peer_profile?.photo} size={40} />
                        <div class="card-text">
                            <div class="row1">
                                <span class="name">{peerName(conn)}</span>
                                {#if tBadge}<span class="type-badge">{tBadge}</span>{/if}
                                {#if missed > 0}
                                    <span class="missed-tag" title="{missed} missed call{missed === 1 ? '' : 's'}">
                                        📵 {missed}
                                    </span>
                                {/if}
                            </div>
                            <div class="row2">{subtitle(conn)}</div>
                        </div>
                        <div class="card-meta">
                            {#if unread > 0}
                                <span class="unread" aria-label="{unread} unread">
                                    {unread > 99 ? '99+' : unread}
                                </span>
                            {/if}
                            <StatusChip status={conn.status} />
                        </div>
                    </button>
                </li>
            {/each}
        </ul>
        {#if viewMode === 'active' && historyCount > 0}
            <button class="history-link" onclick={() => (viewMode = 'history')}>
                <span class="history-label">Connection history</span>
                <span class="history-count">{historyCount}</span>
                <span class="history-chevron">›</span>
            </button>
        {/if}
    {/if}
</div>

<style>
    .connections-list { height: 100%; display: flex; flex-direction: column; min-height: 0; }

    .header { display: flex; justify-content: space-between; align-items: center; padding: 0 0 10px; }
    .header h3 { margin: 0; }
    .refresh {
        background: none;
        border: 1px solid var(--border);
        border-radius: 4px;
        cursor: pointer;
        padding: 4px 8px;
        color: inherit;
    }

    .toolbar { display: flex; gap: 8px; padding: 0 0 10px; }
    .search {
        flex: 1;
        min-width: 0;
        background: var(--bg-elevated);
        color: var(--text);
        border: 1px solid var(--border);
        border-radius: 6px;
        padding: 6px 10px;
        font: inherit;
        font-size: 0.9rem;
    }
    .search:focus { outline: none; border-color: var(--accent); }
    .sort {
        background: var(--bg-elevated);
        color: var(--text);
        border: 1px solid var(--border);
        border-radius: 6px;
        padding: 6px 8px;
        font: inherit;
        font-size: 0.85rem;
        cursor: pointer;
    }
    .sort:focus { outline: none; border-color: var(--accent); }

    .status { color: var(--text-muted); padding: 16px; text-align: center; }
    .status.error { color: var(--error); }

    .empty {
        flex: 1;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        text-align: center;
        padding: 32px 16px;
        gap: 6px;
    }
    .empty-icon { font-size: 2.2rem; opacity: 0.5; margin-bottom: 4px; }
    .empty-title { font-size: 1rem; font-weight: 500; color: var(--text); margin: 0; }
    .empty-hint { font-size: 0.85rem; color: var(--text-muted); max-width: 280px; margin: 0; line-height: 1.45; }

    .list { list-style: none; padding: 0; margin: 0; overflow-y: auto; flex: 1; }
    .list li + li { margin-top: 4px; }

    .card {
        width: 100%;
        text-align: left;
        background: var(--surface);
        border: 1px solid transparent;
        border-radius: 8px;
        padding: 10px 12px;
        cursor: pointer;
        color: inherit;
        position: relative;
        font: inherit;
        display: grid;
        grid-template-columns: auto 1fr auto;
        gap: 10px;
        align-items: center;
        transition: background 0.12s, border-color 0.12s;
    }
    .card:hover { background: var(--bg-elevated); }
    .card.selected {
        background: var(--accent-muted);
        border-color: var(--border-accent);
    }
    .card.selected .name { color: var(--accent); }

    .card-text { min-width: 0; }
    .row1 {
        display: flex;
        align-items: baseline;
        gap: 6px;
        min-width: 0;
    }
    .name {
        font-weight: 500;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        min-width: 0;
    }
    .type-badge {
        font-size: 0.65rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--text-muted);
        border: 1px solid var(--border);
        border-radius: 3px;
        padding: 1px 5px;
        flex-shrink: 0;
    }
    .missed-tag {
        font-size: 0.68rem;
        font-weight: 600;
        color: #ef5350;
        border: 1px solid rgba(244, 67, 54, 0.45);
        background: rgba(244, 67, 54, 0.12);
        border-radius: 999px;
        padding: 1px 7px;
        flex-shrink: 0;
        white-space: nowrap;
    }
    .card.needs-attention .name {
        font-weight: 600;
    }
    .card.needs-attention::before {
        content: '';
        position: absolute;
        left: 0;
        top: 6px;
        bottom: 6px;
        width: 3px;
        background: var(--accent);
        border-radius: 0 2px 2px 0;
    }
    .row2 {
        margin-top: 2px;
        font-size: 0.82rem;
        color: var(--text-muted);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .card-meta { display: flex; flex-direction: column; align-items: flex-end; gap: 4px; flex-shrink: 0; }
    .unread {
        background: var(--error);
        color: #fff;
        font-size: 0.7rem;
        font-weight: 600;
        line-height: 1;
        padding: 2px 6px;
        border-radius: 10px;
        min-width: 18px;
        text-align: center;
    }

    .header-left { display: flex; align-items: center; gap: 8px; min-width: 0; }
    .back-btn {
        background: none;
        border: 1px solid var(--border);
        border-radius: 4px;
        padding: 4px 9px;
        cursor: pointer;
        color: inherit;
        font: inherit;
        line-height: 1;
    }
    .back-btn:hover { background: var(--bg-elevated); }

    /* Explicit option colors — native <select> dropdowns in some
       WebView builds ignore the .sort CSS for the expanded option list
       and fall back to OS-default colors (which can land white-on-white
       in either theme). Plus index.html's color-scheme tells the WebView
       which theme to use for native controls overall. */
    .sort option {
        background: var(--bg-elevated);
        color: var(--text);
    }

    .history-link {
        display: flex;
        align-items: center;
        gap: 8px;
        width: 100%;
        padding: 10px 12px;
        margin-top: 12px;
        background: var(--surface);
        border: 1px dashed var(--border);
        border-radius: 8px;
        cursor: pointer;
        color: var(--text-muted);
        font: inherit;
        text-align: left;
        transition: background 0.12s, color 0.12s;
    }
    .history-link:hover {
        background: var(--bg-elevated);
        color: var(--text);
    }
    .history-label { flex: 1; font-weight: 500; }
    .history-count {
        background: var(--bg-elevated);
        color: var(--text-muted);
        font-size: 0.75rem;
        padding: 2px 8px;
        border-radius: 999px;
        font-weight: 500;
    }
    .history-chevron { font-size: 1.2em; line-height: 1; opacity: 0.6; }
</style>

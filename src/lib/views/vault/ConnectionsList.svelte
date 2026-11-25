<script lang="ts">
    import { onMount } from 'svelte';
    import { invoke } from '@tauri-apps/api/core';
    import type { Connection, VaultOpResponse } from '../../connections';
    import { selectedConnectionStore } from '../../stores/navigation';
    import {
        connectionsStore,
        connectionsErrorStore,
        connectionsUnreadableStore,
        connectionRequestsStore,
        connectionRequestsErrorStore,
        loadConnections,
        loadConnectionRequests,
        reloadConnectionViews,
        NOT_LIVE_TEXT,
    } from '../../stores/vault';
    import {
        connectionTitle,
        secondaryNames,
        requestRow,
        declineArgs,
        UNREADABLE_CONNECTIONS,
        hasUnreadableConnections,
    } from '../../connectionView.js';
    import { formatRelativeOrAbsolute } from '../../time';
    import Avatar from '../../components/Avatar.svelte';

    // The vault store owns the list and the pending requests, as the last
    // load confirmed them: it reads them again on the session going live
    // and on the vault's connection events (stores/vault.ts). A failed
    // load clears them and leaves the backend's error text.
    let connections = $derived($connectionsStore);
    let loading = $state(true);
    let error = $derived($connectionsErrorStore);
    let requests = $derived($connectionRequestsStore);
    // While the session isn't live the list says so; the requests don't say it again.
    let requestsError = $derived($connectionRequestsErrorStore === NOT_LIVE_TEXT ? '' : $connectionRequestsErrorStore);
    let someUnreadable = $derived(hasUnreadableConnections($connectionsUnreadableStore));
    let search = $state('');

    type SortOrder = 'recent' | 'alpha' | 'created';
    let sort: SortOrder = $state('recent');

    let selectedId = $derived($selectedConnectionStore?.id);

    function openConnection(conn: Connection): void {
        selectedConnectionStore.set(conn);
    }

    async function loadAll() {
        loading = connections.length === 0;
        await Promise.all([loadConnections(), loadConnectionRequests()]);
        loading = false;
    }

    function refresh() {
        reloadConnectionViews();
    }

    // The row's second line, without names: when the connection was made.
    function connectedWhen(c: Connection): string {
        const when = formatRelativeOrAbsolute(c.created_at);
        return when ? `Connected ${when}` : '';
    }

    function ts(s: string | undefined): number {
        const n = s ? Date.parse(s) : NaN;
        return Number.isNaN(n) ? 0 : n;
    }

    let visible = $derived.by(() => {
        const q = search.trim().toLowerCase();
        const filtered = q
            ? connections.filter((c) =>
                  [connectionTitle(c), ...secondaryNames(c)].some((t) => t.toLowerCase().includes(q)),
              )
            : connections.slice();
        switch (sort) {
            case 'alpha':
                filtered.sort((a, b) => connectionTitle(a).localeCompare(connectionTitle(b)));
                break;
            case 'created':
                filtered.sort((a, b) => ts(b.created_at) - ts(a.created_at));
                break;
            case 'recent':
            default:
                filtered.sort((a, b) => ts(b.last_active_at || b.created_at) - ts(a.last_active_at || a.created_at));
                break;
        }
        return filtered;
    });

    // Declining is the only request action a desktop has (§3.1, §6.4):
    // approving is the phone's, so no approve control is shown.
    let declining = $state<string | null>(null);
    let declineErrors = $state<Record<string, string>>({});

    async function decline(side: 'incoming' | 'outgoing', key: string, req: { pending_id?: string; connection_id?: string }) {
        const args = declineArgs(side, req);
        if (!args || declining) return;
        declining = key;
        declineErrors = { ...declineErrors, [key]: '' };
        try {
            const resp: VaultOpResponse<unknown> = await invoke('decline_connection_request', args);
            if (!resp.success) declineErrors = { ...declineErrors, [key]: resp.error ?? '' };
        } catch (e) {
            declineErrors = { ...declineErrors, [key]: String(e) };
        }
        declining = null;
        // Whatever the answer, read again: the requests shown are the vault's.
        reloadConnectionViews();
    }

    let hasRequests = $derived((requests?.incoming.length ?? 0) + (requests?.outgoing.length ?? 0) > 0);

    onMount(() => { loadAll(); });
</script>

<div class="connections-list">
    <div class="header">
        <h3>Connections</h3>
        <button class="refresh" aria-label="Refresh" onclick={refresh}>↻</button>
    </div>

    {#if requestsError || hasRequests}
        <section class="requests">
            <h4>Requests</h4>
            {#if requestsError}
                <div class="status error">{requestsError}</div>
            {:else if requests}
                {#if requests.incoming.length}
                    <h5>Incoming</h5>
                    <ul class="req-list">
                        {#each requests.incoming as req (req.pending_id)}
                            {@const key = `in:${req.pending_id}`}
                            {@const row = requestRow(req)}
                            <li class="req" class:unreadable={row.unreadable}>
                                <div class="req-text">
                                    <div class="name"><bdi>{row.title}</bdi></div>
                                    {#each row.secondary as s}<div class="row2"><bdi>{s}</bdi></div>{/each}
                                    {#if declineErrors[key]}<div class="req-error">{declineErrors[key]}</div>{/if}
                                </div>
                                <button class="decline" disabled={declining !== null} onclick={() => decline('incoming', key, req)}>
                                    {declining === key ? '…' : 'Decline'}
                                </button>
                            </li>
                        {/each}
                    </ul>
                {/if}
                {#if requests.outgoing.length}
                    <h5>Outgoing</h5>
                    <ul class="req-list">
                        {#each requests.outgoing as req (req.connection_id)}
                            {@const key = `out:${req.connection_id}`}
                            {@const row = requestRow(req)}
                            <li class="req" class:unreadable={row.unreadable}>
                                <div class="req-text">
                                    <div class="name"><bdi>{row.title}</bdi></div>
                                    {#each row.secondary as s}<div class="row2"><bdi>{s}</bdi></div>{/each}
                                    {#if declineErrors[key]}<div class="req-error">{declineErrors[key]}</div>{/if}
                                </div>
                                <button class="decline" disabled={declining !== null} onclick={() => decline('outgoing', key, req)}>
                                    {declining === key ? '…' : 'Decline'}
                                </button>
                            </li>
                        {/each}
                    </ul>
                {/if}
            {/if}
        </section>
    {/if}

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

    <!-- The count is 0 after a failed load, so this never sits beside an error. -->
    {#if someUnreadable}
        <div class="status error unreadable-note">{UNREADABLE_CONNECTIONS}</div>
    {/if}

    {#if loading && connections.length === 0}
        <div class="status">Loading connections…</div>
    {:else if error}
        <div class="status error">{error}</div>
    {:else if visible.length === 0}
        {#if search.trim()}
            <div class="status">No connections match "{search}".</div>
        {:else if !someUnreadable}
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
            {#each visible as conn (conn.id)}
                {@const title = connectionTitle(conn)}
                {@const names = secondaryNames(conn)}
                <li>
                    <button
                        type="button"
                        class="card"
                        class:selected={selectedId === conn.id}
                        onclick={() => openConnection(conn)}
                    >
                        <Avatar name={title} size={40} />
                        <div class="card-text">
                            <div class="row1">
                                <span class="name"><bdi>{title}</bdi></span>
                            </div>
                            <!-- The names under an alias and the display name (§10.8), each isolated. -->
                            <div class="row2">
                                {#if names.length}
                                    {#each names as s, i}{#if i}{' · '}{/if}<bdi>{s}</bdi>{/each}
                                {:else}
                                    {connectedWhen(conn)}
                                {/if}
                            </div>
                        </div>
                    </button>
                </li>
            {/each}
        </ul>
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
    .unreadable-note { padding: 0 0 10px; text-align: left; font-size: 0.85rem; }

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
        grid-template-columns: auto 1fr;
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
    .row2 {
        margin-top: 2px;
        font-size: 0.82rem;
        color: var(--text-muted);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    /* Explicit option colors — native <select> dropdowns in some
       WebView builds ignore the .sort CSS for the expanded option list
       and fall back to OS-default colors (which can land white-on-white
       in either theme). Plus index.html's color-scheme tells the WebView
       which theme to use for native controls overall. */
    .sort option {
        background: var(--bg-elevated);
        color: var(--text);
    }

    .requests { padding: 0 0 10px; }
    .requests h4 { margin: 0 0 6px; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); }
    .requests h5 { margin: 6px 0 4px; font-size: 0.75rem; font-weight: 500; color: var(--text-muted); }
    .req-list { list-style: none; padding: 0; margin: 0; }
    .req-list li + li { margin-top: 4px; }
    .req {
        display: flex;
        align-items: center;
        gap: 10px;
        background: var(--surface);
        border-radius: 8px;
        padding: 8px 12px;
    }
    .req-text { flex: 1; min-width: 0; }
    .req.unreadable .name { color: var(--text-muted); font-style: italic; }
    .req-error { margin-top: 4px; font-size: 0.8rem; color: var(--error); }
    .decline {
        background: none;
        border: 1px solid var(--border);
        border-radius: 6px;
        padding: 4px 10px;
        cursor: pointer;
        color: inherit;
        font: inherit;
        font-size: 0.85rem;
        flex-shrink: 0;
    }
    .decline:hover:not(:disabled) { background: var(--bg-elevated); }
    .decline:disabled { opacity: 0.6; cursor: default; }
</style>

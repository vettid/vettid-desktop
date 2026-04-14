<script lang="ts">
    import { onMount } from 'svelte';
    import {
        connectionsStore,
        feedStore,
        unreadByConnectionStore,
        loadConnections,
        loadFeed,
    } from '../../stores/vault';
    import type { Connection, FeedEvent } from '../../types';
    import { selectedConnectionStore } from '../../stores/navigation';

    let loading = $state(true);
    let error = $state('');

    let connections = $derived($connectionsStore);
    let events = $derived($feedStore);
    let unread = $derived($unreadByConnectionStore);

    /**
     * Sort connections by the timestamp of their most recent feed event so the
     * active conversations bubble to the top — matching Android's
     * `FeedViewModel.buildConnectionCards()`.
     */
    let connectionsSorted = $derived.by(() => {
        const lastTouchByConnection = new Map<string, number>();
        for (const ev of events) {
            if (!ev.connection_id) continue;
            const t = Date.parse(ev.timestamp) || 0;
            const prev = lastTouchByConnection.get(ev.connection_id) ?? 0;
            if (t > prev) lastTouchByConnection.set(ev.connection_id, t);
        }
        return [...connections].sort((a, b) => {
            const ta = lastTouchByConnection.get(a.connection_id) ?? Date.parse(a.created_at) ?? 0;
            const tb = lastTouchByConnection.get(b.connection_id) ?? Date.parse(b.created_at) ?? 0;
            return tb - ta;
        });
    });

    /** Standalone activity items — events with no connection (security, system). */
    let standaloneEvents = $derived(events.filter((e) => !e.connection_id));

    function peerName(c: Connection): string {
        const profile = c.peer_profile;
        const first = profile?.first_name ?? '';
        const last = profile?.last_name ?? '';
        const full = `${first} ${last}`.trim();
        return full || c.label || c.peer_guid.slice(0, 8);
    }

    function lastEventFor(connectionId: string): FeedEvent | undefined {
        return events
            .filter((e) => e.connection_id === connectionId)
            .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))[0];
    }

    async function refresh() {
        loading = true;
        error = '';
        try {
            await Promise.all([loadConnections(), loadFeed()]);
        } catch (e) {
            error = String(e);
        }
        loading = false;
    }

    onMount(() => { refresh(); });

    function openConnection(c: Connection) {
        selectedConnectionStore.set(c);
    }
</script>

<div class="feed-view">
    <div class="header">
        <h3>Activity</h3>
        <button class="refresh" aria-label="Refresh" onclick={refresh}>↻</button>
    </div>

    {#if loading && connections.length === 0 && events.length === 0}
        <div class="status">Loading…</div>
    {:else if error}
        <div class="status error">{error}</div>
    {:else}
        <div class="scroll">
            <!-- Connections section -->
            <section class="section">
                <h4 class="section-title">Connections</h4>
                {#if connectionsSorted.length === 0}
                    <div class="empty">No connections yet</div>
                {:else}
                    <ul class="connection-list">
                        {#each connectionsSorted as conn (conn.connection_id)}
                            {@const last = lastEventFor(conn.connection_id)}
                            {@const unreadCount = unread[conn.connection_id] ?? 0}
                            <li>
                                <button class="connection-card" onclick={() => openConnection(conn)}>
                                    <div class="avatar" aria-hidden="true">
                                        {#if conn.peer_profile?.photo}
                                            <img src={`data:image/png;base64,${conn.peer_profile.photo}`} alt="" />
                                        {:else}
                                            <span class="initials">{peerName(conn).slice(0, 1).toUpperCase()}</span>
                                        {/if}
                                    </div>
                                    <div class="card-body">
                                        <div class="row1">
                                            <span class="name">{peerName(conn)}</span>
                                            {#if last}
                                                <span class="time">{new Date(last.timestamp).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}</span>
                                            {/if}
                                        </div>
                                        <div class="row2">
                                            <span class="preview">
                                                {last?.message ?? last?.title ?? `Connected — ${conn.status}`}
                                            </span>
                                            {#if unreadCount > 0}
                                                <span class="unread-pill">{unreadCount}</span>
                                            {/if}
                                        </div>
                                    </div>
                                    <span class="status-badge {conn.status}">{conn.status}</span>
                                </button>
                            </li>
                        {/each}
                    </ul>
                {/if}
            </section>

            <!-- Standalone activity -->
            {#if standaloneEvents.length > 0}
                <section class="section">
                    <h4 class="section-title">Activity</h4>
                    <ul class="event-list">
                        {#each standaloneEvents as event (event.event_id)}
                            <li class="event-item" class:unread={!event.is_read}>
                                <div class="event-type">{event.event_type}</div>
                                {#if event.title}<div class="event-title">{event.title}</div>{/if}
                                {#if event.message}<div class="event-message">{event.message}</div>{/if}
                                <div class="event-time">{new Date(event.timestamp).toLocaleString()}</div>
                            </li>
                        {/each}
                    </ul>
                </section>
            {/if}
        </div>
    {/if}
</div>

<style>
    .feed-view { height: 100%; display: flex; flex-direction: column; }
    .header { display: flex; justify-content: space-between; align-items: center; padding: 0 0 12px; }
    .header h3 { margin: 0; }
    .refresh { background: none; border: 1px solid var(--border); border-radius: 4px; cursor: pointer; padding: 4px 8px; }
    .status { color: var(--text-secondary); padding: 24px; text-align: center; }
    .status.error { color: var(--danger); }

    .scroll { flex: 1; overflow-y: auto; }
    .section { margin-bottom: 20px; }
    .section-title {
        font-size: 0.75em;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--text-secondary);
        margin: 0 0 8px;
        padding: 0 4px;
    }
    .empty { padding: 16px; color: var(--text-secondary); text-align: center; font-size: 0.9em; }

    .connection-list, .event-list { list-style: none; padding: 0; margin: 0; }
    .connection-list li { margin-bottom: 6px; }

    .connection-card {
        width: 100%;
        display: flex;
        gap: 12px;
        align-items: center;
        padding: 10px 12px;
        background: var(--surface, #1a1a1a);
        border: 1px solid var(--border);
        border-radius: 8px;
        cursor: pointer;
        text-align: left;
        color: inherit;
        font: inherit;
    }
    .connection-card:hover { background: var(--surface-hover, #222); }

    .avatar {
        width: 40px; height: 40px;
        border-radius: 50%;
        background: var(--accent-muted, #333);
        display: flex; align-items: center; justify-content: center;
        flex-shrink: 0;
        overflow: hidden;
    }
    .avatar img { width: 100%; height: 100%; object-fit: cover; }
    .initials { font-weight: 600; color: var(--accent); }

    .card-body { flex: 1; min-width: 0; }
    .row1 { display: flex; justify-content: space-between; gap: 8px; align-items: baseline; }
    .name { font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .time { font-size: 0.75em; color: var(--text-secondary); flex-shrink: 0; }

    .row2 { display: flex; justify-content: space-between; gap: 8px; align-items: center; margin-top: 2px; }
    .preview {
        font-size: 0.85em;
        color: var(--text-secondary);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .unread-pill {
        background: var(--accent);
        color: #000;
        font-size: 0.7em;
        font-weight: 600;
        padding: 2px 8px;
        border-radius: 10px;
        flex-shrink: 0;
    }

    .status-badge {
        font-size: 0.7em;
        padding: 2px 8px;
        border-radius: 3px;
        text-transform: capitalize;
    }
    .status-badge.active { background: rgba(46, 125, 50, 0.2); color: #4caf50; }
    .status-badge.pending { background: rgba(230, 81, 0, 0.2); color: #ff9800; }
    .status-badge.revoked, .status-badge.expired { background: rgba(198, 40, 40, 0.2); color: #f44336; }

    .event-item {
        padding: 10px 12px;
        border-bottom: 1px solid var(--border);
    }
    .event-item.unread { border-left: 3px solid var(--accent); padding-left: 9px; }
    .event-type { font-size: 0.7em; text-transform: uppercase; color: var(--text-secondary); }
    .event-title { font-weight: 500; margin-top: 2px; }
    .event-message { font-size: 0.9em; margin-top: 2px; }
    .event-time { font-size: 0.75em; color: var(--text-secondary); margin-top: 4px; }
</style>

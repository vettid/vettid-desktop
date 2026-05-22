<script lang="ts">
    import { onMount, tick } from 'svelte';
    import { invoke } from '@tauri-apps/api/core';
    import type { Connection, VaultOpResponse } from '../../types';
    import { selectedConnectionStore } from '../../stores/navigation';
    import { feLog } from '../../diag';

    let connections: Connection[] = $state([]);
    let loading = $state(true);
    let error = $state('');

    // WEDGE-DIAG (2026-05-22): post-render breadcrumb. A Svelte 5 $effect
    // runs *after* the DOM mutations for a flush, so this firing means the
    // {#each} render completed. If loadConnections logs "list assigned" but
    // this never fires, the freeze is inside the each-block render itself.
    $effect(() => {
        feLog(`CL $effect: loading=${loading} error=${error !== ''} n=${connections.length}`);
    });

    function peerName(c: Connection): string {
        const p = c.peer_profile;
        const full = `${p?.first_name ?? ''} ${p?.last_name ?? ''}`.trim();
        return full || c.label || c.peer_guid.slice(0, 8);
    }

    // Clicking a row opens it — the Connections shell watches
    // selectedConnectionStore and swaps to the conversation view.
    function openConnection(conn: Connection): void {
        selectedConnectionStore.set(conn);
    }

    async function loadConnections() {
        feLog('CL loadConnections: start');
        loading = true;
        error = '';
        try {
            feLog('CL loadConnections: invoking list_connections');
            const resp: VaultOpResponse = await invoke('list_connections');
            feLog(`CL loadConnections: invoke resolved success=${resp.success}`);
            if (resp.success && resp.data) {
                const data = resp.data as { connections?: Connection[] };
                const arr = data.connections ?? [];
                feLog(`CL loadConnections: parsing ${arr.length} connections (~${JSON.stringify(arr).length} bytes)`);
                connections = arr;
                feLog('CL loadConnections: list assigned to $state');
            } else {
                error = resp.error ?? 'Failed to load connections';
            }
        } catch (e) {
            feLog(`CL loadConnections: threw ${String(e)}`);
            error = String(e);
        }
        loading = false;
        feLog('CL loadConnections: loading=false set, awaiting tick');
        await tick();
        feLog('CL loadConnections: tick resolved — DOM flushed');
    }

    // Load once when the list mounts. This was a $effect, which re-runs
    // on reactivity cycles — a one-shot fetch belongs in onMount so a
    // parent re-render can't re-fire connection.list.
    onMount(() => { feLog('CL onMount'); loadConnections(); });
</script>

<div class="connections-list">
    <div class="header">
        <h3>Connections</h3>
        <button class="refresh" aria-label="Refresh" onclick={loadConnections}>↻</button>
    </div>

    {#if loading}
        <div class="status">Loading connections...</div>
    {:else if error}
        <div class="status error">{error}</div>
    {:else if connections.length === 0}
        <div class="status">No connections yet</div>
    {:else}
        <ul class="list">
            {#each connections as conn (conn.connection_id)}
                <li>
                    <button class="connection-item" onclick={() => openConnection(conn)}>
                        <div class="name">{peerName(conn)}</div>
                        <div class="meta">
                            <span class="status-badge {conn.status}">{conn.status}</span>
                            <span class="direction">{conn.direction}</span>
                        </div>
                    </button>
                </li>
            {/each}
        </ul>
    {/if}
</div>

<style>
    .connections-list { height: 100%; display: flex; flex-direction: column; }
    .header { display: flex; justify-content: space-between; align-items: center; padding: 0 0 12px; }
    .header h3 { margin: 0; }
    .refresh { background: none; border: 1px solid var(--border); border-radius: 4px; cursor: pointer; padding: 4px 8px; }
    .status { color: var(--text-secondary); padding: 24px; text-align: center; }
    .status.error { color: var(--danger); }
    .list { list-style: none; padding: 0; margin: 0; overflow-y: auto; flex: 1; }
    .connection-item {
        width: 100%;
        text-align: left;
        background: none;
        border: none;
        border-bottom: 1px solid var(--border);
        padding: 12px;
        cursor: pointer;
        color: inherit;
        font: inherit;
    }
    .connection-item:hover { background: rgba(255, 255, 255, 0.04); }
    .name { font-weight: 500; }
    .meta { display: flex; gap: 8px; margin-top: 4px; font-size: 0.85em; color: var(--text-secondary); }
    .status-badge { padding: 2px 6px; border-radius: 3px; font-size: 0.8em; }
    .status-badge.active { background: #e8f5e9; color: #2e7d32; }
    .status-badge.pending { background: #fff3e0; color: #e65100; }
    .status-badge.revoked { background: #ffebee; color: #c62828; }
</style>

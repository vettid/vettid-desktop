<script lang="ts">
    import { invoke } from '@tauri-apps/api/core';
    import type { Connection, VaultOpResponse } from '../../types';

    let connections: Connection[] = $state([]);
    let loading = $state(true);
    let error = $state('');

    async function loadConnections() {
        loading = true;
        error = '';
        try {
            const resp: VaultOpResponse = await invoke('list_connections');
            if (resp.success && resp.data) {
                const data = resp.data as { connections?: Connection[] };
                connections = data.connections ?? [];
            } else {
                error = resp.error ?? 'Failed to load connections';
            }
        } catch (e) {
            error = String(e);
        }
        loading = false;
    }

    $effect(() => { loadConnections(); });
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
            {#each connections as conn}
                <li class="connection-item">
                    <div class="name">{conn.label || conn.peer_guid}</div>
                    <div class="meta">
                        <span class="status-badge {conn.status}">{conn.status}</span>
                        <span class="direction">{conn.direction}</span>
                    </div>
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
    .connection-item { padding: 12px; border-bottom: 1px solid var(--border); }
    .name { font-weight: 500; }
    .meta { display: flex; gap: 8px; margin-top: 4px; font-size: 0.85em; color: var(--text-secondary); }
    .status-badge { padding: 2px 6px; border-radius: 3px; font-size: 0.8em; }
    .status-badge.active { background: #e8f5e9; color: #2e7d32; }
    .status-badge.pending { background: #fff3e0; color: #e65100; }
    .status-badge.revoked { background: #ffebee; color: #c62828; }
</style>

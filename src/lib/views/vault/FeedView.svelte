<script lang="ts">
    import { invoke } from '@tauri-apps/api/core';
    import { listen } from '@tauri-apps/api/event';
    import type { FeedEvent, VaultOpResponse } from '../../types';

    let events: FeedEvent[] = $state([]);
    let loading = $state(true);
    let error = $state('');

    async function loadFeed() {
        loading = true;
        error = '';
        try {
            const resp: VaultOpResponse = await invoke('list_feed');
            if (resp.success && resp.data) {
                const data = resp.data as { events?: FeedEvent[] };
                events = data.events ?? [];
            } else {
                error = resp.error ?? 'Failed to load feed';
            }
        } catch (e) {
            error = String(e);
        }
        loading = false;
    }

    $effect(() => { loadFeed(); });

    $effect(() => {
        const unlisten = listen<FeedEvent>('vault:feed-event', (event) => {
            events = [event.payload, ...events];
        });
        return () => { unlisten.then(fn => fn()); };
    });
</script>

<div class="feed-view">
    <div class="header">
        <h3>Activity Feed</h3>
        <button class="refresh" aria-label="Refresh" onclick={loadFeed}>↻</button>
    </div>

    {#if loading}
        <div class="status">Loading feed...</div>
    {:else if error}
        <div class="status error">{error}</div>
    {:else if events.length === 0}
        <div class="status">No activity yet</div>
    {:else}
        <ul class="feed-list">
            {#each events as event}
                <li class="feed-item" class:unread={!event.is_read}>
                    <div class="event-type">{event.event_type}</div>
                    <div class="event-content">
                        {#if event.title}<strong>{event.title}</strong>{/if}
                        {#if event.message}<span>{event.message}</span>{/if}
                    </div>
                    <div class="event-time">{new Date(event.timestamp).toLocaleString()}</div>
                </li>
            {/each}
        </ul>
    {/if}
</div>

<style>
    .feed-view { height: 100%; display: flex; flex-direction: column; }
    .header { display: flex; justify-content: space-between; align-items: center; padding: 0 0 12px; }
    .header h3 { margin: 0; }
    .refresh { background: none; border: 1px solid var(--border); border-radius: 4px; cursor: pointer; padding: 4px 8px; }
    .status { color: var(--text-secondary); padding: 24px; text-align: center; }
    .status.error { color: var(--danger); }
    .feed-list { list-style: none; padding: 0; margin: 0; overflow-y: auto; flex: 1; }
    .feed-item { padding: 12px; border-bottom: 1px solid var(--border); }
    .feed-item.unread { border-left: 3px solid var(--accent); }
    .event-type { font-size: 0.75em; color: var(--text-secondary); text-transform: uppercase; margin-bottom: 4px; }
    .event-content { display: flex; flex-direction: column; gap: 2px; }
    .event-time { font-size: 0.8em; color: var(--text-secondary); margin-top: 4px; }
</style>

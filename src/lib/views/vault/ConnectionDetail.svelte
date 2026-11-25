<script lang="ts">
    // A connection's details, read-only (DESKTOP-REWORK-PLAN Phase 5, 5.2):
    // the fields of `connection.get` (VAULT-MESSAGING §10.4), titled as §10.8
    // says. Only what the last read confirmed is shown: a failed read clears
    // it and shows the backend's text. It reads again when the connection
    // views do (`connectionsReload`, stores/vault.ts).
    import { invoke } from '@tauri-apps/api/core';
    import { untrack } from 'svelte';
    import type { Connection, VaultOpResponse } from '../../connections';
    import { clearSelectedConnection } from '../../stores/navigation';
    import { connectionsReload } from '../../stores/vault';
    import { connectionTitle, secondaryNames, relayHeldText } from '../../connectionView.js';
    import Avatar from '../../components/Avatar.svelte';

    interface Props {
        connection: Connection;
        // Back action. Defaults to clearing the selection (→ list) when
        // used standalone.
        onBack?: () => void;
        /** Hide the local identity header when embedded in
         *  ConnectionWorkspace, which owns the workspace header. */
        compact?: boolean;
    }

    let { connection, onBack, compact = false }: Props = $props();
    const handleBack = (): void => (onBack ?? clearSelectedConnection)();

    /** What the last `connection.get` confirmed; `null` before it or after a failure. */
    let detail = $state<Connection | null>(null);
    let loading = $state(false);
    let error = $state('');

    /** Counts reads: only the latest one's answer is applied. */
    let seq = 0;

    async function refreshDetail(id: string) {
        const mine = ++seq;
        // Another connection's details never stay on screen while this one loads.
        if (detail?.id !== id) detail = null;
        loading = true;
        let next: Connection | null = null;
        let err = '';
        try {
            const resp: VaultOpResponse<Connection> = await invoke('get_connection', { connectionId: id });
            if (resp.success && resp.data) next = resp.data;
            else err = resp.error ?? '';
        } catch (e) {
            err = String(e);
        }
        if (mine !== seq) return;
        detail = next;
        error = err;
        loading = false;
    }

    // The list replaces the selected connection with its new copy on each
    // read: the same id and reload count is not read twice.
    let lastRead = '';
    $effect(() => {
        const id = connection.id;
        // Read again whenever the connection views do.
        const key = `${id}\n${$connectionsReload}`;
        if (key === lastRead) return;
        lastRead = key;
        untrack(() => void refreshDetail(id));
    });

    function when(iso: string | undefined): string {
        if (!iso) return '';
        const t = new Date(iso);
        return Number.isNaN(t.getTime()) ? '' : t.toLocaleString();
    }
</script>

<div class="detail">
    {#if !compact}
        <header class="bar">
            <button class="back" onclick={handleBack} aria-label="Back">←</button>
            <h3><bdi>{connectionTitle(detail ?? connection)}</bdi></h3>
        </header>
    {/if}

    {#if loading && !detail}
        <div class="status">Loading…</div>
    {:else if error}
        <div class="status error">{error}</div>
    {:else if detail}
        {@const title = connectionTitle(detail)}
        <div class="scroll">
            {#if detail.relay_held}
                <div class="held">{relayHeldText(title)}</div>
            {/if}

            <section class="card">
                <h4>Profile</h4>
                <div class="profile-head">
                    <Avatar name={title} size={64} />
                    <div class="profile-id">
                        <div class="full-name"><bdi>{title}</bdi></div>
                        {#each secondaryNames(detail) as s}
                            <div class="sub"><bdi>{s}</bdi></div>
                        {/each}
                    </div>
                </div>
            </section>

            <section class="card">
                <h4>Connection</h4>
                <dl class="fields">
                    <dt>Created</dt>
                    <dd>{when(detail.created_at)}</dd>
                    {#if when(detail.last_active_at)}
                        <dt>Last active</dt>
                        <dd>{when(detail.last_active_at)}</dd>
                    {/if}
                    {#if detail.note}
                        <dt>Note</dt>
                        <dd class="note">{detail.note}</dd>
                    {/if}
                    {#if detail.tags?.length}
                        <dt>Tags</dt>
                        <dd>{detail.tags.join(', ')}</dd>
                    {/if}
                </dl>
            </section>
        </div>
    {/if}
</div>

<style>
    .detail { height: 100%; display: flex; flex-direction: column; }
    .bar {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 0 0 12px;
        border-bottom: 1px solid var(--border);
    }
    .bar h3 { margin: 0; flex: 1; }
    .back {
        background: none;
        border: 1px solid var(--border);
        border-radius: 4px;
        padding: 4px 10px;
        cursor: pointer;
        color: inherit;
    }

    .scroll { flex: 1; overflow-y: auto; padding-top: 12px; }
    .status { padding: 24px; text-align: center; color: var(--text-secondary); }
    .status.error { color: var(--danger); }

    .held {
        background: rgba(230, 81, 0, 0.12);
        border: 1px solid rgba(230, 81, 0, 0.35);
        border-radius: 8px;
        padding: 10px 14px;
        margin-bottom: 12px;
        font-size: 0.9em;
    }

    .card {
        background: var(--surface, #1a1a1a);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
    }
    .card h4 { margin: 0 0 12px; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); }

    .profile-head { display: flex; gap: 14px; align-items: center; }
    .full-name { font-size: 1.1em; font-weight: 500; }
    .sub { font-size: 0.85em; color: var(--text-secondary); margin-top: 2px; }

    .fields { display: grid; grid-template-columns: minmax(110px, auto) 1fr; gap: 6px 14px; margin: 0; }
    .fields dt { color: var(--text-secondary); font-size: 0.85em; }
    .fields dd { margin: 0; font-size: 0.9em; word-break: break-word; }
    .note { white-space: pre-wrap; }
</style>

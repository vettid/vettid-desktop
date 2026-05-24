<script lang="ts">
  // Connection-scoped history view. Used as the entire workspace body
  // for system + device connections, where the messaging / profile /
  // sharing surface doesn't apply — there's nothing to chat to the
  // VettID system about, and the paired desktop's identity isn't a
  // "peer profile". The mobile app owns the rich actions (voting,
  // managing this desktop's session); the desktop just lets you
  // browse the audit trail.
  import { invoke } from '@tauri-apps/api/core';
  import type { Connection, VaultOpResponse } from '../../types';

  interface AuditEntry {
    entry_id: string;
    connection_id: string;
    peer_guid?: string;
    event_type: string;
    direction?: string;
    title: string;
    body?: string;
    created_at: number;
    refs?: Record<string, string>;
  }

  interface Props {
    connection: Connection;
  }
  let { connection }: Props = $props();

  let entries = $state<AuditEntry[]>([]);
  let loading = $state(true);
  let error = $state('');

  async function load() {
    loading = true;
    error = '';
    try {
      const resp: VaultOpResponse = await invoke('list_connection_audit', {
        connectionId: connection.connection_id,
        limit: 50,
      });
      if (resp.success && resp.data) {
        const data = resp.data as { entries?: AuditEntry[] };
        entries = data.entries ?? [];
      } else if (resp.error) {
        error = resp.error;
      }
    } catch (e) {
      error = String(e);
    }
    loading = false;
  }

  $effect(() => {
    const _ = connection.connection_id;
    void load();
  });

  function fmtTime(unix: number): string {
    const d = new Date(unix * 1000);
    const today = new Date();
    if (d.toDateString() === today.toDateString()) {
      return d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
    }
    return d.toLocaleString([], {
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
    });
  }
</script>

<div class="ch">
  <header class="ch-head">
    <h3>History</h3>
    <p class="hint">
      {#if connection.connection_type === 'system'}
        Activity from the VettID system — guides, announcements,
        proposals. Vote and manage notifications from the mobile app.
      {:else if connection.connection_type === 'device'}
        Session events for this paired desktop. End-session, revoke,
        and other management actions live on the mobile app.
      {:else}
        Audit events for this connection.
      {/if}
    </p>
  </header>

  <div class="ch-body">
    {#if loading}
      <p class="status">Loading history…</p>
    {:else if error}
      <p class="error">{error}</p>
    {:else if entries.length === 0}
      <p class="empty">No activity recorded yet.</p>
    {:else}
      <ul class="entries">
        {#each entries as e (e.entry_id)}
          <li class="entry">
            <div class="row1">
              <span class="title">{e.title}</span>
              <span class="time">{fmtTime(e.created_at)}</span>
            </div>
            {#if e.body}
              <div class="body">{e.body}</div>
            {/if}
            <div class="kind">{e.event_type}{e.direction ? ` · ${e.direction}` : ''}</div>
          </li>
        {/each}
      </ul>
    {/if}
  </div>
</div>

<style>
  .ch {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
  }
  .ch-head {
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .ch-head h3 {
    margin: 0 0 4px;
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
  }
  .hint {
    margin: 0;
    color: var(--text-muted);
    font-size: 0.85rem;
    line-height: 1.4;
  }
  .ch-body {
    flex: 1;
    overflow-y: auto;
    padding: 12px 16px;
  }
  .status, .empty, .error {
    color: var(--text-muted);
    font-size: 0.9rem;
  }
  .error { color: var(--error); }
  .entries {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .entry {
    padding: 12px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--surface);
  }
  .row1 {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 2px;
  }
  .title { font-weight: 500; }
  .time {
    font-size: 0.78rem;
    color: var(--text-muted);
    flex-shrink: 0;
  }
  .body {
    font-size: 0.9rem;
    color: var(--text-secondary);
    margin: 4px 0;
  }
  .kind {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
    margin-top: 4px;
  }
</style>

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

  interface AgentDetails {
    agent_name?: string;
    agent_type?: string;
    hostname?: string;
    platform?: string;
    status?: string;
    paired_at?: string;
    last_active_at?: string;
    scope?: string[];
    approval_mode?: string;
    rate_limit?: { max?: number; per?: string };
  }

  interface Props {
    connection: Connection;
  }
  let { connection }: Props = $props();

  let entries = $state<AuditEntry[]>([]);
  let agent = $state<AgentDetails | null>(null);
  let loading = $state(true);
  let error = $state('');

  let isAgent = $derived(connection.connection_type === 'agent');

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

    // For agents, fetch the Contract + identity data alongside the
    // audit log. The agent.list response is small (~1KB per agent)
    // so a fresh fetch on every detail view is fine; the call is on
    // the desktop's independent-capability list (no phone approval).
    if (isAgent) {
      try {
        const resp: VaultOpResponse = await invoke('list_agents');
        if (resp.success && resp.data) {
          const data = resp.data as { agents?: AgentDetails[] & { connection_id?: string }[] };
          const list = (data.agents ?? []) as (AgentDetails & { connection_id?: string })[];
          agent = list.find((a) => a.connection_id === connection.connection_id) ?? null;
        }
      } catch (e) {
        // Soft-fail — history still renders, contract just stays
        // null and the section shows a one-line note.
        console.warn('list_agents failed for agent detail surface:', e);
      }
    } else {
      agent = null;
    }

    loading = false;
  }

  $effect(() => {
    const _ = connection.connection_id;
    void load();
  });

  function fmtIsoDate(iso?: string): string {
    if (!iso) return '—';
    try {
      return new Date(iso).toLocaleString([], {
        month: 'short', day: 'numeric', year: 'numeric',
        hour: 'numeric', minute: '2-digit',
      });
    } catch { return iso; }
  }

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
    <h3>{isAgent ? 'Details' : 'History'}</h3>
    <p class="hint">
      {#if connection.connection_type === 'system'}
        Activity from the VettID system — guides, announcements,
        proposals. Vote and manage notifications from the mobile app.
      {:else if connection.connection_type === 'device'}
        Session events for this paired desktop. End-session, revoke,
        and other management actions live on the mobile app.
      {:else if isAgent}
        Identity, contract, and audit history for this paired agent.
        Edit the contract or revoke from the mobile app.
      {:else}
        Audit events for this connection.
      {/if}
    </p>
  </header>

  <div class="ch-body">
    {#if isAgent}
      <!-- Identity card -->
      <section class="card">
        <h4>Identity</h4>
        <dl class="kv">
          <dt>Agent name</dt><dd>{agent?.agent_name ?? '—'}</dd>
          <dt>Type</dt><dd>{agent?.agent_type ?? '—'}</dd>
          <dt>Hostname</dt><dd>{agent?.hostname ?? '—'}</dd>
          <dt>Platform</dt><dd>{agent?.platform ?? '—'}</dd>
          <dt>Paired</dt><dd>{fmtIsoDate(agent?.paired_at)}</dd>
          <dt>Last active</dt><dd>{fmtIsoDate(agent?.last_active_at)}</dd>
        </dl>
      </section>

      <!-- Contract card -->
      <section class="card">
        <h4>Contract</h4>
        {#if agent}
          <dl class="kv">
            <dt>Scope</dt>
            <dd>
              {#if (agent.scope ?? []).length === 0}
                —
              {:else}
                <ul class="scope">
                  {#each agent.scope ?? [] as token}
                    <li>{token}</li>
                  {/each}
                </ul>
              {/if}
            </dd>
            <dt>Approval</dt><dd>{agent.approval_mode ?? '—'}</dd>
            <dt>Rate limit</dt>
            <dd>
              {#if (agent.rate_limit?.max ?? 0) <= 0}
                unlimited
              {:else}
                {agent.rate_limit?.max} per {agent.rate_limit?.per ?? 'hour'}
              {/if}
            </dd>
          </dl>
        {:else}
          <p class="empty">No contract on record.</p>
        {/if}
      </section>

      <h4 class="section-title">Activity</h4>
    {/if}

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
  .card {
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--surface);
    padding: 12px 14px;
    margin-bottom: 12px;
  }
  .card h4 {
    margin: 0 0 8px;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-muted);
    font-weight: 600;
  }
  .kv {
    display: grid;
    grid-template-columns: minmax(110px, max-content) 1fr;
    gap: 6px 14px;
    margin: 0;
    font-size: 0.9rem;
  }
  .kv dt {
    color: var(--text-muted);
    font-size: 0.85rem;
  }
  .kv dd {
    margin: 0;
    color: var(--text);
    word-break: break-word;
  }
  .scope {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-wrap: wrap;
    gap: 4px 6px;
  }
  .scope li {
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 1px 8px;
    font-size: 0.78rem;
    font-family: ui-monospace, SFMono-Regular, monospace;
  }
  .section-title {
    margin: 12px 0 8px;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-muted);
    font-weight: 600;
  }
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

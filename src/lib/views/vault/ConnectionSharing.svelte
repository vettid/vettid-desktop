<script lang="ts">
  // Per-connection sharing tab — replaces the top-level Sharing
  // destination. Mirrors Android's split: "From them" lists the
  // grants the peer has handed to this user, "To them" lists what
  // this user has handed to the peer (plus pending outbound
  // requests). The same data the global dashboard showed, just
  // pre-filtered to the connection that owns this tab.
  import { onMount } from 'svelte';
  import {
    listInbound,
    listOutbound,
    listMyRequests,
    type GrantSummary,
    type OutgoingRequestSummary,
  } from '../../grants';
  import type { Connection } from '../../types';

  interface Props {
    connection: Connection;
  }
  let { connection }: Props = $props();

  type Tab = 'from-them' | 'to-them';
  let tab = $state<Tab>('from-them');

  let inbound = $state<GrantSummary[]>([]);
  let outbound = $state<GrantSummary[]>([]);
  let myRequests = $state<OutgoingRequestSummary[]>([]);
  let loading = $state(true);
  let error = $state('');

  async function loadAll() {
    loading = true;
    error = '';
    try {
      const [ib, ob, mr] = await Promise.all([
        listInbound(),
        listOutbound(),
        listMyRequests(connection.connection_id),
      ]);
      inbound = ib.filter((g) => g.connection_id === connection.connection_id);
      outbound = ob.filter((g) => g.connection_id === connection.connection_id);
      myRequests = mr;
    } catch (e) {
      error = String(e);
    }
    loading = false;
  }

  // Reload when the connection swaps under us (parent reuses this
  // component when the user picks a different conversation).
  $effect(() => {
    const _ = connection.connection_id;
    void loadAll();
  });

  function fmtExpires(g: GrantSummary): string {
    if (g.expires_at <= 0) return 'no expiry';
    const remaining = g.expires_at - Math.floor(Date.now() / 1000);
    if (remaining <= 0) return 'expired';
    if (remaining < 60) return `${remaining}s left`;
    if (remaining < 3600) return `${Math.floor(remaining / 60)}m left`;
    if (remaining < 86400) return `${Math.floor(remaining / 3600)}h left`;
    return `${Math.floor(remaining / 86400)}d left`;
  }

  function fmtUses(g: GrantSummary): string {
    if (g.max_uses <= 0) return `${g.uses_so_far} use${g.uses_so_far === 1 ? '' : 's'}`;
    return `${g.uses_so_far}/${g.max_uses}`;
  }
</script>

<div class="cs">
  <nav class="cs-tabs" role="tablist" aria-label="Sharing direction">
    <button
      type="button"
      role="tab"
      aria-selected={tab === 'from-them'}
      class:active={tab === 'from-them'}
      onclick={() => (tab = 'from-them')}
    >From them <span class="count">{inbound.length}</span></button>
    <button
      type="button"
      role="tab"
      aria-selected={tab === 'to-them'}
      class:active={tab === 'to-them'}
      onclick={() => (tab = 'to-them')}
    >To them <span class="count">{outbound.length + myRequests.filter(r => r.status === 'pending').length}</span></button>
  </nav>

  <div class="cs-body">
    {#if loading}
      <p class="status">Loading sharing…</p>
    {:else if error}
      <p class="error">{error}</p>
    {:else if tab === 'from-them'}
      {#if inbound.length === 0}
        <p class="empty">They haven't shared anything with you yet.</p>
      {:else}
        <ul class="grants">
          {#each inbound as g (g.grant_id)}
            <li class="grant">
              <div class="grant-head">
                <span class="label">{g.item_label}</span>
                <span class="kind">{g.item_kind}</span>
              </div>
              <div class="grant-meta">
                <span>{fmtExpires(g)}</span>
                <span>·</span>
                <span>{fmtUses(g)}</span>
                <span>·</span>
                <span>{g.mode}</span>
              </div>
            </li>
          {/each}
        </ul>
      {/if}
    {:else}
      {#if outbound.length === 0 && myRequests.filter(r => r.status === 'pending').length === 0}
        <p class="empty">You haven't shared anything with them and have no pending requests.</p>
      {:else}
        {#if outbound.length > 0}
          <h3 class="section">Active grants</h3>
          <ul class="grants">
            {#each outbound as g (g.grant_id)}
              <li class="grant">
                <div class="grant-head">
                  <span class="label">{g.item_label}</span>
                  <span class="kind">{g.item_kind}</span>
                </div>
                <div class="grant-meta">
                  <span>{fmtExpires(g)}</span>
                  <span>·</span>
                  <span>{fmtUses(g)}</span>
                  <span>·</span>
                  <span>{g.mode}</span>
                </div>
              </li>
            {/each}
          </ul>
        {/if}
        {#if myRequests.some((r) => r.status === 'pending')}
          <h3 class="section">Your pending requests to them</h3>
          <ul class="grants">
            {#each myRequests.filter((r) => r.status === 'pending') as r (r.request_id)}
              <li class="grant pending">
                <div class="grant-head">
                  <span class="label">{r.item_label}</span>
                  <span class="kind">{r.item_kind}</span>
                </div>
                <div class="grant-meta">
                  <span>awaiting their approval</span>
                  <span>·</span>
                  <span>{r.mode}</span>
                </div>
              </li>
            {/each}
          </ul>
        {/if}
      {/if}
    {/if}
  </div>
</div>

<style>
  .cs {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
  }
  .cs-tabs {
    display: flex;
    gap: 4px;
    border-bottom: 1px solid var(--border);
    padding: 8px 16px 0;
    flex-shrink: 0;
  }
  .cs-tabs button {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    padding: 8px 12px;
    color: var(--text-muted);
    font-size: 0.9rem;
    font-weight: 500;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .cs-tabs button:hover { color: var(--text); }
  .cs-tabs button.active {
    color: var(--text);
    border-bottom-color: var(--accent);
  }
  .count {
    font-size: 0.75rem;
    background: var(--bg-elevated);
    color: var(--text-muted);
    padding: 1px 6px;
    border-radius: 999px;
    line-height: 1.4;
  }
  .cs-body {
    flex: 1;
    overflow-y: auto;
    padding: 16px;
  }
  .status, .empty, .error {
    color: var(--text-muted);
    font-size: 0.9rem;
  }
  .error { color: var(--error); }
  .section {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    color: var(--text-muted);
    margin: 18px 0 8px;
    font-weight: 600;
  }
  .section:first-child { margin-top: 0; }
  .grants {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .grant {
    padding: 12px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--surface);
  }
  .grant.pending {
    border-style: dashed;
  }
  .grant-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 4px;
  }
  .label { font-weight: 500; }
  .kind {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 1px 6px;
  }
  .grant-meta {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    font-size: 0.78rem;
    color: var(--text-muted);
  }
</style>

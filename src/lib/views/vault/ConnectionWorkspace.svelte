<script lang="ts">
  // Right pane of the two-pane Connections layout: the identity header
  // (avatar, title as VAULT-MESSAGING §10.8 says) and the connection's
  // details, read-only (DESKTOP-REWORK-PLAN Phase 5, 5.2). A conversation
  // comes back with 5.3.
  import type { Connection } from '../../connections';
  import Avatar from '../../components/Avatar.svelte';
  import { connectionTitle, secondaryNames } from '../../connectionView.js';
  import ConnectionDetail from './ConnectionDetail.svelte';

  interface Props {
    connection: Connection;
  }
  let { connection }: Props = $props();

  let title = $derived(connectionTitle(connection));
  let names = $derived(secondaryNames(connection));
</script>

<header class="ws-head">
  <Avatar name={title} size={40} />
  <div class="ws-text">
    <div class="ws-name"><bdi>{title}</bdi></div>
    {#if names.length}
      <div class="ws-meta">
        {#each names as s, i}{#if i}{' · '}{/if}<bdi>{s}</bdi>{/each}
      </div>
    {/if}
  </div>
</header>

<div class="ws-body">
  <ConnectionDetail {connection} compact />
</div>

<style>
  .ws-head {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .ws-text { min-width: 0; flex: 1; }
  .ws-name { font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .ws-meta { margin-top: 3px; font-size: 0.82rem; color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  .ws-body {
    flex: 1;
    min-height: 0;
    display: flex;
    flex-direction: column;
    padding: 12px 16px;
    overflow: hidden;
  }
</style>

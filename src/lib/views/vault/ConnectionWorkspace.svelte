<script lang="ts">
  // Right pane of the two-pane Connections layout: the identity header
  // (avatar, title as VAULT-MESSAGING §10.8 says), then the conversation
  // (DESKTOP-REWORK-PLAN Phase 5, 5.3) or the connection's details,
  // read-only (5.2). One Conversation per connection: a new selection
  // mounts a fresh one.
  import type { Connection } from '../../connections';
  import Avatar from '../../components/Avatar.svelte';
  import { connectionTitle, secondaryNames } from '../../connectionView.js';
  import ConnectionDetail from './ConnectionDetail.svelte';
  import Conversation from './Conversation.svelte';

  interface Props {
    connection: Connection;
  }
  let { connection }: Props = $props();

  let title = $derived(connectionTitle(connection));
  let names = $derived(secondaryNames(connection));

  type Mode = 'messages' | 'profile';
  let mode = $state<Mode>('messages');
  // A new connection opens on its messages.
  let shownId = '';
  $effect.pre(() => {
    if (connection.id !== shownId) {
      shownId = connection.id;
      mode = 'messages';
    }
  });
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

<div class="tabs" role="tablist" aria-label="Connection sections">
  <button
    type="button"
    role="tab"
    aria-selected={mode === 'messages'}
    class:active={mode === 'messages'}
    onclick={() => (mode = 'messages')}
  >Messages</button>
  <button
    type="button"
    role="tab"
    aria-selected={mode === 'profile'}
    class:active={mode === 'profile'}
    onclick={() => (mode = 'profile')}
  >Profile</button>
</div>

<div class="ws-body">
  {#if mode === 'messages'}
    {#key connection.id}
      <Conversation {connection} compact />
    {/key}
  {:else}
    <ConnectionDetail {connection} compact onBack={() => (mode = 'messages')} />
  {/if}
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

  .tabs {
    display: flex;
    gap: 0;
    padding: 0 16px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .tabs button {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--text-muted);
    padding: 9px 16px;
    cursor: pointer;
    font: inherit;
    font-size: 0.9rem;
    margin-bottom: -1px;
  }
  .tabs button:hover { color: var(--text); }
  .tabs button.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
    font-weight: 500;
  }

  .ws-body {
    flex: 1;
    min-height: 0;
    display: flex;
    flex-direction: column;
    padding: 12px 16px;
    overflow: hidden;
  }
</style>

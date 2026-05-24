<script lang="ts">
  // Right pane of the two-pane Connections layout. Owns the identity
  // header (avatar, name, status, call buttons) and a Messages /
  // Profile / Sharing tab strip that swaps the body between the
  // Conversation, ConnectionDetail, and ConnectionSharing views.
  // Conversation + Detail each get a `compact` flag so their own
  // headers stay out of the way and the workspace header is the
  // single source of identity on screen.
  import type { Connection } from '../../types';
  import Avatar from '../../components/Avatar.svelte';
  import StatusChip from '../../components/StatusChip.svelte';
  import { peerName } from '../../connectionName';
  import { placeCall, type CallType } from '../../stores/calls';
  import { CALLS_ENABLED } from '../../config/features';
  import Conversation from './Conversation.svelte';
  import ConnectionDetail from './ConnectionDetail.svelte';
  import ConnectionSharing from './ConnectionSharing.svelte';
  import ConnectionHistory from './ConnectionHistory.svelte';

  interface Props {
    connection: Connection;
  }
  let { connection }: Props = $props();

  type Mode = 'messages' | 'profile' | 'sharing';
  let mode = $state<Mode>('messages');
  let callError = $state('');

  // System + device connections collapse to a history-only view.
  // There's no peer to text/call (system) and no peer-style profile
  // to inspect (device); the mobile app owns the rich actions for
  // both (voting on the system connection, end-session/revoke on
  // the device connection). Hiding the tabs keeps the desktop from
  // promising surfaces that don't actually apply.
  let isHistoryOnly = $derived(
    connection.connection_type === 'system' ||
    connection.connection_type === 'device'
  );

  // Agent connections get a simplified two-tab shape: Messages (for
  // texting the agent — same wire format as a peer conversation, the
  // agent just happens to be the addressee) and History (the audit
  // trail of agent activity). No Profile/Sharing tabs since the agent
  // has no peer-style profile and grant management for agents goes
  // through scope, not the data-sharing surface.
  let isAgent = $derived(connection.connection_type === 'agent');

  // Drop back to Messages whenever the selected connection changes —
  // a new conversation is the most useful default.
  $effect(() => {
    const _ = connection.connection_id;
    mode = 'messages';
    callError = '';
  });

  async function startCall(type: CallType) {
    callError = '';
    if (!connection.peer_guid) {
      callError = "This connection can't be called.";
      return;
    }
    try {
      await placeCall(connection.connection_id, connection.peer_guid, peerName(connection), type);
    } catch (e) {
      callError = `Call failed: ${e}`;
    }
  }
</script>

<header class="ws-head">
  <Avatar
    name={peerName(connection)}
    photo={connection.peer_profile?.photo}
    connectionType={connection.connection_type}
    size={40}
  />
  <div class="ws-text">
    <div class="ws-name">{peerName(connection)}</div>
    <div class="ws-meta">
      <StatusChip status={connection.status} />
      {#if connection.connection_type === 'agent'}
        <span class="type-tag">agent</span>
      {:else if connection.connection_type === 'device'}
        <span class="type-tag">device</span>
      {/if}
    </div>
  </div>
  {#if CALLS_ENABLED}
    <div class="ws-actions">
      <button class="ha" onclick={() => startCall('audio')} title="Voice call" aria-label="Voice call">📞</button>
      <button class="ha" onclick={() => startCall('video')} title="Video call" aria-label="Video call">🎥</button>
    </div>
  {/if}
</header>

{#if callError}<div class="cerr">{callError}</div>{/if}

{#if isHistoryOnly}
  <div class="ws-body">
    <ConnectionHistory {connection} />
  </div>
{:else if isAgent}
  <nav class="tabs" role="tablist" aria-label="Connection sections">
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
    >Details</button>
  </nav>

  <div class="ws-body">
    {#if mode === 'messages'}
      <Conversation {connection} compact onShowProfile={() => (mode = 'profile')} />
    {:else}
      <ConnectionHistory {connection} />
    {/if}
  </div>
{:else}
  <nav class="tabs" role="tablist" aria-label="Connection sections">
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
    <button
      type="button"
      role="tab"
      aria-selected={mode === 'sharing'}
      class:active={mode === 'sharing'}
      onclick={() => (mode = 'sharing')}
    >Sharing</button>
  </nav>

  <div class="ws-body">
    {#if mode === 'messages'}
      <Conversation {connection} compact onShowProfile={() => (mode = 'profile')} />
    {:else if mode === 'profile'}
      <ConnectionDetail {connection} compact onBack={() => (mode = 'messages')} />
    {:else}
      <ConnectionSharing {connection} />
    {/if}
  </div>
{/if}

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
  .ws-meta { display: flex; align-items: center; gap: 6px; margin-top: 3px; }
  .type-tag {
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 1px 5px;
  }
  .ws-actions { display: flex; gap: 6px; flex-shrink: 0; }
  .ha {
    background: none;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 5px 10px;
    cursor: pointer;
    color: inherit;
    font-size: 1.05em;
  }
  .ha:hover { background: var(--bg-elevated); border-color: var(--accent); }

  .cerr {
    background: rgba(244,67,54,0.1);
    color: var(--error);
    border-bottom: 1px solid rgba(244,67,54,0.25);
    padding: 8px 16px;
    font-size: 0.85rem;
  }

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

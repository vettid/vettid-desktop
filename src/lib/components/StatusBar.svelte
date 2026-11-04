<script lang="ts">
  import { sessionStore } from '../stores/session';
  import SessionTimer from './SessionTimer.svelte';

  let session = $derived($sessionStore);

  // What the bar says for each session state (NEW TEXT, owner approval
  // needed): words, not the raw state.
  function stateLabel(state: string): string {
    switch (state) {
      case 'active': return 'Session active';
      case 'suspended': return 'Session paused';
      default: return 'No active session';
    }
  }
</script>

<div class="status-bar">
  {#if session.state === 'inactive'}
    <!-- No session yet. The desktop reaches its vault through the relay
         only for a pairing or a session, so there is no link state to
         show here. -->
    <div class="status-item">
      <span>{stateLabel(session.state)}</span>
    </div>
  {:else}
    <div class="status-item">
      <span class="dot"
        class:active={session.state === 'active'}
        class:suspended={session.state === 'suspended'}
        class:expired={session.state === 'expired' || session.state === 'revoked'}
      ></span>
      <span>{stateLabel(session.state)}</span>
    </div>

    {#if session.state === 'active'}
      <SessionTimer />
    {/if}

    <div class="status-item">
      <span class="dot" class:connected={session.phoneReachable} class:disconnected={!session.phoneReachable}></span>
      <span>Phone {session.phoneReachable ? 'reachable' : 'unreachable'}</span>
    </div>
  {/if}
</div>

<style>
  .status-bar {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 8px 20px;
    background: rgba(0, 0, 0, 0.2);
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    font-size: 0.8rem;
    color: var(--text-muted);
  }

  .status-item {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
  }

  .dot.connected, .dot.active {
    background: var(--success);
  }

  .dot.disconnected, .dot.expired {
    background: var(--error);
  }

  .dot.suspended {
    background: var(--warning);
  }
</style>

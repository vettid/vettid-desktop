<script lang="ts">
  import { sessionStore } from '../stores/session';
  import SessionTimer from '../components/SessionTimer.svelte';

  let session = $derived($sessionStore);
</script>

<div class="session-view">
  <h1>Session</h1>

  <div class="session-card">
    <div class="row">
      <span class="label">Status</span>
      <span class="value status" class:active={session.state === 'active'}
            class:suspended={session.state === 'suspended'}
            class:expired={session.state === 'expired'}>
        {session.state}
      </span>
    </div>

    {#if session.sessionId}
      <div class="row">
        <span class="label">Session ID</span>
        <span class="value mono">{session.sessionId}</span>
      </div>
    {/if}

    {#if session.state === 'active' && session.expiresAt}
      <div class="row">
        <span class="label">Time Remaining</span>
        <SessionTimer />
      </div>
    {/if}

    <div class="row">
      <span class="label">Extensions Used</span>
      <span class="value">{session.extendedCount} / {session.maxExtensions}</span>
    </div>

    <div class="row">
      <span class="label">Phone</span>
      <span class="value" class:reachable={session.phoneReachable} class:unreachable={!session.phoneReachable}>
        {session.phoneReachable ? 'Reachable' : 'Unreachable'}
      </span>
    </div>
  </div>

  {#if session.state === 'suspended'}
    <div class="alert warning">
      Your phone is unreachable. All vault operations are paused.
      Make sure your phone is connected to the internet and the VettID app is running.
    </div>
  {/if}

  {#if session.state === 'expired'}
    <div class="alert error">
      Session expired. Open VettID on your phone to extend the session, or re-pair this desktop.
    </div>
  {/if}
</div>

<style>
  .session-view {
    padding: 24px;
  }

  h1 {
    font-size: 1.3rem;
    margin-bottom: 20px;
  }

  .session-card {
    background: var(--surface);
    border-radius: 8px;
    padding: 20px;
  }

  .row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 0;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
  }

  .row:last-child {
    border-bottom: none;
  }

  .label {
    color: var(--text-muted);
  }

  .mono {
    font-family: 'Courier New', monospace;
    font-size: 0.85rem;
  }

  .status.active { color: var(--success); }
  .status.suspended { color: var(--warning); }
  .status.expired { color: var(--error); }

  .reachable { color: var(--success); }
  .unreachable { color: var(--error); }

  .alert {
    margin-top: 16px;
    padding: 16px;
    border-radius: 8px;
    font-size: 0.9rem;
  }

  .alert.warning {
    background: rgba(255, 152, 0, 0.1);
    border: 1px solid rgba(255, 152, 0, 0.3);
    color: var(--warning);
  }

  .alert.error {
    background: rgba(244, 67, 54, 0.1);
    border: 1px solid rgba(244, 67, 54, 0.3);
    color: var(--error);
  }
</style>

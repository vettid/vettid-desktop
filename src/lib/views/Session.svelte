<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { sessionStore, refreshSessionFromBackend } from '../stores/session';
  import SessionTimer from '../components/SessionTimer.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';

  let session = $derived($sessionStore);

  let busy = $state(false);
  let busyLabel = $state('');
  let statusMessage = $state('');

  let lockDialogOpen = $state(false);
  let endDialogOpen = $state(false);

  // Identity for the "Session for {name} ({email})" line. Pulled
  // from profile.get on mount — the same op the Vault view uses for
  // its header, so cached server-side after the first fetch.
  let ownerName = $state('');
  let ownerEmail = $state('');

  async function loadIdentity() {
    try {
      const resp: any = await invoke('get_profile');
      if (resp?.success && resp?.data) {
        const d = resp.data;
        const first = d.first_name ?? '';
        const last = d.last_name ?? '';
        ownerName = `${first} ${last}`.trim();
        ownerEmail = d.email ?? '';
      }
    } catch (e) {
      // Identity is a nicety, not a hard requirement — if profile.get
      // fails the rest of the session view is still useful.
    }
  }

  $effect(() => {
    if (session.state === 'active') loadIdentity();
  });

  async function doLock() {
    if (busy) return;
    busy = true;
    busyLabel = 'Locking…';
    statusMessage = '';
    try {
      await invoke('lock');
      statusMessage = 'Locked. The next launch auto-unlocks.';
      await refreshSessionFromBackend();
    } catch (e) {
      statusMessage = `Lock failed: ${e}`;
    } finally {
      busy = false;
    }
  }

  async function doEnd() {
    if (busy) return;
    busy = true;
    busyLabel = 'Ending your session…';
    statusMessage = '';
    try {
      await invoke('end_session');
      statusMessage = 'Session ended.';
      // Refresh the Svelte store immediately so the StatusBar pill +
      // App.svelte routing pick up the expired state right away
      // instead of waiting on the 30s poll. Without this the user
      // sees "nothing happened" until the timer fires.
      await refreshSessionFromBackend();
    } catch (e) {
      statusMessage = `Failed to end session: ${e}`;
    } finally {
      busy = false;
    }
  }
</script>

<ConfirmDialog
  bind:open={lockDialogOpen}
  title="Lock now?"
  message="Your vault stays paired — the next launch auto-unlocks."
  confirmLabel="Lock"
  onConfirm={doLock}
/>

<ConfirmDialog
  bind:open={endDialogOpen}
  title="End session?"
  message="You'll start a fresh session from the lock screen — no re-pairing needed on your phone."
  confirmLabel="End session"
  tone="danger"
  onConfirm={doEnd}
/>

{#if busy}
  <!-- Full-view takeover while end-session / lock is in flight. The
       end-session round-trip (publish + NATS flush + on-disk reset)
       can take a beat; without this the user sees a frozen, still-
       clickable screen and assumes nothing happened. -->
  <div class="busy-overlay">
    <div class="busy-spinner"></div>
    <p>{busyLabel}</p>
  </div>
{/if}

<div class="session-view">
  <header>
    <h1>Session</h1>
    {#if ownerName || ownerEmail}
      <p class="owner">
        for <strong>{ownerName || ownerEmail}</strong>{#if ownerName && ownerEmail} <span class="email">({ownerEmail})</span>{/if}
      </p>
    {/if}
    <p class="hint">Live state of this desktop's vault session.</p>
  </header>

  <!-- Actions row up top: Lock and End. Inline native confirm
       dialogs keep the click count down vs the previous two-step
       reveal — the user reported it felt like "nothing happened"
       because the confirm button wasn't where the muscle memory
       expected. -->
  <div class="actions">
    <button class="action-btn" onclick={() => lockDialogOpen = true}
            disabled={busy || session.state !== 'active'}>
      Lock now
    </button>
    <button class="action-btn danger" onclick={() => endDialogOpen = true}
            disabled={busy || session.state !== 'active'}>
      End session
    </button>
    {#if statusMessage}
      <span class="status-msg">{statusMessage}</span>
    {/if}
  </div>

  <div class="card">
    <div class="row">
      <span class="label">Status</span>
      <span class="value status"
            class:active={session.state === 'active'}
            class:suspended={session.state === 'suspended'}
            class:expired={session.state === 'expired' || session.state === 'revoked'}>
        {session.state}
      </span>
    </div>
    {#if session.state === 'active' && session.expiresAt}
      <div class="row">
        <span class="label">Time remaining</span>
        <span class="value timer"><SessionTimer /></span>
      </div>
    {/if}
    {#if session.sessionId}
      <div class="row">
        <span class="label">Session ID</span>
        <span class="value mono truncate">{session.sessionId}</span>
      </div>
    {/if}
    <div class="row">
      <span class="label">Extensions used</span>
      <span class="value">{session.extendedCount} / {session.maxExtensions}</span>
    </div>
    <div class="row">
      <span class="label">Phone</span>
      <span class="value"
            class:reachable={session.phoneReachable}
            class:unreachable={!session.phoneReachable}>
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
</div>

<style>
  .session-view {
    padding: 24px;
    max-width: 720px;
  }
  header {
    margin-bottom: 16px;
  }
  h1 {
    font-size: 1.3rem;
    margin-bottom: 4px;
  }
  .hint {
    color: var(--text-muted);
    font-size: 0.9rem;
    line-height: 1.5;
  }
  .owner {
    color: var(--text);
    font-size: 0.95rem;
    margin: 2px 0 4px;
  }
  .owner strong {
    font-weight: 600;
  }
  .owner .email {
    color: var(--text-muted);
    font-weight: 400;
  }

  .actions {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 20px;
    flex-wrap: wrap;
  }
  .action-btn {
    background: rgba(255, 255, 255, 0.06);
    color: var(--text);
    border: 1px solid rgba(255,255,255,0.1);
    padding: 8px 16px;
    border-radius: 6px;
    cursor: pointer;
    font: inherit;
    font-size: 0.9rem;
    white-space: nowrap;
  }
  .action-btn:hover:not(:disabled) { background: rgba(255, 255, 255, 0.1); }
  .action-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .action-btn.danger {
    background: rgba(244, 67, 54, 0.12);
    border-color: rgba(244, 67, 54, 0.35);
    color: #ef5350;
  }
  .action-btn.danger:hover:not(:disabled) { background: rgba(244, 67, 54, 0.2); }

  .status-msg {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin-left: 4px;
  }

  .card {
    background: var(--surface);
    border-radius: 8px;
    padding: 14px 18px;
  }

  .row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 0;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    gap: 16px;
  }
  .row:last-child { border-bottom: none; }

  .label { color: var(--text-muted); font-size: 0.9rem; }
  .value { font-size: 0.9rem; }
  .mono { font-family: 'Courier New', monospace; font-size: 0.8rem; }
  .truncate {
    max-width: 360px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .timer { color: var(--accent); font-weight: 500; }

  .status.active    { color: var(--success); }
  .status.suspended { color: var(--warning); }
  .status.expired   { color: var(--error); }
  .reachable        { color: var(--success); }
  .unreachable      { color: var(--error); }

  .alert {
    margin-top: 16px;
    padding: 14px;
    border-radius: 8px;
    font-size: 0.9rem;
  }
  .alert.warning {
    background: rgba(255, 152, 0, 0.1);
    border: 1px solid rgba(255, 152, 0, 0.3);
    color: var(--warning);
  }

  .busy-overlay {
    position: fixed;
    inset: 0;
    z-index: 50;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 16px;
    background: var(--bg, #0e0e12);
    color: var(--text, #e8e8ea);
    font-size: 0.95rem;
  }
  .busy-spinner {
    width: 30px;
    height: 30px;
    border: 3px solid rgba(255, 255, 255, 0.1);
    border-top-color: var(--accent, #6b8afd);
    border-radius: 50%;
    animation: session-busy-spin 0.9s linear infinite;
  }
  @keyframes session-busy-spin {
    to { transform: rotate(360deg); }
  }
</style>

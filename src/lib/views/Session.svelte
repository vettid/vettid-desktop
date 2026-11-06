<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { sessionStore, vaultStore, askToEnd, endBusy, endStatus } from '../stores/session';
  import { vaultScreen, endOffered, unreachableAlertShown } from '../vaultState.js';
  import SessionTimer from '../components/SessionTimer.svelte';

  let session = $derived($sessionStore);
  // #77: the vault's state (the hold-off line while `due`).
  let screen = $derived(vaultScreen($vaultStore));

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

  // End session, its confirmation and its "Ending your session…" overlay
  // live above the views (stores/session.ts, App.svelte, #77): a screen
  // swap while it is open or under way loses nothing.
</script>

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

  <!-- Actions row up top: End session (#76: no Lock now; the owner's
       decision: End session is how this desktop's access stops). -->
  <div class="actions">
    {#if endOffered(screen.kind)}
      <button class="action-btn danger" onclick={askToEnd}
              disabled={$endBusy}>
        End session
      </button>
    {/if}
    {#if $endStatus}
      <span class="status-msg">{$endStatus}</span>
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
      <span class="label">Phone</span>
      <span class="value"
            class:reachable={session.phoneReachable}
            class:unreachable={!session.phoneReachable}>
        {session.phoneReachable ? 'Reachable' : 'Unreachable'}
      </span>
    </div>
  </div>

  {#if screen.holdOff}
    <!-- #77: past the deadline with the hold off: the session continues. -->
    <div class="alert warning" role="status">{screen.holdOff}</div>
  {/if}

  {#if unreachableAlertShown(session)}
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
</style>

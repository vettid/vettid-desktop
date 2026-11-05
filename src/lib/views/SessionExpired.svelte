<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { onDestroy } from 'svelte';
  import { noticeOf } from '../tooSoon.js';
  import { activateSession, sessionNotice, endPending, vaultStore, askToEnd, endBusy } from '../stores/session';
  import { vaultScreen, endOffered } from '../vaultState.js';

  // #77: the vault's lock and hold (§3.2-§3.4). Held, locked or unknown,
  // this screen says so in place of the session, with End session; Start
  // New Session only while the vault is open.
  let screen = $derived(vaultScreen($vaultStore));

  let step = $state<'idle' | 'awaiting-qr' | 'awaiting-approval' | 'success' | 'error' | 'removed-unconfirmed'>('idle');
  let removedNotice = $state('');
  let errorMessage = $state('');
  let unlistenRequested: UnlistenFn | null = null;

  onDestroy(() => { unlistenRequested?.(); });

  interface RegisterResponse {
    success: boolean;
    error?: string;
    connection_id?: string;
    session_id?: string;
    expires_at?: number;
    /** After too_soon: when it may ask again (unix seconds, #83). */
    retry_at?: number | null;
  }

  /**
   * Starts a fresh session against the existing pairing: the desktop asks
   * its vault for an access session (device.session.request), and the
   * owner's phone is asked to approve it. The backend emits
   * `session:requested` once the vault has taken the request.
   */
  async function start() {
    errorMessage = '';
    step = 'awaiting-qr';

    unlistenRequested = await listen('session:requested', () => {
      step = 'awaiting-approval';
    });

    try {
      const result = await invoke<RegisterResponse>('extend_session');
      if (result.success && result.session_id && result.expires_at) {
        step = 'success';
        activateSession(result.session_id, result.expires_at, result.connection_id);
      } else {
        step = 'error';
        // #83: the time in this computer's own locale.
        errorMessage = noticeOf(result, 'Extension failed');
      }
    } catch (e: any) {
      step = 'error';
      errorMessage = e.toString();
    }
  }

  /**
   * Logout removes this desktop's pairing entirely — wipes the
   * on-disk pairing (this build can't tell the vault yet). The
   * user has to re-pair after this. Distinct from "End session,
   * keep pairing" which is the default reason to be on this screen.
   */
  async function logoutFromHere() {
    try {
      sessionNotice.set(null);
      const result = await invoke<{ revoke_sent: boolean; local_wiped: boolean; notice?: string | null }>('logout');
      if (result?.revoke_sent && result?.local_wiped && !result?.notice) {
        window.location.reload();
      } else {
        // The vault was not told, or the pairing is still on disk: the
        // person has to read this before the reload.
        step = 'removed-unconfirmed';
        errorMessage = '';
        removedNotice = result?.notice
          || 'This desktop has been logged out here, but your vault was not told. Remove this desktop on your phone.';
      }
    } catch (e: any) {
      errorMessage = `Logout failed: ${e}`;
    }
  }

  function reset() {
    step = 'idle';
    errorMessage = '';
    unlistenRequested?.();
    unlistenRequested = null;
  }
</script>

<div class="wrap">
  <div class="card">
    {#if screen.showStart}
      <h1>Start a new session</h1>
      <p class="subtitle">
        Your pairing is in place — tap Start to ask your phone to authorize this
        desktop again. Your data stays hidden until the phone approves.
      </p>
    {:else}
      <div class="vault-state {screen.kind}" role="status">
        {#each screen.lines as line, i}
          <p class:lead={i === 0}>{line}</p>
        {/each}
      </div>
    {/if}

    {#if $sessionNotice}
      <p class="error-text" role="status">{$sessionNotice}</p>
    {:else if $endPending && step === 'idle'}
      <!-- #80: an end the vault hasn't answered never looks like a confirmed one. -->
      <div class="waiting" role="status">
        <div class="spinner"></div>
        <p>Ending your session… This desktop is waiting for your vault to confirm it.</p>
      </div>
    {/if}

    {#if step === 'idle'}
      {#if screen.showStart}
        <button class="btn primary" onclick={start}>
          Start New Session
        </button>
      {/if}
      {#if endOffered(screen.kind, false)}
        <!-- §3.2: End session in every state; device.session.end is
             allowed while held, and a stored end keeps retrying. -->
        <button class="btn danger" onclick={askToEnd} disabled={$endBusy}>
          End session
        </button>
      {/if}
      <button class="btn ghost" onclick={logoutFromHere}>
        Remove this desktop instead
      </button>

    {:else if step === 'awaiting-qr'}
      <div class="waiting"><div class="spinner"></div><p>Requesting authorization…</p></div>

    {:else if step === 'awaiting-approval'}
      <div class="waiting">
        <div class="spinner"></div>
        <p>Awaiting approval on your phone…</p>
      </div>

    {:else if step === 'success'}
      <div class="success-msg">Session started.</div>

    {:else if step === 'removed-unconfirmed'}
      <p class="error-text" role="alert">{removedNotice}</p>
      <button class="btn primary" onclick={() => window.location.reload()}>OK</button>

    {:else if step === 'error'}
      <p class="error-text">{errorMessage}</p>
      <button class="btn primary" onclick={reset}>Try Again</button>
    {/if}

    {#if errorMessage && step !== 'error'}
      <p class="error-text">{errorMessage}</p>
    {/if}
  </div>
</div>

<style>
  .wrap { display: flex; justify-content: center; align-items: center; flex: 1; padding: 40px; }
  .card { background: var(--surface); padding: 40px; border-radius: 12px; max-width: 460px; width: 100%; }
  h1 { font-size: 1.5rem; margin-bottom: 8px; }
  .subtitle { color: var(--text-muted); margin-bottom: 20px; line-height: 1.5; }
  .btn { width: 100%; padding: 12px; border: none; border-radius: 6px;
         font-size: 1rem; cursor: pointer; margin-bottom: 8px; }
  .btn.primary { background: var(--accent); color: #1a1a1a; font-weight: 500; }
  .btn.primary:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn.ghost { background: transparent; color: var(--text-muted);
               border: 1px solid rgba(255,255,255,0.1); }
  .btn.danger { background: rgba(244, 67, 54, 0.12); color: #ef5350;
                border: 1px solid rgba(244, 67, 54, 0.35); }
  .btn.danger:disabled { opacity: 0.5; cursor: not-allowed; }
  .vault-state { padding: 16px; border-radius: 8px; margin-bottom: 20px;
                 background: rgba(255, 152, 0, 0.1); border: 1px solid rgba(255, 152, 0, 0.3); }
  .vault-state.unknown { background: rgba(255, 255, 255, 0.04); border-color: rgba(255, 255, 255, 0.1); }
  .vault-state p { color: var(--text-muted); line-height: 1.5; margin-top: 8px; }
  .vault-state p.lead { color: var(--text); font-size: 1.05rem; margin-top: 0; }
  .waiting { display: flex; align-items: center; gap: 12px; padding: 16px;
             background: rgba(15, 52, 96, 0.3); border-radius: 8px; margin-top: 16px; }
  .waiting p { color: var(--text-muted); }
  .spinner {
    width: 20px; height: 20px;
    border: 2px solid rgba(233, 69, 96, 0.3); border-top-color: var(--accent);
    border-radius: 50%; animation: spin 1s linear infinite; flex-shrink: 0;
  }
  .success-msg {
    padding: 16px; background: rgba(76, 175, 80, 0.15);
    border: 1px solid rgba(76, 175, 80, 0.3); border-radius: 8px;
    color: var(--success); margin-bottom: 16px; text-align: center;
  }
  .error-text { color: var(--error); font-size: 0.9rem; margin-top: 12px; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>

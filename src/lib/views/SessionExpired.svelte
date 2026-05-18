<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import QRCode from 'qrcode';
  import { onDestroy } from 'svelte';
  import { activateSession } from '../stores/session';

  let step = $state<'idle' | 'awaiting-qr' | 'awaiting-approval' | 'success' | 'error'>('idle');
  let errorMessage = $state('');
  let qrDataUrl = $state('');
  let unlistenQr: UnlistenFn | null = null;

  onDestroy(() => { unlistenQr?.(); });

  interface RegisterResponse {
    success: boolean;
    error?: string;
    connection_id?: string;
    session_id?: string;
    expires_at?: number;
  }

  /**
   * Starts a fresh session against the existing pairing. The desktop
   * publishes device.request-session with new ephemeral keys; the
   * phone gets a notification + auto-navigates to the authorize
   * screen; the user scans the QR shown here to approve. No
   * passphrase — the on-disk creds are unlocked by the OS keyring
   * (or the machine-bound fallback).
   */
  async function start() {
    errorMessage = '';
    step = 'awaiting-qr';

    unlistenQr = await listen<{ connection_id: string; qr_payload: string }>('pairing:qr-ready', async (event) => {
      try {
        qrDataUrl = await QRCode.toDataURL(event.payload.qr_payload, { margin: 1, width: 280 });
      } catch (e) {
        errorMessage = `Failed to render QR: ${e}`;
      }
      step = 'awaiting-approval';
    });

    try {
      const result = await invoke<RegisterResponse>('extend_session');
      if (result.success && result.session_id && result.expires_at) {
        step = 'success';
        activateSession(result.session_id, result.expires_at, result.connection_id);
      } else {
        step = 'error';
        errorMessage = result.error || 'Extension failed';
      }
    } catch (e: any) {
      step = 'error';
      errorMessage = e.toString();
    }
  }

  /**
   * Logout removes this desktop's pairing entirely — wipes the
   * on-disk credentials + asks the vault to revoke the device. The
   * user has to re-pair after this. Distinct from "End session,
   * keep pairing" which is the default reason to be on this screen.
   */
  async function logoutFromHere() {
    try {
      await invoke('logout');
      window.location.reload();
    } catch (e: any) {
      errorMessage = `Logout failed: ${e}`;
    }
  }

  function reset() {
    step = 'idle';
    errorMessage = '';
    qrDataUrl = '';
    unlistenQr?.();
    unlistenQr = null;
  }
</script>

<div class="wrap">
  <div class="card">
    <h1>Start a new session</h1>
    <p class="subtitle">
      Your pairing is in place — tap Start to ask your phone to authorize this
      desktop again. You'll see a QR here that your phone will scan to approve.
      Your data stays hidden until the phone approves.
    </p>

    {#if step === 'idle'}
      <button class="btn primary" onclick={start}>
        Start New Session
      </button>
      <button class="btn ghost" onclick={logoutFromHere}>
        Remove this desktop instead
      </button>

    {:else if step === 'awaiting-qr'}
      <div class="waiting"><div class="spinner"></div><p>Requesting authorization…</p></div>

    {:else if step === 'awaiting-approval'}
      <p class="subtitle">Scan this QR with your phone.</p>
      {#if qrDataUrl}
        <img src={qrDataUrl} alt="Authorization QR" class="qr" />
      {/if}
      <div class="waiting">
        <div class="spinner"></div>
        <p>Awaiting approval on your phone…</p>
      </div>

    {:else if step === 'success'}
      <div class="success-msg">Session started.</div>

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
  .btn.primary { background: var(--accent); color: white; }
  .btn.primary:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn.ghost { background: transparent; color: var(--text-muted);
               border: 1px solid rgba(255,255,255,0.1); }
  .qr { display: block; margin: 0 auto 16px; background: white; padding: 10px; border-radius: 8px; }
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

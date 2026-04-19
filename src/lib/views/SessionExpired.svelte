<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import QRCode from 'qrcode';
  import { onDestroy } from 'svelte';
  import { activateSession } from '../stores/session';

  let passphrase = $state('');
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

  async function start() {
    if (passphrase.length < 8) {
      errorMessage = 'Enter your passphrase (minimum 8 characters).';
      return;
    }
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
      const result = await invoke<RegisterResponse>('extend_session', { passphrase });
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

  async function logoutFromHere() {
    if (!passphrase) {
      errorMessage = 'Enter passphrase to log out (needed to notify the vault).';
      return;
    }
    try {
      await invoke('logout', { passphrase });
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
    <h1>Session expired</h1>
    <p class="subtitle">
      Scan a new QR with your phone to extend this desktop's session. Your data is
      hidden until a phone approves the extension.
    </p>

    {#if step === 'idle'}
      <input
        type="password"
        bind:value={passphrase}
        placeholder="Passphrase"
        class="input"
      />
      <button class="btn primary" onclick={start} disabled={!passphrase}>
        Scan to Extend
      </button>
      <button class="btn ghost" onclick={logoutFromHere}>
        Log out instead
      </button>

    {:else if step === 'awaiting-qr'}
      <div class="waiting"><div class="spinner"></div><p>Requesting extension…</p></div>

    {:else if step === 'awaiting-approval'}
      <p class="subtitle">Scan this QR with your phone.</p>
      {#if qrDataUrl}
        <img src={qrDataUrl} alt="Extension QR" class="qr" />
      {/if}
      <div class="waiting">
        <div class="spinner"></div>
        <p>Awaiting approval on your phone…</p>
      </div>

    {:else if step === 'success'}
      <div class="success-msg">Session extended.</div>

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
  .input {
    width: 100%; padding: 12px; margin-bottom: 12px;
    background: var(--bg); border: 1px solid rgba(255,255,255,0.1);
    border-radius: 6px; color: var(--text); font-size: 1rem; outline: none;
  }
  .input:focus { border-color: var(--accent); }
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

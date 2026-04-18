<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import QRCode from 'qrcode';
  import { onDestroy } from 'svelte';

  let inviteCode = $state('');
  let passphrase = $state('');
  let confirmPassphrase = $state('');
  let step = $state<'code' | 'passphrase' | 'awaiting-qr' | 'awaiting-approval' | 'success' | 'error'>('code');
  let errorMessage = $state('');
  let qrDataUrl = $state('');
  let connectionId = $state('');
  let unlistenQr: UnlistenFn | null = null;

  onDestroy(() => {
    unlistenQr?.();
  });

  async function advanceToPassphrase() {
    if (inviteCode.length !== 8) {
      errorMessage = 'Invite code must be 8 characters.';
      return;
    }
    errorMessage = '';
    step = 'passphrase';
  }

  async function submit() {
    if (passphrase !== confirmPassphrase) {
      errorMessage = 'Passphrases do not match.';
      return;
    }
    if (passphrase.length < 8) {
      errorMessage = 'Passphrase must be at least 8 characters.';
      return;
    }

    errorMessage = '';
    step = 'awaiting-qr';

    // Listen for the QR event emitted by the backend after stage-1 resolves.
    unlistenQr = await listen<{ connection_id: string; qr_payload: string }>('pairing:qr-ready', async (event) => {
      connectionId = event.payload.connection_id;
      try {
        qrDataUrl = await QRCode.toDataURL(event.payload.qr_payload, { margin: 1, width: 280 });
      } catch (e) {
        errorMessage = `Failed to render QR: ${e}`;
      }
      step = 'awaiting-approval';
    });

    try {
      const result: any = await invoke('register', {
        request: { invite_code: inviteCode, passphrase },
      });

      if (result.success) {
        step = 'success';
      } else {
        step = 'error';
        errorMessage = result.error || 'Pairing failed';
      }
    } catch (e: any) {
      step = 'error';
      errorMessage = e.toString();
    }
  }

  function reset() {
    step = 'code';
    inviteCode = '';
    passphrase = '';
    confirmPassphrase = '';
    errorMessage = '';
    qrDataUrl = '';
    connectionId = '';
    unlistenQr?.();
    unlistenQr = null;
  }
</script>

<div class="pairing">
  <div class="card">
    <h1>Connect Desktop</h1>
    <p class="subtitle">Pair this desktop to your VettID vault.</p>

    {#if step === 'code'}
      <ol class="instructions">
        <li>Open VettID on your phone.</li>
        <li>Tap <strong>Connect Desktop</strong> from the feed FAB.</li>
        <li>Enter the 8-character code shown below.</li>
      </ol>

      <input
        type="text"
        bind:value={inviteCode}
        maxlength="8"
        placeholder="ABC23456"
        class="code-field"
        oninput={() => { inviteCode = inviteCode.toUpperCase(); errorMessage = ''; }}
      />

      <button class="btn primary" onclick={advanceToPassphrase} disabled={inviteCode.length !== 8}>
        Continue
      </button>

    {:else if step === 'passphrase'}
      <p class="subtitle">
        Choose a passphrase to encrypt this desktop's credentials on disk.
        It's combined with your machine's fingerprint, so the store can't be decrypted on another machine.
      </p>

      <input
        type="password"
        bind:value={passphrase}
        placeholder="Encryption passphrase"
        class="input"
      />
      <input
        type="password"
        bind:value={confirmPassphrase}
        placeholder="Confirm passphrase"
        class="input"
      />

      <button class="btn primary" onclick={submit}
              disabled={!passphrase || passphrase !== confirmPassphrase}>
        Connect
      </button>
      <button class="btn secondary" onclick={() => { step = 'code'; errorMessage = ''; }}>
        Back
      </button>

    {:else if step === 'awaiting-qr'}
      <div class="waiting">
        <div class="spinner"></div>
        <p>Resolving invite…</p>
      </div>

    {:else if step === 'awaiting-approval'}
      <p class="subtitle">Scan this QR with your phone to authorize the session.</p>
      {#if qrDataUrl}
        <img src={qrDataUrl} alt="Authorization QR" class="qr" />
      {/if}
      <div class="waiting">
        <div class="spinner"></div>
        <p>Awaiting approval on your phone…</p>
      </div>

    {:else if step === 'success'}
      <div class="success-msg">Desktop paired! Session active.</div>
      <button class="btn primary" onclick={() => window.location.reload()}>Continue</button>

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
  .pairing { display: flex; justify-content: center; align-items: center; flex: 1; padding: 40px; }
  .card { background: var(--surface); padding: 40px; border-radius: 12px; max-width: 460px; width: 100%; }
  h1 { font-size: 1.5rem; margin-bottom: 8px; }
  .subtitle { color: var(--text-muted); margin-bottom: 20px; line-height: 1.5; }
  .instructions { padding-left: 20px; margin-bottom: 24px; line-height: 1.6; color: var(--text-muted); }
  .instructions li { margin-bottom: 8px; }
  .code-field {
    width: 100%; padding: 16px; font-size: 2rem; text-align: center;
    letter-spacing: 0.5em; font-family: 'Courier New', monospace;
    background: var(--bg); border: 2px solid rgba(255,255,255,0.1);
    border-radius: 8px; color: var(--text); outline: none; margin-bottom: 20px;
  }
  .code-field:focus { border-color: var(--accent); }
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
  .btn.secondary { background: rgba(255,255,255,0.05); color: var(--text-muted); }
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

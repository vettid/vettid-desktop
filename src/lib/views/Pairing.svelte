<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import QRCode from 'qrcode';
  import { onDestroy } from 'svelte';

  let inviteCode = $state('');
  let step = $state<'code' | 'awaiting-qr' | 'awaiting-approval' | 'success' | 'error'>('code');
  let errorMessage = $state('');
  let qrDataUrl = $state('');
  let connectionId = $state('');
  let unlistenQr: UnlistenFn | null = null;

  onDestroy(() => {
    unlistenQr?.();
  });

  // Svelte action: focus the input when it mounts so the user can
  // start typing immediately. Re-applies on each step transition
  // because the input gets remounted under a fresh `{#if}` branch.
  function autofocus(node: HTMLInputElement) {
    queueMicrotask(() => node.focus());
  }

  async function submit() {
    // The phone app generates 12-char codes displayed as three
    // 4-character blocks (ABCD-EFGH-JKLM). Accept either form on
    // input — strip dashes/whitespace before validating.
    inviteCode = inviteCode.replace(/[\s-]/g, '').toUpperCase();
    if (inviteCode.length !== 12) {
      errorMessage = 'Invite code must be 12 characters.';
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
        request: { invite_code: inviteCode },
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
        <li>Type the 12-character code shown below — dashes are optional.</li>
      </ol>

      <input
        type="text"
        bind:value={inviteCode}
        maxlength="14"
        placeholder="ABCD-EFGH-JKLM"
        class="code-field"
        use:autofocus
        oninput={() => { inviteCode = inviteCode.toUpperCase(); errorMessage = ''; }}
        onkeydown={(e) => {
          if (e.key === 'Enter' && inviteCode.replace(/[\s-]/g, '').length === 12) {
            e.preventDefault();
            submit();
          }
        }}
      />

      <button class="btn primary" onclick={submit} disabled={inviteCode.replace(/[\s-]/g, '').length !== 12}>
        Connect
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
    width: 100%;
    padding: 16px;
    /* Sized so all 14 chars (12 code + 2 dashes) fit at once.
       The phone displays the code as ABCD-EFGH-JKLM; we want
       the entry field to render the same shape comfortably. */
    font-size: 1.4rem;
    text-align: center;
    letter-spacing: 0.18em;
    font-family: 'Courier New', monospace;
    background: var(--bg);
    border: 2px solid rgba(255,255,255,0.1);
    border-radius: 8px;
    color: var(--text);
    outline: none;
    margin-bottom: 20px;
  }
  .code-field:focus { border-color: var(--accent); }
  .input {
    width: 100%; padding: 12px; margin-bottom: 12px;
    background: var(--bg); border: 1px solid rgba(255,255,255,0.1);
    border-radius: 6px; color: var(--text); font-size: 1rem; outline: none;
  }
  .input:focus { border-color: var(--accent); }

  /* Passphrase row: input + inline show/hide toggle. The first
     passphrase input is wrapped so the toggle sits over its right
     edge; the confirm input below keeps the same width since both
     fields hide-or-show together when the toggle flips. */
  .pw-row {
    position: relative;
    margin-bottom: 12px;
  }
  .pw-row .pw-input {
    margin-bottom: 0;
    padding-right: 64px;
  }
  .pw-toggle {
    position: absolute;
    right: 4px;
    top: 50%;
    transform: translateY(-50%);
    background: transparent;
    border: none;
    color: var(--text-muted);
    font: inherit;
    font-size: 0.85rem;
    padding: 6px 10px;
    cursor: pointer;
  }
  .pw-toggle:hover { color: var(--text); }
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

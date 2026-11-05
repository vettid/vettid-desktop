<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { onDestroy } from 'svelte';
  import { sessionNotice } from '../stores/session';
  import { pairingHeld } from '../stores/navigation';

  let inviteCode = $state('');
  let step = $state<'code' | 'awaiting-qr' | 'awaiting-approval' | 'success' | 'error' | 'paired-no-session'>('code');
  let errorMessage = $state('');
  // The six-digit code the member compares with their phone (§6.7).
  let sas = $state('');
  let sasInstruction = $state('');
  let unlistenSas: UnlistenFn | null = null;

  // #79: from Connect until the person leaves the result, routing leaves
  // this view alone, so a rejection or "Desktop paired!" is what they see.
  $effect(() => {
    pairingHeld.set(step !== 'code');
  });

  onDestroy(() => {
    unlistenSas?.();
    pairingHeld.set(false);
  });

  // Svelte action: focus the input when it mounts so the user can
  // start typing immediately. Re-applies on each step transition
  // because the input gets remounted under a fresh `{#if}` branch.
  function autofocus(node: HTMLInputElement) {
    queueMicrotask(() => node.focus());
  }

  async function submit() {
    // The pairing code is pasted as the phone shows it; the backend reads
    // it (only surrounding whitespace is dropped).
    inviteCode = inviteCode.trim();
    if (!inviteCode) return;
    errorMessage = '';
    step = 'awaiting-qr';

    // The backend emits the SAS once the handshake with the vault is done.
    unlistenSas = await listen<{ sas: string; instruction: string }>('pairing:sas', (event) => {
      sas = event.payload.sas;
      sasInstruction = event.payload.instruction;
      step = 'awaiting-approval';
    });

    try {
      const result: any = await invoke('register', {
        request: { invite_code: inviteCode },
      });

      if (result.success) {
        sessionNotice.set(null);
        step = 'success';
      } else if (result.paired_without_session) {
        // #33: the pairing is saved, only the session isn't: continue to
        // Start New Session, don't offer to pair again.
        step = 'paired-no-session';
        errorMessage = result.error || '';
        // Shown on Start New Session too, if routing gets there first.
        sessionNotice.set(result.error || null);
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
    sas = '';
    sasInstruction = '';
    unlistenSas?.();
    unlistenSas = null;
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
        <li>Copy the pairing code your phone shows, and paste it below.</li>
      </ol>

      <input
        type="text"
        bind:value={inviteCode}
        placeholder="Pairing code"
        class="code-field"
        spellcheck="false"
        autocomplete="off"
        use:autofocus
        oninput={() => { errorMessage = ''; }}
        onkeydown={(e) => {
          if (e.key === 'Enter' && inviteCode.trim()) {
            e.preventDefault();
            submit();
          }
        }}
      />

      <button class="btn primary" onclick={submit} disabled={!inviteCode.trim()}>
        Connect
      </button>

    {:else if step === 'awaiting-qr'}
      <div class="waiting">
        <div class="spinner"></div>
        <p>Resolving invite…</p>
      </div>

    {:else if step === 'awaiting-approval'}
      {#if sas}
        <p class="sas" aria-label="Pairing check code">{sas}</p>
      {/if}
      <p class="subtitle">{sasInstruction}</p>
      <div class="waiting">
        <div class="spinner"></div>
        <p>Awaiting approval on your phone…</p>
      </div>

    {:else if step === 'paired-no-session'}
      <p class="error-text" role="alert">{errorMessage}</p>
      <button class="btn primary" onclick={() => window.location.reload()}>Continue</button>

    {:else if step === 'success'}
      <div class="success-msg">Desktop paired! Session active.</div>
      <button class="btn primary" onclick={() => window.location.reload()}>Continue</button>

    {:else if step === 'error'}
      <p class="error-text">{errorMessage}</p>
      <button class="btn primary" onclick={reset}>Try Again</button>
    {/if}

    {#if errorMessage && step !== 'error' && step !== 'paired-no-session'}
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
  .btn.primary { background: var(--accent); color: #1a1a1a; font-weight: 500; }
  .btn.primary:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn.secondary { background: rgba(255,255,255,0.05); color: var(--text-muted); }
  .sas { font-family: 'Courier New', monospace; font-size: 2rem; letter-spacing: 0.3em; text-align: center; margin: 8px 0 12px; }
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

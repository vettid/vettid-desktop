<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { activateSession } from '../stores/session';

  let shortlinkCode = $state('');
  let passphrase = $state('');
  let confirmPassphrase = $state('');
  let status = $state<'idle' | 'registering' | 'waiting' | 'success' | 'error'>('idle');
  let errorMessage = $state('');
  let step = $state<'code' | 'passphrase'>('code');

  async function startPairing() {
    if (shortlinkCode.length !== 6) {
      errorMessage = 'Please enter a 6-character code';
      return;
    }
    step = 'passphrase';
  }

  async function submitRegistration() {
    if (passphrase !== confirmPassphrase) {
      errorMessage = 'Passphrases do not match';
      return;
    }
    if (passphrase.length < 8) {
      errorMessage = 'Passphrase must be at least 8 characters';
      return;
    }

    errorMessage = '';
    status = 'registering';

    try {
      const result: any = await invoke('register', {
        request: { shortlink_code: shortlinkCode, passphrase }
      });

      if (result.success) {
        status = 'success';
        // Session activation happens when we receive the session info from vault
      } else {
        status = 'error';
        errorMessage = result.error || 'Registration failed';
      }
    } catch (e: any) {
      status = 'error';
      errorMessage = e.toString();
    }
  }
</script>

<div class="pairing">
  <div class="card">
    <h1>Pair Desktop</h1>
    <p class="subtitle">Connect this desktop to your VettID vault</p>

    {#if step === 'code'}
      <div class="instructions">
        <ol>
          <li>Open VettID on your phone</li>
          <li>Go to Settings &rarr; Connected Devices &rarr; Pair Desktop</li>
          <li>Enter the 6-character code shown on your phone</li>
        </ol>
      </div>

      <div class="code-input">
        <input
          type="text"
          bind:value={shortlinkCode}
          maxlength="6"
          placeholder="ABC123"
          class="code-field"
          class:error={errorMessage !== ''}
          oninput={() => { shortlinkCode = shortlinkCode.toUpperCase(); errorMessage = ''; }}
        />
      </div>

      <button class="btn primary" onclick={startPairing} disabled={shortlinkCode.length !== 6}>
        Continue
      </button>

    {:else if step === 'passphrase'}
      <div class="instructions">
        <p>Choose a passphrase to encrypt your desktop credentials.
           This passphrase is used together with your machine's hardware fingerprint.</p>
      </div>

      <div class="form">
        <input
          type="password"
          bind:value={passphrase}
          placeholder="Encryption passphrase"
          class="input"
          disabled={status === 'registering'}
        />
        <input
          type="password"
          bind:value={confirmPassphrase}
          placeholder="Confirm passphrase"
          class="input"
          disabled={status === 'registering'}
        />
      </div>

      {#if status === 'idle' || status === 'error'}
        <button class="btn primary" onclick={submitRegistration}
                disabled={!passphrase || passphrase !== confirmPassphrase}>
          Register
        </button>
        <button class="btn secondary" onclick={() => { step = 'code'; errorMessage = ''; }}>
          Back
        </button>
      {/if}

      {#if status === 'registering'}
        <div class="waiting">
          <div class="spinner"></div>
          <p>Registering... Approve the connection on your phone.</p>
        </div>
      {/if}

      {#if status === 'success'}
        <div class="success-msg">
          Desktop paired successfully!
        </div>
      {/if}
    {/if}

    {#if errorMessage}
      <p class="error-text">{errorMessage}</p>
    {/if}
  </div>
</div>

<style>
  .pairing {
    display: flex;
    justify-content: center;
    align-items: center;
    flex: 1;
    padding: 40px;
  }

  .card {
    background: var(--surface);
    padding: 40px;
    border-radius: 12px;
    max-width: 460px;
    width: 100%;
  }

  h1 {
    font-size: 1.5rem;
    margin-bottom: 8px;
  }

  .subtitle {
    color: var(--text-muted);
    margin-bottom: 24px;
  }

  .instructions {
    margin-bottom: 24px;
    line-height: 1.6;
  }

  .instructions ol {
    padding-left: 20px;
  }

  .instructions li {
    margin-bottom: 8px;
    color: var(--text-muted);
  }

  .code-input {
    margin-bottom: 20px;
  }

  .code-field {
    width: 100%;
    padding: 16px;
    font-size: 2rem;
    text-align: center;
    letter-spacing: 0.5em;
    font-family: 'Courier New', monospace;
    background: var(--bg);
    border: 2px solid rgba(255, 255, 255, 0.1);
    border-radius: 8px;
    color: var(--text);
    outline: none;
  }

  .code-field:focus {
    border-color: var(--accent);
  }

  .code-field.error {
    border-color: var(--error);
  }

  .form {
    display: flex;
    flex-direction: column;
    gap: 12px;
    margin-bottom: 20px;
  }

  .input {
    padding: 12px;
    background: var(--bg);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 6px;
    color: var(--text);
    font-size: 1rem;
    outline: none;
  }

  .input:focus {
    border-color: var(--accent);
  }

  .btn {
    width: 100%;
    padding: 12px;
    border: none;
    border-radius: 6px;
    font-size: 1rem;
    cursor: pointer;
    margin-bottom: 8px;
  }

  .btn.primary {
    background: var(--accent);
    color: white;
  }

  .btn.primary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .btn.secondary {
    background: rgba(255, 255, 255, 0.05);
    color: var(--text-muted);
  }

  .error-text {
    color: var(--error);
    font-size: 0.9rem;
    margin-top: 12px;
  }

  .waiting {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 16px;
    background: rgba(15, 52, 96, 0.3);
    border-radius: 8px;
    margin-top: 16px;
  }

  .waiting p {
    color: var(--text-muted);
  }

  .spinner {
    width: 20px;
    height: 20px;
    border: 2px solid rgba(233, 69, 96, 0.3);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 1s linear infinite;
    flex-shrink: 0;
  }

  .success-msg {
    padding: 16px;
    background: rgba(76, 175, 80, 0.15);
    border: 1px solid rgba(76, 175, 80, 0.3);
    border-radius: 8px;
    color: var(--success);
    margin-top: 16px;
    text-align: center;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }
</style>

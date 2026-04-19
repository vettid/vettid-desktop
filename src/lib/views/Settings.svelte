<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { sessionStore } from '../stores/session';
  import { themeStore, setTheme, type Theme } from '../stores/theme';
  import { natsStore } from '../stores/nats';

  let session = $derived($sessionStore);
  let theme = $derived($themeStore);
  let nats = $derived($natsStore);

  let deviceInfo = $state<{
    hostname: string;
    platform: string;
    binaryFingerprint: string;
    appVersion: string;
  } | null>(null);

  let loading = $state(true);
  let locking = $state(false);
  let lockMessage = $state('');

  let loggingOut = $state(false);
  let logoutPassphrase = $state('');
  let showLogoutPrompt = $state(false);
  let logoutMessage = $state('');

  async function loadDeviceInfo() {
    try {
      const status: any = await invoke('get_status');
      deviceInfo = {
        hostname: status.hostname || 'Unknown',
        platform: status.platform || 'Unknown',
        binaryFingerprint: status.binary_fingerprint || 'Unknown',
        appVersion: status.app_version || '0.1.0',
      };
    } catch {
      deviceInfo = {
        hostname: 'Unknown',
        platform: 'linux',
        binaryFingerprint: 'N/A',
        appVersion: '0.1.0',
      };
    } finally {
      loading = false;
    }
  }

  async function lockApp() {
    if (locking) return;
    const ok = confirm('Lock the app? You will need to enter your passphrase to unlock.');
    if (!ok) return;
    locking = true;
    lockMessage = '';
    try {
      await invoke('lock');
      lockMessage = 'Locked.';
    } catch (e) {
      lockMessage = `Lock failed: ${e}`;
    }
    locking = false;
  }

  async function doLogout() {
    if (loggingOut) return;
    if (!logoutPassphrase) {
      logoutMessage = 'Enter your passphrase — needed to notify the vault.';
      return;
    }
    loggingOut = true;
    logoutMessage = '';
    try {
      await invoke('logout', { passphrase: logoutPassphrase });
      logoutPassphrase = '';
      logoutMessage = 'Logged out. Reloading…';
      setTimeout(() => window.location.reload(), 600);
    } catch (e) {
      logoutMessage = `Logout failed: ${e}`;
      loggingOut = false;
    }
  }

  $effect(() => {
    loadDeviceInfo();
  });
</script>

<div class="settings-view">
  <h1>Settings</h1>

  <div class="section">
    <h2>Device Information</h2>
    <div class="card">
      {#if loading}
        <div class="loading">Loading...</div>
      {:else if deviceInfo}
        <div class="row">
          <span class="label">Hostname</span>
          <span class="value">{deviceInfo.hostname}</span>
        </div>
        <div class="row">
          <span class="label">Platform</span>
          <span class="value">{deviceInfo.platform}</span>
        </div>
        <div class="row">
          <span class="label">App Version</span>
          <span class="value">{deviceInfo.appVersion}</span>
        </div>
        <div class="row">
          <span class="label">Binary Fingerprint</span>
          <span class="value mono truncate">{deviceInfo.binaryFingerprint}</span>
        </div>
      {/if}
    </div>
  </div>

  {#if session.state !== 'inactive'}
    <div class="section">
      <h2>Session</h2>
      <div class="card">
        <div class="row">
          <span class="label">Session ID</span>
          <span class="value mono">{session.sessionId || 'N/A'}</span>
        </div>
        <div class="row">
          <span class="label">Status</span>
          <span class="value status" class:active={session.state === 'active'}
                class:suspended={session.state === 'suspended'}
                class:expired={session.state === 'expired'}>
            {session.state}
          </span>
        </div>
        <div class="row">
          <span class="label">Extensions Used</span>
          <span class="value">{session.extendedCount} / {session.maxExtensions}</span>
        </div>
        <div class="row">
          <span class="label">Phone Reachable</span>
          <span class="value" class:reachable={session.phoneReachable} class:unreachable={!session.phoneReachable}>
            {session.phoneReachable ? 'Yes' : 'No'}
          </span>
        </div>
      </div>
    </div>

    <div class="section">
      <h2>Connection</h2>
      <div class="card">
        <div class="row">
          <span class="label">Owner</span>
          <span class="value">{session.ownerName || 'N/A'}</span>
        </div>
        <div class="row">
          <span class="label">Connection ID</span>
          <span class="value mono truncate">{session.connectionId || 'N/A'}</span>
        </div>
      </div>
    </div>

    <div class="section">
      <h2>Log out</h2>
      <div class="card">
        <p class="hint">
          Logging out notifies the vault, removes this desktop from your device list,
          and erases all local credentials. You'll need to pair again with a new invite code.
        </p>
        {#if !showLogoutPrompt}
          <button class="danger-btn" onclick={() => showLogoutPrompt = true}>
            Log out this desktop
          </button>
        {:else}
          <input
            type="password"
            bind:value={logoutPassphrase}
            placeholder="Enter passphrase to confirm"
            class="input"
            disabled={loggingOut}
          />
          <div class="btn-row">
            <button class="danger-btn" onclick={doLogout} disabled={loggingOut || !logoutPassphrase}>
              {loggingOut ? 'Logging out…' : 'Confirm logout'}
            </button>
            <button class="ghost-btn" onclick={() => { showLogoutPrompt = false; logoutPassphrase = ''; logoutMessage = ''; }}>
              Cancel
            </button>
          </div>
        {/if}
        {#if logoutMessage}
          <p class="logout-msg">{logoutMessage}</p>
        {/if}
      </div>
    </div>
  {/if}

  <div class="section">
    <h2>Appearance</h2>
    <div class="card">
      <div class="row">
        <span class="label">Theme</span>
        <div class="theme-options">
          {#each ['light', 'dark', 'auto'] as opt}
            <button
              class="theme-btn"
              class:active={theme === opt}
              onclick={() => setTheme(opt as Theme)}
            >{opt}</button>
          {/each}
        </div>
      </div>
    </div>
  </div>

  <div class="section">
    <h2>Security</h2>
    <div class="card">
      <div class="row">
        <span class="label">Lock vault</span>
        <button class="lock-btn" onclick={lockApp} disabled={locking || session.state === 'inactive'}>
          {locking ? 'Locking…' : 'Lock now'}
        </button>
      </div>
      {#if lockMessage}
        <div class="lock-msg">{lockMessage}</div>
      {/if}
    </div>
  </div>

  <div class="section">
    <h2>Network</h2>
    <div class="card">
      <div class="row">
        <span class="label">NATS state</span>
        <span class="value" class:reachable={nats.connected} class:unreachable={!nats.connected}>
          {nats.rawState ?? 'unknown'}
        </span>
      </div>
      {#if nats.error}
        <div class="row">
          <span class="label">Last error</span>
          <span class="value">{nats.error}</span>
        </div>
      {/if}
    </div>
  </div>

  <div class="section">
    <h2>About</h2>
    <div class="card">
      <div class="row">
        <span class="label">Application</span>
        <span class="value">VettID Desktop</span>
      </div>
      <div class="row">
        <span class="label">Version</span>
        <span class="value">0.1.0</span>
      </div>
    </div>
  </div>
</div>

<style>
  .settings-view {
    padding: 24px;
  }

  h1 {
    font-size: 1.3rem;
    margin-bottom: 20px;
  }

  .section {
    margin-bottom: 24px;
  }

  h2 {
    font-size: 1rem;
    color: var(--text-muted);
    margin-bottom: 8px;
  }

  .card {
    background: var(--surface);
    border-radius: 8px;
    padding: 16px 20px;
  }

  .row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 0;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
  }

  .row:last-child {
    border-bottom: none;
  }

  .label {
    color: var(--text-muted);
    font-size: 0.9rem;
  }

  .value {
    font-size: 0.9rem;
  }

  .mono {
    font-family: 'Courier New', monospace;
    font-size: 0.8rem;
  }

  .truncate {
    max-width: 250px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .status.active { color: var(--success); }
  .status.suspended { color: var(--warning); }
  .status.expired { color: var(--error); }

  .reachable { color: var(--success); }
  .unreachable { color: var(--error); }

  .loading {
    text-align: center;
    color: var(--text-muted);
    padding: 20px;
  }

  .theme-options { display: flex; gap: 6px; }
  .theme-btn {
    background: transparent;
    color: inherit;
    border: 1px solid var(--border, rgba(255,255,255,0.15));
    border-radius: 4px;
    padding: 4px 12px;
    cursor: pointer;
    font: inherit;
    text-transform: capitalize;
    font-size: 0.85rem;
  }
  .theme-btn.active { background: var(--accent, #ffc125); color: #000; border-color: var(--accent, #ffc125); }

  .lock-btn {
    background: rgba(198, 40, 40, 0.15);
    color: #ef5350;
    border: 1px solid rgba(198, 40, 40, 0.4);
    padding: 6px 14px;
    border-radius: 4px;
    cursor: pointer;
    font: inherit;
  }
  .lock-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .lock-msg { padding: 8px 0 0; font-size: 0.85rem; color: var(--text-muted); }

  .hint { color: var(--text-muted); font-size: 0.85rem; margin: 0 0 12px; line-height: 1.5; }
  .btn-row { display: flex; gap: 8px; margin-top: 8px; }
  .danger-btn {
    background: rgba(198, 40, 40, 0.15);
    color: #ef5350;
    border: 1px solid rgba(198, 40, 40, 0.4);
    padding: 8px 16px;
    border-radius: 4px;
    cursor: pointer;
    font: inherit;
  }
  .danger-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .ghost-btn {
    background: transparent;
    color: var(--text-muted);
    border: 1px solid rgba(255, 255, 255, 0.1);
    padding: 8px 16px;
    border-radius: 4px;
    cursor: pointer;
    font: inherit;
  }
  .input {
    width: 100%;
    padding: 10px 12px;
    background: var(--bg);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 4px;
    color: var(--text);
    font-size: 0.95rem;
    outline: none;
    margin-bottom: 8px;
  }
  .input:focus { border-color: var(--accent); }
  .input:disabled { opacity: 0.5; }
  .logout-msg { padding: 8px 0 0; font-size: 0.85rem; color: var(--text-muted); }
</style>

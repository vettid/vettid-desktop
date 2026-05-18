<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { themeStore, setTheme, type Theme } from '../stores/theme';

  let theme = $derived($themeStore);

  // Sub-pages cover persistent preferences only — live session ops
  // (Lock, End session, NATS diagnostics) moved to the Session
  // screen since they're transient operations the user reaches via
  // the top-bar pill. Settings keeps Device / Appearance / Danger
  // Zone (Log out) / About.
  type SubPage = 'device' | 'appearance' | 'danger' | 'about';
  let subPage = $state<SubPage>('device');

  let deviceInfo = $state<{
    hostname: string;
    platform: string;
    osName: string;
    osVersion: string;
    binaryFingerprint: string;
    machineFingerprint: string;
    appVersion: string;
  } | null>(null);

  let loading = $state(true);

  let loggingOut = $state(false);
  let showLogoutPrompt = $state(false);
  let logoutMessage = $state('');

  async function loadDeviceInfo() {
    try {
      const status: any = await invoke('get_status');
      deviceInfo = {
        hostname: status.hostname || 'Unknown',
        platform: status.platform || 'Unknown',
        osName: status.os_name || '',
        osVersion: status.os_version || '',
        binaryFingerprint: status.binary_fingerprint || '',
        machineFingerprint: status.machine_fingerprint || '',
        appVersion: status.app_version || '0.1.0',
      };
    } catch {
      deviceInfo = {
        hostname: 'Unknown',
        platform: 'linux',
        osName: '',
        osVersion: '',
        binaryFingerprint: '',
        machineFingerprint: '',
        appVersion: '0.1.0',
      };
    } finally {
      loading = false;
    }
  }

  async function doLogout() {
    if (loggingOut) return;
    loggingOut = true;
    logoutMessage = '';
    try {
      await invoke('logout');
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

<div class="settings">
  <aside class="settings-nav">
    <h1>Settings</h1>
    <nav>
      <button class:active={subPage === 'device'}     onclick={() => subPage = 'device'}>Device</button>
      <button class:active={subPage === 'appearance'} onclick={() => subPage = 'appearance'}>Appearance</button>
      <button class:active={subPage === 'danger'}     onclick={() => subPage = 'danger'}>Danger zone</button>
      <button class:active={subPage === 'about'}      onclick={() => subPage = 'about'}>About</button>
    </nav>
  </aside>

  <section class="settings-pane">
    {#if subPage === 'device'}
      <h2>Device</h2>
      <p class="hint">
        Identity this desktop sends to the vault at pairing time. The phone's
        Authorize Desktop screen shows the same values — compare to confirm
        you're approving the right machine.
      </p>
      <div class="card">
        {#if loading}
          <div class="loading">Loading…</div>
        {:else if deviceInfo}
          <div class="row">
            <span class="label">Hostname</span>
            <span class="value">{deviceInfo.hostname}</span>
          </div>
          {#if deviceInfo.osName}
            <div class="row">
              <span class="label">OS</span>
              <span class="value">{deviceInfo.osName} {deviceInfo.osVersion}</span>
            </div>
          {/if}
          <div class="row">
            <span class="label">Platform</span>
            <span class="value">{deviceInfo.platform}</span>
          </div>
          <div class="row">
            <span class="label">App version</span>
            <span class="value">{deviceInfo.appVersion}</span>
          </div>
          <div class="row stacked">
            <span class="label">Binary fingerprint</span>
            <span class="value mono wrap">{deviceInfo.binaryFingerprint || '—'}</span>
          </div>
          <div class="row stacked">
            <span class="label">Machine fingerprint</span>
            <span class="value mono wrap">{deviceInfo.machineFingerprint || '—'}</span>
          </div>
        {/if}
      </div>

    {:else if subPage === 'appearance'}
      <h2>Appearance</h2>
      <p class="hint">Pick how the desktop looks. Auto follows your OS preference.</p>
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

    {:else if subPage === 'danger'}
      <h2>Danger zone</h2>
      <p class="hint">
        Log out removes this desktop's pairing entirely. For lock or end-session
        (which keep the pairing), open the Session screen from the top-bar pill.
      </p>
      <div class="card danger">
        <div class="row">
          <div>
            <div class="label">Log out this desktop</div>
            <div class="hint inline">
              Wipes the credentials on disk + the keyring entry and notifies
              the vault. You'll need to pair again from your phone.
            </div>
          </div>
          {#if !showLogoutPrompt}
            <button class="danger-btn" onclick={() => showLogoutPrompt = true}>
              Log out
            </button>
          {/if}
        </div>
        {#if showLogoutPrompt}
          <p class="hint">Are you sure? This wipes the pairing — you'll need to pair again from your phone.</p>
          <div class="btn-row">
            <button class="danger-btn" onclick={doLogout} disabled={loggingOut}>
              {loggingOut ? 'Logging out…' : 'Confirm logout'}
            </button>
            <button class="ghost-btn" onclick={() => { showLogoutPrompt = false; logoutMessage = ''; }}>
              Cancel
            </button>
          </div>
        {/if}
        {#if logoutMessage}
          <p class="logout-msg">{logoutMessage}</p>
        {/if}
      </div>

    {:else if subPage === 'about'}
      <h2>About</h2>
      <p class="hint">Build info for this VettID Desktop install.</p>
      <div class="card">
        <div class="row">
          <span class="label">Application</span>
          <span class="value">VettID Desktop</span>
        </div>
        <div class="row">
          <span class="label">Version</span>
          <span class="value">{deviceInfo?.appVersion ?? '0.1.0'}</span>
        </div>
      </div>
    {/if}
  </section>
</div>

<style>
  .settings {
    display: flex;
    flex: 1;
    overflow: hidden;
  }

  .settings-nav {
    width: 200px;
    padding: 20px;
    border-right: 1px solid rgba(255, 255, 255, 0.05);
    overflow-y: auto;
    flex-shrink: 0;
  }
  .settings-nav h1 {
    font-size: 1.2rem;
    margin-bottom: 18px;
  }
  .settings-nav nav {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .settings-nav button {
    background: transparent;
    border: none;
    color: var(--text-muted);
    padding: 8px 12px;
    border-radius: 6px;
    text-align: left;
    cursor: pointer;
    font: inherit;
    font-size: 0.9rem;
  }
  .settings-nav button:hover { background: rgba(255, 255, 255, 0.04); color: var(--text); }
  .settings-nav button.active {
    color: var(--accent);
    background: var(--accent-muted);
  }

  .settings-pane {
    flex: 1;
    padding: 24px;
    overflow-y: auto;
    max-width: 720px;
  }
  .settings-pane h2 {
    font-size: 1.25rem;
    margin-bottom: 6px;
  }
  .settings-pane .hint {
    color: var(--text-muted);
    margin-bottom: 16px;
    font-size: 0.9rem;
    line-height: 1.5;
  }
  .settings-pane .hint.inline {
    margin: 4px 0 0;
    max-width: 380px;
  }

  .card {
    background: var(--surface);
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 24px;
  }
  .card.danger {
    border: 1px solid rgba(244, 67, 54, 0.18);
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
  /* Stacked rows are for long mono values (full 64-char hashes)
     that can't sit on the same line as the label without ellipsis.
     Label on top, value below, full width. */
  .row.stacked {
    flex-direction: column;
    align-items: flex-start;
    gap: 4px;
  }

  .label {
    color: var(--text-muted);
    font-size: 0.9rem;
  }
  .value { font-size: 0.9rem; }
  .mono { font-family: 'Courier New', monospace; font-size: 0.8rem; }
  .wrap {
    word-break: break-all;
    white-space: normal;
    max-width: 100%;
  }
  .truncate {
    max-width: 320px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .reachable { color: var(--success); }
  .unreachable { color: var(--error); }

  .loading {
    text-align: center;
    color: var(--text-muted);
    padding: 16px;
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
  .theme-btn.active { background: var(--accent); color: #000; border-color: var(--accent); }

  .action-btn {
    background: rgba(255, 255, 255, 0.06);
    color: var(--text);
    border: 1px solid rgba(255,255,255,0.1);
    padding: 6px 14px;
    border-radius: 6px;
    cursor: pointer;
    font: inherit;
    font-size: 0.85rem;
    white-space: nowrap;
  }
  .action-btn:hover:not(:disabled) { background: rgba(255, 255, 255, 0.1); }
  .action-btn:disabled { opacity: 0.4; cursor: not-allowed; }

  .danger-heading {
    margin-top: 24px;
    margin-bottom: 12px;
    font-size: 0.85rem;
    color: var(--error);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }

  .danger-btn {
    background: rgba(244, 67, 54, 0.15);
    color: #ef5350;
    border: 1px solid rgba(244, 67, 54, 0.4);
    padding: 6px 14px;
    border-radius: 6px;
    cursor: pointer;
    font: inherit;
    font-size: 0.85rem;
    white-space: nowrap;
  }
  .danger-btn:disabled { opacity: 0.4; cursor: not-allowed; }

  .ghost-btn {
    background: transparent;
    color: var(--text-muted);
    border: 1px solid rgba(255, 255, 255, 0.1);
    padding: 6px 14px;
    border-radius: 6px;
    cursor: pointer;
    font: inherit;
    font-size: 0.85rem;
  }

  .btn-row { display: flex; gap: 8px; margin-top: 10px; }
  .lock-msg { padding: 6px 0 0; font-size: 0.85rem; color: var(--text-muted); }
  .logout-msg { padding: 8px 0 0; font-size: 0.85rem; color: var(--text-muted); }
</style>

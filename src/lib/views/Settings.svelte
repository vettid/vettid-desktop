<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { sessionStore } from '../stores/session';

  let session = $derived($sessionStore);

  let deviceInfo = $state<{
    hostname: string;
    platform: string;
    binaryFingerprint: string;
    appVersion: string;
  } | null>(null);

  let loading = $state(true);

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
  {/if}

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
</style>

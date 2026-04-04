<script lang="ts">
    import { invoke } from '@tauri-apps/api/core';
    import type { ConnectedDevice, VaultOpResponse } from '../../types';

    let devices: ConnectedDevice[] = $state([]);
    let loading = $state(true);
    let error = $state('');

    async function loadDevices() {
        loading = true; error = '';
        try {
            const resp: VaultOpResponse = await invoke('list_devices');
            if (resp.success && resp.data) {
                const data = resp.data as { devices?: ConnectedDevice[] };
                devices = data.devices ?? [];
            } else { error = resp.error ?? 'Failed to load devices'; }
        } catch (e) { error = String(e); }
        loading = false;
    }

    $effect(() => { loadDevices(); });
</script>

<div class="devices-view">
    <div class="header"><h3>Connected Devices</h3><button class="refresh" aria-label="Refresh" onclick={loadDevices}>↻</button></div>

    {#if loading}<div class="status">Loading devices...</div>
    {:else if error}<div class="status error">{error}</div>
    {:else if devices.length === 0}<div class="status">No connected devices</div>
    {:else}
        <ul class="device-list">
            {#each devices as device}
                <li class="device-item">
                    <div class="device-icon">🖥</div>
                    <div class="device-info">
                        <div class="device-name">{device.hostname}</div>
                        <div class="device-meta">{device.platform} — {device.status}</div>
                        {#if device.last_heartbeat}
                            <div class="device-heartbeat">Last seen: {new Date(device.last_heartbeat).toLocaleString()}</div>
                        {/if}
                    </div>
                    <span class="status-dot {device.status}"></span>
                </li>
            {/each}
        </ul>
    {/if}
</div>

<style>
    .devices-view { height: 100%; display: flex; flex-direction: column; }
    .header { display: flex; justify-content: space-between; align-items: center; padding: 0 0 12px; }
    .header h3 { margin: 0; }
    .refresh { background: none; border: 1px solid var(--border); border-radius: 4px; cursor: pointer; padding: 4px 8px; }
    .status { color: var(--text-secondary); padding: 24px; text-align: center; }
    .status.error { color: var(--danger); }
    .device-list { list-style: none; padding: 0; }
    .device-item { display: flex; align-items: center; gap: 12px; padding: 12px; border-bottom: 1px solid var(--border); }
    .device-icon { font-size: 1.5em; }
    .device-info { flex: 1; }
    .device-name { font-weight: 500; }
    .device-meta { font-size: 0.85em; color: var(--text-secondary); }
    .device-heartbeat { font-size: 0.8em; color: var(--text-secondary); }
    .status-dot { width: 10px; height: 10px; border-radius: 50%; }
    .status-dot.active { background: #4caf50; }
    .status-dot.suspended { background: #ff9800; }
    .status-dot.expired, .status-dot.revoked { background: #f44336; }
</style>

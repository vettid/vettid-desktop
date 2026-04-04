<script lang="ts">
    import { invoke } from '@tauri-apps/api/core';
    import { listen } from '@tauri-apps/api/event';
    import type { SecretEntry, VaultOpResponse } from '../../types';

    let secrets: SecretEntry[] = $state([]);
    let loading = $state(true);
    let error = $state('');
    let pendingSecretId: string | null = $state(null);
    let revealedSecretId: string | null = $state(null);
    let revealedValue: string = $state('');
    let autoHideTimer: ReturnType<typeof setTimeout> | null = $state(null);

    async function loadSecrets() {
        loading = true;
        error = '';
        try {
            const resp: VaultOpResponse = await invoke('list_secrets_catalog');
            if (resp.success && resp.data) {
                const data = resp.data as { secrets?: SecretEntry[] };
                secrets = data.secrets ?? [];
            } else {
                error = resp.error ?? 'Failed to load secrets';
            }
        } catch (e) {
            error = String(e);
        }
        loading = false;
    }

    async function requestReveal(secretId: string) {
        pendingSecretId = secretId;
        error = '';
        try {
            const resp: VaultOpResponse = await invoke('request_secret', { secretId });
            if (resp.pending_approval) {
                // Waiting for phone approval — listen for result
            } else if (resp.success && resp.data) {
                // Secret value returned directly
                showRevealedSecret(secretId, (resp.data as { value?: string }).value ?? '');
            } else {
                error = resp.error ?? 'Failed to retrieve secret';
                pendingSecretId = null;
            }
        } catch (e) {
            error = String(e);
            pendingSecretId = null;
        }
    }

    function showRevealedSecret(secretId: string, value: string) {
        pendingSecretId = null;
        revealedSecretId = secretId;
        revealedValue = value;

        // Auto-hide after 30 seconds
        if (autoHideTimer) clearTimeout(autoHideTimer);
        autoHideTimer = setTimeout(() => {
            hideSecret();
        }, 30000);
    }

    function hideSecret() {
        revealedSecretId = null;
        revealedValue = '';
        if (autoHideTimer) {
            clearTimeout(autoHideTimer);
            autoHideTimer = null;
        }
    }

    function copySecret() {
        navigator.clipboard.writeText(revealedValue);
    }

    $effect(() => { loadSecrets(); });

    // Listen for phone approval results that reveal secrets
    $effect(() => {
        const unlisten = listen<{ requestId: string; data?: { value?: string } }>('vault:phone-approval-result', (event) => {
            if (pendingSecretId && event.payload.data?.value) {
                showRevealedSecret(pendingSecretId, event.payload.data.value);
            }
        });
        return () => { unlisten.then(fn => fn()); };
    });
</script>

<div class="secrets-view">
    <div class="header">
        <h3>Secrets</h3>
        <button class="refresh" aria-label="Refresh" onclick={loadSecrets}>↻</button>
    </div>

    {#if loading}
        <div class="status">Loading secrets catalog...</div>
    {:else if error}
        <div class="status error">{error}
            <button class="retry-btn" onclick={loadSecrets}>Retry</button>
        </div>
    {:else if secrets.length === 0}
        <div class="status">No secrets stored. Add secrets from your phone.</div>
    {:else}
        <ul class="secrets-list">
            {#each secrets as secret}
                <li class="secret-item">
                    <div class="secret-info">
                        <div class="secret-name">{secret.name}</div>
                        <div class="secret-meta">{secret.category}</div>
                    </div>

                    {#if revealedSecretId === secret.id}
                        <div class="revealed-value">
                            <code>{revealedValue}</code>
                            <button class="copy-btn" onclick={copySecret}>Copy</button>
                            <button class="hide-btn" onclick={hideSecret}>Hide</button>
                        </div>
                    {:else}
                        <button
                            class="reveal-btn"
                            onclick={() => requestReveal(secret.id)}
                            disabled={pendingSecretId === secret.id}
                        >
                            {pendingSecretId === secret.id ? 'Waiting for phone...' : 'Reveal'}
                        </button>
                    {/if}
                </li>
            {/each}
        </ul>
        <div class="phone-note">Revealing a secret requires approval on your phone.</div>
    {/if}
</div>

<style>
    .secrets-view { height: 100%; display: flex; flex-direction: column; }
    .header { display: flex; justify-content: space-between; align-items: center; padding: 0 0 12px; }
    .header h3 { margin: 0; }
    .refresh { background: none; border: 1px solid var(--border); border-radius: 4px; cursor: pointer; padding: 4px 8px; }
    .status { color: var(--text-secondary); padding: 24px; text-align: center; }
    .status.error { color: var(--danger); }
    .retry-btn { margin-left: 8px; padding: 4px 10px; border: 1px solid var(--danger); color: var(--danger); background: none; border-radius: 4px; cursor: pointer; font-size: 0.85em; }
    .secrets-list { list-style: none; padding: 0; margin: 0; overflow-y: auto; flex: 1; }
    .secret-item { display: flex; align-items: center; justify-content: space-between; padding: 12px; border-bottom: 1px solid var(--border); gap: 12px; }
    .secret-name { font-weight: 500; }
    .secret-meta { font-size: 0.85em; color: var(--text-secondary); }
    .reveal-btn { padding: 6px 12px; border: 1px solid var(--accent); color: var(--accent); background: none; border-radius: 4px; cursor: pointer; font-size: 0.85em; flex-shrink: 0; }
    .reveal-btn:hover:not(:disabled) { background: var(--accent-bg); }
    .reveal-btn:disabled { opacity: 0.5; cursor: default; }
    .revealed-value { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
    .revealed-value code { padding: 4px 8px; background: var(--bg-hover); border-radius: 4px; font-size: 0.85em; max-width: 200px; overflow: hidden; text-overflow: ellipsis; }
    .copy-btn, .hide-btn { padding: 4px 8px; border: 1px solid var(--border); background: none; border-radius: 4px; cursor: pointer; font-size: 0.8em; }
    .phone-note { font-size: 0.8em; color: var(--text-secondary); text-align: center; padding: 12px; }
</style>

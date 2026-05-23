<script lang="ts">
    import { invoke } from '@tauri-apps/api/core';
    import { listen, type UnlistenFn } from '@tauri-apps/api/event';
    import { onMount } from 'svelte';
    import type { Connection, VaultOpResponse } from '../../types';
    import { clearSelectedConnection } from '../../stores/navigation';
    import { peerName } from '../../connectionName';

    /**
     * Cached verify-identity state from the vault. Mirrors the
     * `CachedVerifyState` struct in
     * enclave/vault-manager/connection_verify_state.go. Survives PIN-lock
     * and re-seal so the Detail row can render "Verified 3 minutes ago"
     * without round-tripping the peer.
     */
    interface VerifyState {
        last_outbound_at?: string;
        last_outbound_ok?: boolean;
        last_outbound_reason?: string;
        last_inbound_at?: string;
        last_inbound_ok?: boolean;
        last_inbound_reason?: string;
    }

    interface Props {
        connection: Connection;
        // Back action. The Connections shell passes a handler that
        // returns to the conversation view; defaults to clearing the
        // selection (→ list) when used standalone.
        onBack?: () => void;
        /** Hide the local identity header when embedded in
         *  ConnectionWorkspace, which owns the workspace header. */
        compact?: boolean;
    }

    let { connection, onBack, compact = false }: Props = $props();
    const handleBack = (): void => (onBack ?? clearSelectedConnection)();

    // svelte-ignore state_referenced_locally
    let detail = $state<Connection>({ ...connection });
    let loading = $state(false);
    let error = $state('');

    let verifyState = $state<VerifyState | null>(null);

    // Resync local `detail` when the parent swaps to a different connection
    // (and trigger a fresh fetch). Without this the warning fires because
    // `$state` would otherwise only capture the prop's initial value.
    $effect(() => {
        detail = connection;
        refreshDetail();
        refreshVerifyState();
    });

    async function refreshDetail() {
        loading = true;
        error = '';
        try {
            const resp: VaultOpResponse = await invoke('get_connection', {
                connectionId: connection.connection_id,
            });
            if (resp.success && resp.data) {
                const data = resp.data as { connection?: Connection };
                if (data.connection) detail = data.connection;
            } else if (resp.error) {
                error = resp.error;
            }
        } catch (e) {
            error = String(e);
        }
        loading = false;
    }

    /**
     * Re-fetch cached verify state from the vault. Called on screen
     * entry and again whenever a connection-event push arrives — the
     * `connection.authenticate-result` subject lands here once the peer
     * has signed (or refused) the challenge.
     */
    async function refreshVerifyState() {
        try {
            const resp: VaultOpResponse = await invoke('get_connection_verify_state', {
                connectionId: connection.connection_id,
            });
            if (resp.success && resp.data) {
                const data = resp.data as { state?: VerifyState };
                verifyState = data.state ?? null;
            }
        } catch {
            // Best-effort — leave prior state in place on transient errors.
        }
    }

    // Listen for connection.authenticate-result pushes (and any other
    // connection lifecycle event) and refresh verify state if the event
    // is for the currently selected connection. The Rust listener routes
    // all `forApp.connection.*` subjects through `vault:connection-event`.
    let unlistenConnection: UnlistenFn | null = null;
    onMount(() => {
        let stale = false;
        listen<{ subject: string; payload_b64: string }>('vault:connection-event', (event) => {
            const subject = event.payload?.subject ?? '';
            // Only refresh on verify-relevant subjects — connection.peer-accepted,
            // .activated, .key-exchanged, etc., never touch verify-state.
            if (!subject.includes('authenticate')) return;
            // The decoded payload carries the connection_id; refetch
            // unconditionally for the current connection regardless,
            // because the vault has the authoritative timestamp.
            void refreshVerifyState();
        }).then((fn) => {
            if (stale) fn();
            else unlistenConnection = fn;
        });
        return () => {
            stale = true;
            unlistenConnection?.();
            unlistenConnection = null;
        };
    });

    /** "3 minutes ago"-style relative timestamp for the verify-state row. */
    function relativeTime(iso: string): string {
        if (!iso) return '';
        const then = new Date(iso).getTime();
        if (isNaN(then)) return '';
        const diff = Date.now() - then;
        const sec = Math.floor(diff / 1000);
        if (sec < 60) return 'just now';
        const min = Math.floor(sec / 60);
        if (min < 60) return `${min} minute${min === 1 ? '' : 's'} ago`;
        const hr = Math.floor(min / 60);
        if (hr < 24) return `${hr} hour${hr === 1 ? '' : 's'} ago`;
        const day = Math.floor(hr / 24);
        if (day < 30) return `${day} day${day === 1 ? '' : 's'} ago`;
        return new Date(iso).toLocaleDateString();
    }

    function formatField(key: string, value: unknown): string {
        if (typeof value === 'string') return value;
        return JSON.stringify(value);
    }

    let revoking = $state(false);
    let revokeMessage = $state('');
    let rotating = $state(false);
    let rotateMessage = $state('');
    let verifying = $state(false);
    let verifyMessage = $state('');

    /**
     * Rotate the E2E keys with this peer. Phone-required — the desktop
     * initiates, the user approves on their phone, and the new keys are
     * derived in the enclave and bound to both sides on success.
     */
    async function rotateKeys() {
        const ok = confirm(`Rotate E2E keys with ${peerName(detail)}? Requires phone approval.`);
        if (!ok) return;
        rotating = true;
        rotateMessage = '';
        try {
            const resp: VaultOpResponse = await invoke('rotate_connection_keys', {
                connectionId: detail.connection_id,
            });
            if (resp.success) {
                rotateMessage = 'Key rotation triggered.';
                await refreshDetail();
            } else if (resp.pending_approval) {
                rotateMessage = 'Waiting for phone approval…';
            } else {
                rotateMessage = resp.error ?? 'Rotate failed';
            }
        } catch (e) {
            rotateMessage = String(e);
        }
        rotating = false;
    }

    /**
     * Challenge the peer to prove they still hold their private key.
     * Phone-required to authorize the challenge. The verification
     * result arrives asynchronously — peer's vault signs a nonce, ours
     * verifies, and the verify-state push reaches us via the listener.
     */
    async function verifyIdentity() {
        verifying = true;
        verifyMessage = '';
        try {
            const resp: VaultOpResponse = await invoke('authenticate_connection', {
                connectionId: detail.connection_id,
            });
            if (resp.success) {
                verifyMessage = 'Challenge sent — result will appear once the peer responds.';
            } else if (resp.pending_approval) {
                verifyMessage = 'Waiting for phone approval…';
            } else {
                verifyMessage = resp.error ?? 'Verify failed';
            }
        } catch (e) {
            verifyMessage = String(e);
        }
        verifying = false;
    }

    /**
     * Revoke this connection. Phone-required — the desktop only initiates;
     * the user approves on their phone. The push event from the vault will
     * refresh the list once the revocation lands.
     */
    async function revoke() {
        const ok = confirm(`Revoke connection with ${peerName(detail)}? This requires phone approval.`);
        if (!ok) return;
        revoking = true;
        revokeMessage = '';
        try {
            const resp: VaultOpResponse = await invoke('revoke_connection', {
                connectionId: detail.connection_id,
            });
            if (resp.success) {
                revokeMessage = 'Connection revoked.';
            } else if (resp.pending_approval) {
                revokeMessage = 'Waiting for phone approval…';
            } else {
                revokeMessage = resp.error ?? 'Revoke failed';
            }
        } catch (e) {
            revokeMessage = String(e);
        }
        revoking = false;
    }
</script>

<div class="detail">
    {#if !compact}
        <header class="bar">
            <button class="back" onclick={handleBack} aria-label="Back">←</button>
            <h3>{peerName(detail)}</h3>
            <span class="status-badge {detail.status}">{detail.status}</span>
        </header>
    {/if}

    {#if loading}
        <div class="status">Loading…</div>
    {:else if error}
        <div class="status error">{error}</div>
    {:else}
        <div class="scroll">
            <!-- Profile section -->
            <section class="card">
                <h4>Profile</h4>
                <div class="profile-head">
                    <div class="avatar-large">
                        {#if detail.peer_profile?.photo}
                            <img src={`data:image/png;base64,${detail.peer_profile.photo}`} alt="" />
                        {:else}
                            <span class="initials-large">{peerName(detail).slice(0, 1).toUpperCase()}</span>
                        {/if}
                    </div>
                    <div class="profile-id">
                        <div class="full-name">{peerName(detail)}</div>
                        {#if detail.peer_profile?.email}
                            <div class="sub">{detail.peer_profile.email}</div>
                        {/if}
                    </div>
                </div>

                {#if detail.peer_profile?.fields}
                    <dl class="fields">
                        {#each Object.entries(detail.peer_profile.fields) as [key, field]}
                            <dt>{field.display_name ?? key}</dt>
                            <dd>{formatField(key, field.value)}</dd>
                        {/each}
                    </dl>
                {/if}
            </section>

            <!-- Connection metadata -->
            <section class="card">
                <h4>Connection</h4>
                <dl class="fields">
                    <dt>ID</dt>
                    <dd class="mono">{detail.connection_id}</dd>
                    <dt>Direction</dt>
                    <dd>{detail.direction}</dd>
                    <dt>Created</dt>
                    <dd>{new Date(detail.created_at).toLocaleString()}</dd>
                    {#if detail.e2e_public_key}
                        <dt>E2E key</dt>
                        <dd class="mono truncate">{detail.e2e_public_key.slice(0, 32)}…</dd>
                    {/if}
                </dl>
            </section>

            <!-- Manage -->
            <section class="card">
                <h4>Manage</h4>

                <div class="action-group">
                    <div class="action-row">
                        <button
                            class="action-ghost"
                            onclick={verifyIdentity}
                            disabled={detail.status !== 'active' || verifying}
                        >{verifying ? 'Challenging…' : 'Verify identity'}</button>
                        {#if verifyState?.last_outbound_at}
                            <span class="verify-pill {verifyState.last_outbound_ok ? 'ok' : 'failed'}">
                                {verifyState.last_outbound_ok ? '✓ Verified' : '✗ Failed'}
                                · {relativeTime(verifyState.last_outbound_at)}
                            </span>
                        {:else}
                            <span class="verify-pill neutral">Not yet verified</span>
                        {/if}
                    </div>
                    <p class="hint">
                        Challenge the peer to prove they still hold the
                        private key that bound this connection. Phone
                        approval required.
                    </p>
                    {#if verifyState?.last_outbound_at && !verifyState.last_outbound_ok && verifyState.last_outbound_reason}
                        <p class="action-msg failed">Reason: {verifyState.last_outbound_reason}</p>
                    {/if}
                    {#if verifyMessage}<p class="action-msg">{verifyMessage}</p>{/if}
                </div>

                <div class="action-group">
                    <button
                        class="action-ghost"
                        onclick={rotateKeys}
                        disabled={detail.status !== 'active' || rotating}
                    >{rotating ? 'Rotating…' : 'Rotate E2E keys'}</button>
                    <p class="hint">
                        Roll the end-to-end encryption keys with this peer.
                        Phone approval required.
                    </p>
                    {#if rotateMessage}<p class="action-msg">{rotateMessage}</p>{/if}
                </div>

                <div class="action-group">
                    <button class="danger" onclick={revoke} disabled={detail.status !== 'active' || revoking}>
                        {revoking ? 'Submitting…' : 'Revoke connection'}
                    </button>
                    <p class="hint">Requires approval from your phone.</p>
                    {#if revokeMessage}<p class="revoke-msg">{revokeMessage}</p>{/if}
                </div>
            </section>
        </div>
    {/if}
</div>

<style>
    .detail { height: 100%; display: flex; flex-direction: column; }
    .bar {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 0 0 12px;
        border-bottom: 1px solid var(--border);
    }
    .bar h3 { margin: 0; flex: 1; }
    .back {
        background: none;
        border: 1px solid var(--border);
        border-radius: 4px;
        padding: 4px 10px;
        cursor: pointer;
        color: inherit;
    }
    .status-badge { font-size: 0.7em; padding: 2px 8px; border-radius: 3px; text-transform: capitalize; }
    .status-badge.active { background: rgba(46, 125, 50, 0.2); color: #4caf50; }
    .status-badge.pending { background: rgba(230, 81, 0, 0.2); color: #ff9800; }
    .status-badge.revoked, .status-badge.expired { background: rgba(198, 40, 40, 0.2); color: #f44336; }

    .scroll { flex: 1; overflow-y: auto; padding-top: 12px; }
    .status { padding: 24px; text-align: center; color: var(--text-secondary); }
    .status.error { color: var(--danger); }

    .card {
        background: var(--surface, #1a1a1a);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
    }
    .card h4 { margin: 0 0 12px; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); }

    .profile-head { display: flex; gap: 14px; align-items: center; margin-bottom: 12px; }
    .avatar-large {
        width: 64px; height: 64px; border-radius: 50%;
        background: var(--accent-muted, #333);
        display: flex; align-items: center; justify-content: center;
        overflow: hidden;
    }
    .avatar-large img { width: 100%; height: 100%; object-fit: cover; }
    .initials-large { font-size: 1.6em; font-weight: 600; color: var(--accent); }
    .full-name { font-size: 1.1em; font-weight: 500; }
    .sub { font-size: 0.85em; color: var(--text-secondary); margin-top: 2px; }

    .fields { display: grid; grid-template-columns: minmax(110px, auto) 1fr; gap: 6px 14px; margin: 0; }
    .fields dt { color: var(--text-secondary); font-size: 0.85em; }
    .fields dd { margin: 0; font-size: 0.9em; word-break: break-word; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.8em; }
    .truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    .danger {
        background: rgba(198, 40, 40, 0.15);
        color: #ef5350;
        border: 1px solid rgba(198, 40, 40, 0.4);
        padding: 8px 14px;
        border-radius: 4px;
        cursor: pointer;
    }
    .danger:disabled { opacity: 0.4; cursor: not-allowed; }
    .hint { font-size: 0.8em; color: var(--text-secondary); margin: 8px 0 0; }
    .revoke-msg { margin: 8px 0 0; font-size: 0.85em; color: var(--text-primary); }

    .action-group { margin-bottom: 14px; }
    .action-group:last-child { margin-bottom: 0; }
    .action-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .verify-pill {
        font-size: 0.75em;
        padding: 3px 9px;
        border-radius: 999px;
        border: 1px solid var(--border);
        color: var(--text-secondary);
        white-space: nowrap;
    }
    .verify-pill.ok { background: rgba(46, 125, 50, 0.18); color: #4caf50; border-color: rgba(46, 125, 50, 0.4); }
    .verify-pill.failed { background: rgba(198, 40, 40, 0.18); color: #ef5350; border-color: rgba(198, 40, 40, 0.4); }
    .verify-pill.neutral { background: transparent; }
    .action-msg.failed { color: #ef5350; }
    .action-ghost {
        background: transparent;
        color: var(--text);
        border: 1px solid var(--border);
        padding: 8px 14px;
        border-radius: 4px;
        cursor: pointer;
        font: inherit;
        font-size: 0.9rem;
    }
    .action-ghost:hover:not(:disabled) {
        background: var(--bg-elevated);
        border-color: var(--accent);
    }
    .action-ghost:disabled { opacity: 0.4; cursor: not-allowed; }
    .action-msg { margin: 8px 0 0; font-size: 0.85em; color: var(--text); }
</style>

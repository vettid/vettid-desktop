<script lang="ts">
    import { invoke } from '@tauri-apps/api/core';
    import { listen, type UnlistenFn } from '@tauri-apps/api/event';
    import { onMount } from 'svelte';
    import type { Connection, VaultOpResponse, PublishedCatalogItem, CallHistoryEntry } from '../../types';
    import { clearSelectedConnection } from '../../stores/navigation';
    import { peerName } from '../../connectionName';
    import {
        requestAccess,
        setPresenceOverride,
        listMyRequests,
        getSharePolicy,
        setSharePolicy,
        type ItemKind,
        type OutgoingRequestSummary,
        type SharePolicyItem,
    } from '../../grants';

    /**
     * One togglable row in the per-peer auto-allow editor.
     * `key` is the canonical share-policy item key (`<kind>:<ref>`);
     * `allowed` and the constraint fields mirror the vault's
     * SharePolicyItem so a flip can be persisted without lookups.
     */
    interface AutoAllowRow {
        key: string;
        kind: ItemKind;
        ref: string;
        display_name: string;
        category: string;
        alias?: string;
        allowed: boolean;
        tier: 'required' | 'optional' | 'on_demand' | 'consent';
        retention: 'session' | 'time_limited' | 'until_revoked';
        rate_limit_per_hour: number;
        expires_at: number;
    }

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

    // Per-catalog-item request tracking (request_id keyed by
    // "data:<ref>" or "secret:<ref>"). Used to render Pending / Granted
    // / Denied state on a catalog row after the user taps Request.
    type RequestRowState = 'available' | 'pending' | 'approved' | 'denied';
    let catalogRequestState = $state<Record<string, { status: RequestRowState; requestId?: string; grantId?: string }>>({});
    let requestingKey = $state<string | null>(null);
    let presenceBusy = $state(false);
    let presenceMsg = $state('');

    function catalogKey(kind: ItemKind, ref: string): string {
        return `${kind}:${ref}`;
    }

    // Resync local `detail` when the parent swaps to a different connection
    // (and trigger a fresh fetch). Without this the warning fires because
    // `$state` would otherwise only capture the prop's initial value.
    $effect(() => {
        detail = connection;
        refreshDetail();
        refreshVerifyState();
        void refreshOutgoingRequestState();
    });

    /**
     * Hydrate catalog request state from `grant.list-my-requests` so
     * rows show the right "Pending / Approved / Denied" pill on
     * re-entry. Filters to this connection only.
     */
    async function refreshOutgoingRequestState() {
        try {
            const reqs = await listMyRequests(connection.connection_id);
            const next: typeof catalogRequestState = {};
            for (const r of reqs) {
                const key = catalogKey(r.item_kind, r.item_ref);
                const status: RequestRowState =
                    r.status === 'pending' ? 'pending'
                    : r.status === 'approved' ? 'approved'
                    : 'denied';
                next[key] = { status, requestId: r.request_id, grantId: r.grant_id };
            }
            catalogRequestState = next;
        } catch (e) {
            console.warn('refreshOutgoingRequestState failed', e);
        }
    }

    async function requestCatalogItem(kind: ItemKind, item: PublishedCatalogItem) {
        const ref = item.name;
        const label = item.display_name ?? item.name;
        const key = catalogKey(kind, ref);
        requestingKey = key;
        try {
            const res = await requestAccess({
                connectionId: connection.connection_id,
                itemKind: kind,
                itemRef: ref,
                itemLabel: label,
                mode: 'one-shot',
                reason: '',
            });
            catalogRequestState = {
                ...catalogRequestState,
                [key]: { status: 'pending', requestId: res.request_id },
            };
        } catch (e) {
            catalogRequestState = {
                ...catalogRequestState,
                [key]: { status: 'available' },
            };
            // Surface in the page-level error spot.
            error = `Request failed: ${e}`;
        }
        requestingKey = null;
    }

    // Auto-allow (share-policy) editor. Collapsed by default — opening
    // it triggers the catalog enumeration so users who never touch it
    // don't pay personal-data.get + credential.secret.list overhead.
    let autoAllowOpen = $state(false);
    let autoAllowRows = $state<AutoAllowRow[]>([]);
    let autoAllowLoading = $state(false);
    let autoAllowError = $state('');
    let autoAllowBusyKey = $state<string | null>(null);

    function humanizeNamespace(ns: string): string {
        // contact.phone.mobile::Wife → "Mobile · Wife"
        const [base, alias] = ns.split('::');
        const parts = base.split('.');
        const leaf = parts[parts.length - 1] ?? base;
        const pretty = leaf
            .replace(/[_-]/g, ' ')
            .replace(/\b\w/g, (c) => c.toUpperCase());
        return alias ? `${pretty} · ${alias}` : pretty;
    }

    async function loadAutoAllow() {
        if (autoAllowLoading) return;
        autoAllowLoading = true;
        autoAllowError = '';
        try {
            const [pdResp, secResp, policy] = await Promise.all([
                invoke('list_personal_data') as Promise<VaultOpResponse>,
                invoke('list_secrets_catalog') as Promise<VaultOpResponse>,
                getSharePolicy(connection.connection_id),
            ]);

            // Seed rows from own catalog — every personal-data field
            // and every minor secret becomes a togglable row, defaulted
            // to "not allowed".
            const merged = new Map<string, AutoAllowRow>();

            // Personal-data fields.
            if (pdResp.success && pdResp.data) {
                const data = pdResp.data as { fields?: Record<string, { alias?: string; value?: string; category?: string }> };
                for (const [ns, field] of Object.entries(data.fields ?? {})) {
                    if (ns.startsWith('_system_')) continue;
                    merged.set(`data:${ns}`, {
                        key: `data:${ns}`,
                        kind: 'data',
                        ref: ns,
                        display_name: humanizeNamespace(ns),
                        category: field?.category ?? 'Personal data',
                        alias: field?.alias ?? undefined,
                        allowed: false,
                        tier: 'on_demand',
                        retention: 'until_revoked',
                        rate_limit_per_hour: 0,
                        expires_at: 0,
                    });
                }
            }

            // Minor secrets (catalog-only; values stay sealed).
            if (secResp.success && secResp.data) {
                const data = secResp.data as { secrets?: Array<{ id?: string; name?: string; category?: string; alias?: string }> };
                for (const s of data.secrets ?? []) {
                    if (!s.name) continue;
                    merged.set(`secret:${s.name}`, {
                        key: `secret:${s.name}`,
                        kind: 'secret',
                        ref: s.name,
                        display_name: s.name,
                        category: s.category ?? 'Secret',
                        alias: s.alias,
                        allowed: false,
                        tier: 'on_demand',
                        retention: 'until_revoked',
                        rate_limit_per_hour: 0,
                        expires_at: 0,
                    });
                }
            }

            // Overlay stored policy — anything already configured wins.
            for (const [key, item] of Object.entries(policy.items ?? {})) {
                const existing = merged.get(key);
                if (existing) {
                    existing.allowed = item.allowed ?? false;
                    existing.tier = (item.tier as AutoAllowRow['tier']) ?? existing.tier;
                    existing.retention = (item.retention as AutoAllowRow['retention']) ?? existing.retention;
                    existing.rate_limit_per_hour = item.rate_limit_per_hour ?? 0;
                    existing.expires_at = item.expires_at ?? 0;
                } else {
                    // Stored row for an item not in current catalog —
                    // surface it so the user can revoke it; the catalog
                    // entry might have been deleted.
                    const [kind, ref] = key.split(':', 2);
                    merged.set(key, {
                        key,
                        kind: (kind as ItemKind) ?? 'data',
                        ref: ref ?? key,
                        display_name: ref ?? key,
                        category: '(removed from catalog)',
                        allowed: item.allowed ?? false,
                        tier: (item.tier as AutoAllowRow['tier']) ?? 'on_demand',
                        retention: (item.retention as AutoAllowRow['retention']) ?? 'until_revoked',
                        rate_limit_per_hour: item.rate_limit_per_hour ?? 0,
                        expires_at: item.expires_at ?? 0,
                    });
                }
            }

            autoAllowRows = Array.from(merged.values()).sort((a, b) => {
                const cat = a.category.localeCompare(b.category);
                if (cat !== 0) return cat;
                return a.display_name.localeCompare(b.display_name);
            });
        } catch (e) {
            autoAllowError = String(e);
        }
        autoAllowLoading = false;
    }

    async function toggleAutoAllow(row: AutoAllowRow) {
        autoAllowBusyKey = row.key;
        const next = !row.allowed;
        try {
            const item: SharePolicyItem = {
                allowed: next,
                tier: row.tier,
                retention: row.retention,
            };
            if (row.rate_limit_per_hour > 0) item.rate_limit_per_hour = row.rate_limit_per_hour;
            if (row.expires_at > 0) item.expires_at = row.expires_at;
            await setSharePolicy(connection.connection_id, { [row.key]: item });
            // Apply optimistically — vault upsert is single-row.
            autoAllowRows = autoAllowRows.map((r) =>
                r.key === row.key ? { ...r, allowed: next } : r,
            );
        } catch (e) {
            autoAllowError = String(e);
        }
        autoAllowBusyKey = null;
    }

    function openAutoAllow() {
        autoAllowOpen = true;
        if (autoAllowRows.length === 0 && !autoAllowLoading) {
            void loadAutoAllow();
        }
    }

    async function setPresence(value: boolean | null) {
        presenceBusy = true;
        presenceMsg = '';
        try {
            await setPresenceOverride(connection.connection_id, value);
            presenceMsg = value === null
                ? 'Cleared — follows your default.'
                : value
                    ? 'Always visible to this peer.'
                    : 'Hidden from this peer.';
        } catch (e) {
            presenceMsg = `Failed: ${e}`;
        }
        presenceBusy = false;
    }

    // Per-connection call history. Filter the global list on this
    // connection_id — the vault returns the full list and we narrow
    // here so we share the cache when the user navigates between
    // connections in the same session.
    let callHistory = $state<CallHistoryEntry[]>([]);
    let callHistoryLoading = $state(false);

    async function refreshCallHistory() {
        callHistoryLoading = true;
        try {
            const resp: VaultOpResponse = await invoke('list_call_history');
            if (resp.success && resp.data) {
                const data = resp.data as { calls?: CallHistoryEntry[]; entries?: CallHistoryEntry[] };
                const all = data.calls ?? data.entries ?? [];
                callHistory = all
                    .filter((c) => c.connection_id === connection.connection_id)
                    .sort((a, b) => (b.started_at ?? 0) - (a.started_at ?? 0))
                    .slice(0, 20);
            }
        } catch (e) {
            console.warn('list_call_history failed', e);
        }
        callHistoryLoading = false;
    }

    $effect(() => {
        const _ = connection.connection_id;
        void refreshCallHistory();
    });

    function fmtCallTime(unix?: number): string {
        if (!unix) return '';
        const date = new Date(unix * 1000);
        const today = new Date();
        if (date.toDateString() === today.toDateString()) {
            return date.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
        }
        return date.toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
    }

    function fmtDuration(secs?: number): string {
        if (!secs || secs < 1) return '';
        const m = Math.floor(secs / 60);
        const s = secs % 60;
        if (m === 0) return `${s}s`;
        return `${m}m ${s}s`;
    }

    function callIcon(c: CallHistoryEntry): string {
        if (c.status === 'missed') return '📵';
        if (c.status === 'rejected') return '✗';
        if (c.direction === 'incoming') return '⬇';
        return '⬆';
    }

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

            <!-- Peer catalog — request access to items they've published. -->
            {#if (detail.peer_profile?.data_catalog?.length ?? 0) > 0 || (detail.peer_profile?.secret_catalog?.length ?? 0) > 0}
                <section class="card">
                    <h4>What they share</h4>
                    <p class="catalog-hint">Items {peerName(detail)} has published. Tap Request to ask for access.</p>
                    <ul class="catalog">
                        {#each (detail.peer_profile?.data_catalog ?? []) as item (item.name)}
                            {@const key = catalogKey('data', item.name)}
                            {@const state = catalogRequestState[key]?.status ?? 'available'}
                            <li class="catalog-row">
                                <span class="cat-kind">📇</span>
                                <div class="cat-body">
                                    <div class="cat-name">{item.display_name ?? item.name}</div>
                                    <div class="cat-meta">
                                        {item.category ?? 'Data'}
                                        {#if item.alias} · {item.alias}{/if}
                                    </div>
                                </div>
                                {#if state === 'pending'}
                                    <span class="cat-pill pending">Pending</span>
                                {:else if state === 'approved'}
                                    <span class="cat-pill approved">Approved</span>
                                {:else if state === 'denied'}
                                    <span class="cat-pill denied">Denied</span>
                                {:else}
                                    <button
                                        class="cat-btn"
                                        onclick={() => requestCatalogItem('data', item)}
                                        disabled={requestingKey === key}
                                    >{requestingKey === key ? '…' : 'Request'}</button>
                                {/if}
                            </li>
                        {/each}
                        {#each (detail.peer_profile?.secret_catalog ?? []) as item (item.name)}
                            {@const key = catalogKey('secret', item.name)}
                            {@const state = catalogRequestState[key]?.status ?? 'available'}
                            <li class="catalog-row">
                                <span class="cat-kind">🔑</span>
                                <div class="cat-body">
                                    <div class="cat-name">{item.display_name ?? item.name}</div>
                                    <div class="cat-meta">
                                        {item.category ?? 'Secret'}
                                        {#if item.alias} · {item.alias}{/if}
                                    </div>
                                </div>
                                {#if state === 'pending'}
                                    <span class="cat-pill pending">Pending</span>
                                {:else if state === 'approved'}
                                    <span class="cat-pill approved">Approved</span>
                                {:else if state === 'denied'}
                                    <span class="cat-pill denied">Denied</span>
                                {:else}
                                    <button
                                        class="cat-btn"
                                        onclick={() => requestCatalogItem('secret', item)}
                                        disabled={requestingKey === key}
                                    >{requestingKey === key ? '…' : 'Request'}</button>
                                {/if}
                            </li>
                        {/each}
                    </ul>
                </section>
            {/if}

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

            <!-- Auto-allow editor — per-peer share policy. Collapsed
                 by default so users who only use the approval flow
                 don't pay catalog-enumeration overhead. -->
            <section class="card">
                <button
                    type="button"
                    class="aa-toggle"
                    onclick={autoAllowOpen ? () => (autoAllowOpen = false) : openAutoAllow}
                    aria-expanded={autoAllowOpen}
                >
                    <span>Auto-allow for {peerName(detail)}</span>
                    <span class="aa-chev" class:open={autoAllowOpen}>▾</span>
                </button>
                {#if autoAllowOpen}
                    <p class="hint">
                        Items you toggle on here are pre-authorized — this
                        peer can fetch them without sending you a request.
                        Toggle off to revoke or to gate behind an
                        approval prompt next time.
                    </p>
                    {#if autoAllowLoading}
                        <div class="aa-status">Loading your catalog…</div>
                    {:else if autoAllowError}
                        <div class="aa-status error">{autoAllowError}</div>
                    {:else if autoAllowRows.length === 0}
                        <div class="aa-status">No catalog items yet. Add personal data or secrets in the Vault tab.</div>
                    {:else}
                        <ul class="aa-list">
                            {#each autoAllowRows as row (row.key)}
                                <li class="aa-row">
                                    <span class="aa-kind">{row.kind === 'data' ? '📇' : '🔑'}</span>
                                    <div class="aa-body">
                                        <div class="aa-name">{row.display_name}</div>
                                        <div class="aa-meta">
                                            {row.category}
                                            {#if row.alias} · {row.alias}{/if}
                                        </div>
                                    </div>
                                    <label class="aa-switch" title={row.allowed ? 'Auto-allowed' : 'Requires approval'}>
                                        <input
                                            type="checkbox"
                                            checked={row.allowed}
                                            disabled={autoAllowBusyKey === row.key}
                                            onchange={() => toggleAutoAllow(row)}
                                        />
                                        <span class="aa-slider" class:on={row.allowed}></span>
                                    </label>
                                </li>
                            {/each}
                        </ul>
                    {/if}
                {/if}
            </section>

            <!-- Call history (per-connection) -->
            {#if callHistory.length > 0 || callHistoryLoading}
                <section class="card">
                    <h4>Recent calls</h4>
                    {#if callHistoryLoading && callHistory.length === 0}
                        <div class="ch-status">Loading…</div>
                    {:else if callHistory.length === 0}
                        <div class="ch-status">No calls yet.</div>
                    {:else}
                        <ul class="ch-list">
                            {#each callHistory as call (call.call_id)}
                                <li class="ch-row">
                                    <span class="ch-icon" class:missed={call.status === 'missed'}>{callIcon(call)}</span>
                                    <div class="ch-body">
                                        <div class="ch-head-line">
                                            <span class="ch-type">{call.call_type === 'video' ? 'Video' : 'Voice'}</span>
                                            {#if call.status === 'missed'}<span class="ch-status-tag missed">missed</span>
                                            {:else if call.status === 'rejected'}<span class="ch-status-tag">declined</span>
                                            {/if}
                                        </div>
                                        <div class="ch-meta">
                                            {call.direction === 'incoming' ? 'Incoming' : 'Outgoing'}
                                            {#if call.duration_secs}· {fmtDuration(call.duration_secs)}{/if}
                                        </div>
                                    </div>
                                    <div class="ch-time">{fmtCallTime(call.started_at)}</div>
                                </li>
                            {/each}
                        </ul>
                    {/if}
                </section>
            {/if}

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
                    <div class="presence-row">
                        <span class="presence-label">Presence to this peer:</span>
                        <div class="presence-buttons">
                            <button class="presence-btn" onclick={() => setPresence(null)} disabled={presenceBusy}>Default</button>
                            <button class="presence-btn" onclick={() => setPresence(true)} disabled={presenceBusy}>Always show</button>
                            <button class="presence-btn" onclick={() => setPresence(false)} disabled={presenceBusy}>Always hide</button>
                        </div>
                    </div>
                    <p class="hint">
                        Overrides your default visibility for this connection only.
                        "Default" follows your global presence setting.
                    </p>
                    {#if presenceMsg}<p class="action-msg">{presenceMsg}</p>{/if}
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

    .catalog-hint {
        font-size: 0.8em;
        color: var(--text-secondary);
        margin: 0 0 10px;
    }
    .catalog {
        list-style: none;
        padding: 0;
        margin: 0;
        display: flex;
        flex-direction: column;
        gap: 6px;
    }
    .catalog-row {
        display: flex;
        align-items: center;
        gap: 10px;
        background: var(--bg-elevated, #1c1c1c);
        border: 1px solid var(--border);
        border-radius: 6px;
        padding: 8px 12px;
    }
    .cat-kind { font-size: 1.1em; flex-shrink: 0; }
    .cat-body { flex: 1; min-width: 0; }
    .cat-name { font-size: 0.92em; }
    .cat-meta { font-size: 0.72em; color: var(--text-secondary); margin-top: 1px; }
    .cat-btn {
        background: transparent;
        border: 1px solid var(--accent);
        color: var(--accent);
        padding: 4px 12px;
        border-radius: 6px;
        cursor: pointer;
        font: inherit;
        font-size: 0.8em;
    }
    .cat-btn:hover:not(:disabled) { background: rgba(255,193,37,0.12); }
    .cat-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .cat-pill {
        font-size: 0.72em;
        padding: 3px 9px;
        border-radius: 999px;
        background: rgba(255,152,0,0.18);
        color: #ff9800;
        text-transform: capitalize;
    }
    .cat-pill.approved { background: rgba(46,125,50,0.18); color: #4caf50; }
    .cat-pill.denied { background: rgba(198,40,40,0.18); color: #ef5350; }

    .presence-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
    .presence-label { font-size: 0.85em; color: var(--text-secondary); }
    .presence-buttons { display: flex; gap: 6px; }
    .presence-btn {
        background: transparent;
        color: inherit;
        border: 1px solid var(--border);
        padding: 5px 10px;
        border-radius: 4px;
        cursor: pointer;
        font: inherit;
        font-size: 0.8em;
    }
    .presence-btn:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
    .presence-btn:disabled { opacity: 0.5; cursor: not-allowed; }

    .ch-status {
        font-size: 0.85em;
        color: var(--text-secondary);
        padding: 6px 0;
    }
    .ch-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 4px; }
    .ch-row {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 6px 0;
        border-bottom: 1px solid rgba(255,255,255,0.04);
    }
    .ch-row:last-child { border-bottom: none; }
    .ch-icon { font-size: 1.1em; color: var(--text-secondary); flex-shrink: 0; width: 22px; text-align: center; }
    .ch-icon.missed { color: #ef5350; }
    .ch-body { flex: 1; min-width: 0; }
    .ch-head-line { display: flex; gap: 8px; align-items: baseline; }
    .ch-type { font-size: 0.92em; }
    .ch-status-tag {
        font-size: 0.68em;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        color: var(--text-secondary);
        border: 1px solid var(--border);
        border-radius: 3px;
        padding: 1px 5px;
    }
    .ch-status-tag.missed { color: #ef5350; border-color: rgba(244,67,54,0.45); }
    .ch-meta { font-size: 0.75em; color: var(--text-secondary); margin-top: 1px; }
    .ch-time { font-size: 0.78em; color: var(--text-secondary); flex-shrink: 0; }

    /* Auto-allow editor */
    .aa-toggle {
        display: flex;
        width: 100%;
        align-items: center;
        justify-content: space-between;
        background: transparent;
        border: none;
        color: inherit;
        padding: 0;
        margin: 0 0 4px;
        cursor: pointer;
        font: inherit;
        font-size: 0.85em;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--text-secondary);
    }
    .aa-toggle:hover { color: var(--text); }
    .aa-chev { transition: transform 0.15s; }
    .aa-chev.open { transform: rotate(180deg); }
    .aa-status { padding: 12px 0; color: var(--text-secondary); font-size: 0.85em; }
    .aa-status.error { color: var(--danger); }
    .aa-list { list-style: none; padding: 0; margin: 8px 0 0; display: flex; flex-direction: column; gap: 4px; max-height: 320px; overflow-y: auto; }
    .aa-row {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 6px 8px;
        border-bottom: 1px solid rgba(255,255,255,0.04);
    }
    .aa-row:last-child { border-bottom: none; }
    .aa-kind { font-size: 1.05em; flex-shrink: 0; width: 22px; text-align: center; }
    .aa-body { flex: 1; min-width: 0; }
    .aa-name { font-size: 0.9em; }
    .aa-meta { font-size: 0.72em; color: var(--text-secondary); margin-top: 1px; }
    .aa-switch {
        position: relative;
        width: 38px;
        height: 22px;
        flex-shrink: 0;
        cursor: pointer;
    }
    .aa-switch input { opacity: 0; width: 0; height: 0; }
    .aa-slider {
        position: absolute;
        inset: 0;
        background: rgba(255,255,255,0.12);
        border-radius: 999px;
        transition: background 0.18s;
    }
    .aa-slider::before {
        content: '';
        position: absolute;
        top: 3px;
        left: 3px;
        width: 16px;
        height: 16px;
        background: var(--text-secondary);
        border-radius: 50%;
        transition: transform 0.18s, background 0.18s;
    }
    .aa-slider.on { background: rgba(255,193,37,0.35); }
    .aa-slider.on::before { transform: translateX(16px); background: var(--accent); }
    .aa-switch input:disabled + .aa-slider { opacity: 0.5; cursor: not-allowed; }
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

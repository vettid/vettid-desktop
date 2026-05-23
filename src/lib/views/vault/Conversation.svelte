<script lang="ts">
    import { invoke } from '@tauri-apps/api/core';
    import { listen } from '@tauri-apps/api/event';
    import { open } from '@tauri-apps/plugin-shell';
    import type { Connection, Message, VaultOpResponse } from '../../types';
    import { clearSelectedConnection } from '../../stores/navigation';
    import { markConversationRead } from '../../stores/vault';
    import { placeCall, type CallType } from '../../stores/calls';
    import { peerName } from '../../connectionName';
    import SendBtcSheet from './wallet/SendBtcSheet.svelte';
    import RequestPaymentSheet from './wallet/RequestPaymentSheet.svelte';

    interface Props {
        connection: Connection;
        onShowProfile: () => void;
        /** Hide the local identity header when embedded in
         *  ConnectionWorkspace, which owns the workspace header. */
        compact?: boolean;
    }

    let { connection, onShowProfile, compact = false }: Props = $props();

    let messages = $state<Message[]>([]);
    let composeText = $state('');
    let loading = $state(true);
    let sending = $state(false);
    let error = $state('');
    let scrollEl: HTMLDivElement | undefined = $state();
    // Scroll-to-bottom FAB only shows when the user has scrolled
    // up enough that they're no longer near the latest message.
    let nearBottom = $state(true);
    // Pagination: vault returns the most-recent `limit` messages; when
    // the user scrolls to within `LOAD_OLDER_THRESHOLD_PX` of the top
    // we fetch the page before that (`before=<oldest message_id>`).
    let loadingOlder = $state(false);
    let hasMoreOlder = $state(true);
    const PAGE_SIZE = 50;
    const LOAD_OLDER_THRESHOLD_PX = 120;

    // Per-incoming-payment-request action state. Keyed by request_id
    // (or message_id as fallback) so each bubble tracks its own pay /
    // decline state independently.
    let paymentActionState = $state<Record<string, { busy: boolean; error?: string }>>({});
    // Which payment_request_id (or message_id) is the user currently
    // typing a decline reason for? Drives the inline decline composer.
    let decliningFor = $state<string | null>(null);
    let declineReason = $state('');

    // Compose menu (➕) — Request payment lives here. Send-via-attach
    // can come later (D.6 image/file).
    let composeMenuOpen = $state(false);

    // Sheets mounted by the conversation. Loaded lazily on demand so
    // tabs that never touch payments don't pay the wallet.list cost.
    interface WalletItem {
        wallet_id: string;
        label: string;
        address: string;
        network: string;
        cached_balance_sats: number;
    }
    let activeSheet = $state<'send' | 'request' | null>(null);
    let walletsForSheet = $state<WalletItem[]>([]);
    let walletsError = $state('');
    let payPrefill = $state<{ toAddress: string; amountSats: number } | null>(null);

    interface PaymentPayload {
        amount_sats?: number;
        memo?: string;
        address?: string;
        txid?: string;
        label?: string;
        request_id?: string;
        reason?: string;
    }

    function parsePayment(content: string): PaymentPayload | null {
        try {
            const j = JSON.parse(content);
            return typeof j === 'object' && j !== null ? (j as PaymentPayload) : null;
        } catch {
            return null;
        }
    }

    function paymentKey(msg: Message, payload: PaymentPayload | null): string {
        return payload?.request_id || msg.id;
    }

    function formatBtc(sats?: number): string {
        if (typeof sats !== 'number' || !isFinite(sats)) return '';
        const btc = (sats / 100_000_000).toFixed(8);
        return btc.replace(/\.?0+$/, '') + ' BTC';
    }

    async function loadMessages() {
        loading = true;
        error = '';
        hasMoreOlder = true;
        try {
            const resp: VaultOpResponse = await invoke('get_conversation', {
                peerConnectionId: connection.connection_id,
                limit: PAGE_SIZE,
            });
            if (resp.success && resp.data) {
                const data = resp.data as { messages?: Message[] };
                messages = (data.messages ?? []).sort(
                    (a, b) => Date.parse(a.sent_at) - Date.parse(b.sent_at),
                );
                // If the vault returned fewer than the page size, we
                // already have every message — disable further fetches.
                if (messages.length < PAGE_SIZE) hasMoreOlder = false;
            } else if (resp.error) {
                error = resp.error;
            }
        } catch (e) {
            error = String(e);
        }
        loading = false;
        scrollToBottom();
        markConversationRead(connection.connection_id);
        sendReadReceiptsForUnread();
    }

    /**
     * Page older messages into the top of the list. Anchored on the
     * scroll height before the prepend so the user's viewport stays
     * locked to the message they were reading instead of jumping.
     */
    async function loadOlder() {
        if (loadingOlder || !hasMoreOlder || messages.length === 0) return;
        const oldest = messages[0];
        if (!oldest) return;
        loadingOlder = true;
        const heightBefore = scrollEl?.scrollHeight ?? 0;
        const topBefore = scrollEl?.scrollTop ?? 0;
        try {
            const resp: VaultOpResponse = await invoke('get_conversation', {
                peerConnectionId: connection.connection_id,
                limit: PAGE_SIZE,
                before: oldest.id,
            });
            if (resp.success && resp.data) {
                const data = resp.data as { messages?: Message[] };
                const older = (data.messages ?? []).sort(
                    (a, b) => Date.parse(a.sent_at) - Date.parse(b.sent_at),
                );
                // De-dupe by id in case the vault's `before` semantics
                // are inclusive on either side.
                const have = new Set(messages.map((m) => m.id));
                const fresh = older.filter((m) => !have.has(m.id));
                if (fresh.length === 0) {
                    hasMoreOlder = false;
                } else {
                    messages = [...fresh, ...messages];
                    if (fresh.length < PAGE_SIZE) hasMoreOlder = false;
                    // Anchor the viewport to the same message after prepend.
                    queueMicrotask(() => {
                        if (!scrollEl) return;
                        const newHeight = scrollEl.scrollHeight;
                        scrollEl.scrollTop = topBefore + (newHeight - heightBefore);
                    });
                }
            }
        } catch (e) {
            // Pagination failures are non-fatal — keep what we have.
            console.warn('loadOlder failed', e);
        }
        loadingOlder = false;
    }

    /**
     * Fire `message.read-receipt` for every received message we haven't yet
     * marked read. The vault de-dupes by (connection_id, message_id), so it's
     * safe to be permissive — better than missing one and leaving the peer
     * staring at a single check forever.
     */
    async function sendReadReceiptsForUnread() {
        const unread = messages.filter((m) =>
            !isSent(m) && m.status !== 'read',
        );
        for (const msg of unread) {
            try {
                await invoke('mark_message_read', {
                    connectionId: connection.connection_id,
                    messageId: msg.id,
                });
                msg.status = 'read';
            } catch (e) {
                console.warn('Failed to send read receipt:', e);
            }
        }
        // Trigger reactivity since we mutated objects in place.
        messages = [...messages];
    }

    async function sendMessage() {
        const text = composeText.trim();
        if (!text || sending) return;
        sending = true;
        try {
            const resp: VaultOpResponse = await invoke('send_message', {
                peerConnectionId: connection.connection_id,
                content: text,
            });
            if (resp.success) {
                composeText = '';
                await loadMessages();
            } else {
                error = resp.error ?? 'Send failed';
            }
        } catch (e) {
            error = String(e);
        }
        sending = false;
    }

    function handleKeydown(e: KeyboardEvent) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    }

    function scrollToBottom() {
        // Defer to next tick so the DOM has rendered the new content.
        queueMicrotask(() => {
            if (scrollEl) scrollEl.scrollTop = scrollEl.scrollHeight;
        });
    }

    function onMessagesScroll() {
        if (!scrollEl) return;
        nearBottom = scrollEl.scrollTop + scrollEl.clientHeight >= scrollEl.scrollHeight - 100;
        if (scrollEl.scrollTop <= LOAD_OLDER_THRESHOLD_PX && hasMoreOlder && !loadingOlder) {
            void loadOlder();
        }
    }

    /**
     * Pay an incoming payment request. Loads wallets (lazy) and opens
     * SendBtcSheet prefilled with the address + amount. The user
     * confirms in the sheet — we never silently send.
     */
    async function payPaymentRequest(msg: Message, payload: PaymentPayload | null) {
        if (!payload?.address || !payload?.amount_sats) {
            error = 'Payment request is missing address or amount.';
            return;
        }
        const key = paymentKey(msg, payload);
        paymentActionState = { ...paymentActionState, [key]: { busy: true } };
        try {
            await ensureWalletsLoaded();
            if (walletsForSheet.length === 0) {
                paymentActionState = {
                    ...paymentActionState,
                    [key]: { busy: false, error: walletsError || 'No wallets available' },
                };
                return;
            }
            payPrefill = { toAddress: payload.address, amountSats: payload.amount_sats };
            activeSheet = 'send';
            paymentActionState = { ...paymentActionState, [key]: { busy: false } };
        } catch (e) {
            paymentActionState = {
                ...paymentActionState,
                [key]: { busy: false, error: String(e) },
            };
        }
    }

    /**
     * Decline an incoming payment request by sending a structured
     * `btc_payment_decline` message with `{request_id, reason}`. The
     * recipient renders it as a dedicated bubble.
     */
    async function declinePaymentRequest(msg: Message, payload: PaymentPayload | null) {
        const key = paymentKey(msg, payload);
        const reason = declineReason.trim() || 'Declined';
        paymentActionState = { ...paymentActionState, [key]: { busy: true } };
        try {
            const body = JSON.stringify({
                request_id: payload?.request_id ?? msg.id,
                reason,
            });
            const resp: VaultOpResponse = await invoke('send_message', {
                peerConnectionId: connection.connection_id,
                content: body,
                contentType: 'btc_payment_decline',
            });
            if (resp.success) {
                decliningFor = null;
                declineReason = '';
                paymentActionState = { ...paymentActionState, [key]: { busy: false } };
                await loadMessages();
            } else {
                paymentActionState = {
                    ...paymentActionState,
                    [key]: { busy: false, error: resp.error ?? 'Decline failed' },
                };
            }
        } catch (e) {
            paymentActionState = {
                ...paymentActionState,
                [key]: { busy: false, error: String(e) },
            };
        }
    }

    function openDecline(msg: Message, payload: PaymentPayload | null) {
        decliningFor = paymentKey(msg, payload);
        declineReason = '';
    }

    function cancelDecline() {
        decliningFor = null;
        declineReason = '';
    }

    async function ensureWalletsLoaded() {
        if (walletsForSheet.length > 0) return;
        walletsError = '';
        try {
            const resp: VaultOpResponse = await invoke('list_wallets');
            if (resp.success && resp.data) {
                const data = resp.data as { wallets?: (WalletItem & { is_archived?: boolean })[] };
                walletsForSheet = (data.wallets ?? []).filter((w) => !w.is_archived);
            } else {
                walletsError = resp.error ?? 'Failed to load wallets';
            }
        } catch (e) {
            walletsError = String(e);
        }
    }

    async function openRequestPaymentSheet() {
        composeMenuOpen = false;
        await ensureWalletsLoaded();
        if (walletsForSheet.length === 0) {
            error = walletsError || 'You have no wallets. Create one in the Wallets tab first.';
            return;
        }
        activeSheet = 'request';
    }

    function closeSheet() {
        activeSheet = null;
        payPrefill = null;
    }

    function onSheetSent() {
        loadMessages();
    }

    /**
     * Split a message into text/link tokens for click-through. We only want to
     * recognize the conservative `https?://` and `www.` shapes used by the
     * Android app — wider matchers tend to false-positive on punctuation.
     */
    const URL_PATTERN = /(https?:\/\/[^\s]+|www\.[^\s]+)/g;
    interface Token { text: string; isLink: boolean; href?: string; }

    function tokenize(text: string): Token[] {
        const tokens: Token[] = [];
        let lastIndex = 0;
        for (const match of text.matchAll(URL_PATTERN)) {
            const start = match.index ?? 0;
            if (start > lastIndex) {
                tokens.push({ text: text.slice(lastIndex, start), isLink: false });
            }
            const url = match[0];
            const href = url.startsWith('http') ? url : `https://${url}`;
            tokens.push({ text: url, isLink: true, href });
            lastIndex = start + url.length;
        }
        if (lastIndex < text.length) {
            tokens.push({ text: text.slice(lastIndex), isLink: false });
        }
        return tokens;
    }

    async function openLink(href: string) {
        try {
            await open(href);
        } catch (e) {
            console.error('Failed to open link:', e);
        }
    }

    /**
     * Heuristic for sender → "is this me or the peer". The vault encodes the
     * sender as either the peer's connection_id (when we receive) or our own
     * device id / "me" (when we send). We treat anything that doesn't match
     * the peer connection id as outbound.
     */
    function isSent(msg: Message): boolean {
        return msg.sender_id !== connection.connection_id
            && msg.sender_id !== connection.peer_guid;
    }

    async function startCall(type: CallType) {
        // Calls need a peer identity — the system connection, device
        // pairings, and agents have no peer_guid and can't be called.
        if (!connection.peer_guid) {
            error = "This connection can't be called.";
            return;
        }
        try {
            await placeCall(connection.connection_id, connection.peer_guid, peerName(connection), type);
        } catch (e) {
            error = `Call failed: ${e}`;
        }
    }

    // Reload when the connection prop changes.
    $effect(() => {
        // Take a stable reference so the effect re-fires on connection change.
        const _ = connection.connection_id;
        loadMessages();
    });

    // Real-time message handler — only consume events for this conversation.
    $effect(() => {
        const unlisten = listen<{ subject: string; payload_b64: string }>(
            'vault:message-received',
            (event) => {
                const subject = event.payload?.subject ?? '';
                if (!subject.includes(connection.connection_id)) return;
                // Reload to pick up the new message rather than trying to
                // decrypt the payload here — the vault's `message.list` is
                // authoritative and avoids drift.
                loadMessages();
            },
        );
        return () => { unlisten.then((fn) => fn()); };
    });
</script>

<div class="conversation">
    {#if !compact}
        <header class="bar">
            <button class="back" onclick={clearSelectedConnection} aria-label="Back">←</button>
            <button class="header-name" onclick={onShowProfile}>
                <span class="name">{peerName(connection)}</span>
                <span class="profile-hint">view profile</span>
            </button>
            <button class="call-btn" onclick={() => startCall('audio')} aria-label="Voice call" title="Voice call">📞</button>
            <button class="call-btn" onclick={() => startCall('video')} aria-label="Video call" title="Video call">🎥</button>
            <span class="status-dot {connection.status}" aria-label={connection.status}></span>
        </header>
    {/if}

    {#if loading && messages.length === 0}
        <div class="status">Loading…</div>
    {:else if error}
        <div class="status error">{error}</div>
    {:else}
        <div class="messages-scroll" bind:this={scrollEl} onscroll={onMessagesScroll}>
            {#if loadingOlder}
                <div class="older-status">Loading older messages…</div>
            {:else if !hasMoreOlder && messages.length >= PAGE_SIZE}
                <div class="older-status muted">— Start of conversation —</div>
            {/if}
            {#each messages as msg (msg.id)}
                {@const sent = isSent(msg)}
                <div class="message" class:sent class:received={!sent}>
                    <div class="bubble">
                        {#if msg.content_type === 'payment_request'}
                            {@const p = parsePayment(msg.content)}
                            {@const key = paymentKey(msg, p)}
                            {@const action = paymentActionState[key]}
                            <div class="pay-head">{sent ? '📤 Payment request sent' : '📥 Payment request'}</div>
                            {#if p?.amount_sats !== undefined}
                                <div class="pay-amount">{formatBtc(p.amount_sats)}</div>
                            {/if}
                            {#if p?.memo}<div class="pay-memo">"{p.memo}"</div>{/if}
                            {#if p?.address}<div class="pay-addr mono">{p.address.slice(0, 18)}…</div>{/if}
                            {#if !sent}
                                {#if decliningFor === key}
                                    <div class="decline-row">
                                        <input
                                            type="text"
                                            placeholder="Reason (optional)"
                                            bind:value={declineReason}
                                            maxlength="140"
                                            class="decline-input"
                                        />
                                        <button
                                            class="pay-action danger"
                                            onclick={() => declinePaymentRequest(msg, p)}
                                            disabled={action?.busy}
                                        >{action?.busy ? '…' : 'Send decline'}</button>
                                        <button class="pay-action ghost" onclick={cancelDecline} disabled={action?.busy}>Cancel</button>
                                    </div>
                                {:else}
                                    <div class="pay-actions">
                                        <button
                                            class="pay-action primary"
                                            onclick={() => payPaymentRequest(msg, p)}
                                            disabled={action?.busy}
                                        >Pay</button>
                                        <button
                                            class="pay-action ghost"
                                            onclick={() => openDecline(msg, p)}
                                            disabled={action?.busy}
                                        >Decline</button>
                                    </div>
                                {/if}
                                {#if action?.error}
                                    <div class="pay-err">{action.error}</div>
                                {/if}
                            {/if}
                        {:else if msg.content_type === 'btc_payment_decline'}
                            {@const p = parsePayment(msg.content)}
                            <div class="pay-head">{sent ? '🚫 You declined a payment request' : '🚫 Payment request declined'}</div>
                            {#if p?.reason}<div class="pay-memo">"{p.reason}"</div>{/if}
                        {:else if msg.content_type === 'btc_payment_receipt'}
                            {@const p = parsePayment(msg.content)}
                            <div class="pay-head">{sent ? '✅ Payment sent' : '✅ Payment received'}</div>
                            {#if p?.amount_sats !== undefined}
                                <div class="pay-amount">{formatBtc(p.amount_sats)}</div>
                            {/if}
                            {#if p?.txid}<div class="pay-addr mono">tx: {p.txid.slice(0, 16)}…</div>{/if}
                        {:else if msg.content_type === 'btc_address'}
                            {@const p = parsePayment(msg.content)}
                            <div class="pay-head">📬 Shared wallet address</div>
                            {#if p?.label}<div class="pay-label">{p.label}</div>{/if}
                            {#if p?.address}<div class="pay-addr mono">{p.address}</div>{/if}
                        {:else}
                            {#each tokenize(msg.content) as tok}
                                {#if tok.isLink && tok.href}
                                    <button
                                        type="button"
                                        class="link-btn"
                                        onclick={() => openLink(tok.href!)}
                                    >{tok.text}</button>
                                {:else}<span>{tok.text}</span>{/if}
                            {/each}
                        {/if}
                    </div>
                    <div class="msg-meta">
                        <span class="time">{new Date(msg.sent_at).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}</span>
                        {#if sent}
                            <span class="receipt" class:read={msg.status === 'read'}>
                                {#if msg.status === 'read'}✓✓
                                {:else if msg.status === 'delivered'}✓✓
                                {:else if msg.status === 'sent'}✓
                                {:else if msg.status === 'sending'}…
                                {:else if msg.status === 'failed'}!{/if}
                            </span>
                        {/if}
                    </div>
                </div>
            {/each}
            {#if !nearBottom}
                <button
                    type="button"
                    class="scroll-fab"
                    onclick={scrollToBottom}
                    aria-label="Scroll to latest"
                    title="Scroll to latest"
                >↓</button>
            {/if}
        </div>

        <form class="compose" onsubmit={(e) => { e.preventDefault(); sendMessage(); }}>
            <div class="compose-menu-wrap">
                <button
                    type="button"
                    class="compose-attach"
                    aria-label="More actions"
                    title="More"
                    onclick={() => (composeMenuOpen = !composeMenuOpen)}
                >+</button>
                {#if composeMenuOpen}
                    <div class="compose-menu" role="menu">
                        <button
                            type="button"
                            class="compose-menu-item"
                            onclick={openRequestPaymentSheet}
                        >💸 Request payment</button>
                    </div>
                {/if}
            </div>
            <textarea
                bind:value={composeText}
                onkeydown={handleKeydown}
                placeholder="Message {peerName(connection)}…"
                rows="1"
            ></textarea>
            <button type="submit" disabled={sending || !composeText.trim()}>
                {sending ? '…' : 'Send'}
            </button>
        </form>
    {/if}
</div>

{#if activeSheet === 'send' && payPrefill}
    <SendBtcSheet
        wallets={walletsForSheet}
        prefillToAddress={payPrefill.toAddress}
        prefillAmountSats={payPrefill.amountSats}
        onClose={closeSheet}
        onSent={onSheetSent}
    />
{:else if activeSheet === 'request' && walletsForSheet[0]}
    <RequestPaymentSheet
        wallet={{
            wallet_id: walletsForSheet[0].wallet_id,
            label: walletsForSheet[0].label,
            network: walletsForSheet[0].network,
        }}
        prefillConnectionId={connection.connection_id}
        onClose={closeSheet}
        onSent={onSheetSent}
    />
{/if}

<style>
    .conversation { height: 100%; display: flex; flex-direction: column; }

    .bar {
        display: flex; align-items: center; gap: 12px;
        padding: 0 0 10px;
        border-bottom: 1px solid var(--border);
    }
    .back, .header-name {
        background: none;
        border: 1px solid var(--border);
        border-radius: 4px;
        padding: 4px 10px;
        cursor: pointer;
        color: inherit;
    }
    .header-name {
        flex: 1;
        text-align: left;
        display: flex;
        flex-direction: column;
        gap: 1px;
    }
    .name { font-weight: 500; }
    .profile-hint { font-size: 0.7em; color: var(--text-secondary); }

    .call-btn {
        background: none;
        border: 1px solid var(--border);
        border-radius: 4px;
        padding: 4px 10px;
        cursor: pointer;
        color: inherit;
        font-size: 1.05em;
    }
    .call-btn:hover { background: rgba(255,193,37,0.1); border-color: var(--accent, #ffc125); }

    .status-dot { width: 10px; height: 10px; border-radius: 50%; background: var(--text-secondary); }
    .status-dot.active { background: #4caf50; }
    .status-dot.pending { background: #ff9800; }
    .status-dot.revoked, .status-dot.expired { background: #f44336; }

    .status { padding: 24px; text-align: center; color: var(--text-secondary); }
    .status.error { color: var(--danger); }

    .messages-scroll {
        flex: 1;
        overflow-y: auto;
        padding: 16px 8px;
        display: flex;
        flex-direction: column;
        gap: 6px;
    }

    .message {
        display: flex;
        flex-direction: column;
        max-width: 75%;
    }
    .message.sent { align-self: flex-end; align-items: flex-end; }
    .message.received { align-self: flex-start; align-items: flex-start; }

    .bubble {
        padding: 8px 12px;
        border-radius: 14px;
        word-break: break-word;
        white-space: pre-wrap;
        line-height: 1.35;
    }
    /* Android color scheme: gold on black for sent, black on gold for received */
    .message.sent .bubble {
        background: #ffc125;
        color: #000;
        border-bottom-right-radius: 4px;
    }
    .message.received .bubble {
        background: #1c1c1c;
        color: #ffc125;
        border-bottom-left-radius: 4px;
    }

    .link-btn {
        background: none;
        border: none;
        padding: 0;
        font: inherit;
        cursor: pointer;
        color: inherit;
        text-decoration: underline;
    }
    .message.sent .link-btn { color: #003a6c; }

    .msg-meta {
        display: flex;
        gap: 6px;
        font-size: 0.7em;
        color: var(--text-secondary);
        margin-top: 2px;
    }
    .receipt { color: var(--text-secondary); }
    .receipt.read { color: #4caf50; }

    .compose {
        display: flex;
        gap: 8px;
        padding: 10px;
        border-top: 1px solid var(--border);
    }
    .compose textarea {
        flex: 1;
        resize: none;
        padding: 8px 12px;
        background: #1c1c1c;
        color: inherit;
        border: 1px solid var(--border);
        border-radius: 18px;
        font-family: inherit;
        font-size: 0.95em;
        max-height: 120px;
    }
    .compose button {
        background: #ffc125;
        color: #000;
        border: none;
        border-radius: 18px;
        padding: 8px 18px;
        cursor: pointer;
        font-weight: 500;
    }
    .compose button:disabled { opacity: 0.5; cursor: not-allowed; }

    /* BTC message types — payment requests, receipts, address shares.
       Inherit bubble color so sent (gold-on-black) and received
       (black-on-gold) variants stay consistent with text messages. */
    .pay-head { font-weight: 600; font-size: 0.95em; margin-bottom: 4px; }
    .pay-amount {
        font-weight: 600;
        font-size: 1.15em;
        font-variant-numeric: tabular-nums;
        margin: 4px 0;
    }
    .pay-memo { font-style: italic; opacity: 0.88; margin: 4px 0; }
    .pay-label { font-weight: 500; margin: 2px 0; }
    .pay-addr {
        font-family: 'JetBrains Mono', 'Consolas', monospace;
        font-size: 0.85em;
        word-break: break-all;
        margin: 4px 0;
        opacity: 0.92;
    }
    .pay-hint {
        font-size: 0.8em;
        margin-top: 8px;
        padding-top: 6px;
        border-top: 1px solid rgba(0,0,0,0.18);
        opacity: 0.75;
    }
    .mono { font-family: 'JetBrains Mono', 'Consolas', monospace; }

    /* Payment-request action row inside an incoming bubble. */
    .pay-actions { display: flex; gap: 8px; margin-top: 10px; }
    .pay-action {
        font: inherit;
        font-size: 0.85em;
        padding: 5px 12px;
        border-radius: 6px;
        cursor: pointer;
        border: 1px solid currentColor;
    }
    .pay-action:disabled { opacity: 0.5; cursor: not-allowed; }
    .pay-action.primary {
        background: #000;
        color: #ffc125;
        border-color: #000;
    }
    .pay-action.ghost {
        background: transparent;
        color: inherit;
    }
    .pay-action.danger {
        background: #c62828;
        color: #fff;
        border-color: #c62828;
    }
    .decline-row {
        display: flex;
        flex-direction: column;
        gap: 6px;
        margin-top: 10px;
    }
    .decline-input {
        background: rgba(0,0,0,0.18);
        color: inherit;
        border: 1px solid rgba(0,0,0,0.3);
        border-radius: 6px;
        padding: 6px 10px;
        font: inherit;
        font-size: 0.85em;
    }
    .decline-row { gap: 6px; }
    .decline-row .pay-action { align-self: flex-start; }
    .pay-err {
        margin-top: 6px;
        padding: 6px 8px;
        background: rgba(198, 40, 40, 0.18);
        border: 1px solid rgba(198, 40, 40, 0.45);
        border-radius: 6px;
        color: #ef5350;
        font-size: 0.78em;
    }

    /* Older-messages indicator banner above the message list. */
    .older-status {
        text-align: center;
        font-size: 0.78em;
        color: var(--text-secondary);
        padding: 6px 0;
    }
    .older-status.muted { opacity: 0.6; }

    /* Compose ➕ menu (Request payment, future attach actions). */
    .compose-menu-wrap { position: relative; display: flex; align-items: center; }
    .compose-attach {
        background: transparent;
        color: var(--text-secondary);
        border: 1px solid var(--border);
        border-radius: 50%;
        width: 32px;
        height: 32px;
        font-size: 1.2em;
        line-height: 1;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .compose-attach:hover { color: var(--accent); border-color: var(--accent); }
    .compose-menu {
        position: absolute;
        bottom: 100%;
        left: 0;
        margin-bottom: 6px;
        background: var(--surface, #1c1c1c);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 4px;
        box-shadow: 0 6px 18px rgba(0,0,0,0.45);
        min-width: 180px;
        z-index: 5;
    }
    .compose-menu-item {
        display: block;
        width: 100%;
        background: transparent;
        color: inherit;
        border: none;
        text-align: left;
        padding: 8px 12px;
        border-radius: 4px;
        cursor: pointer;
        font: inherit;
        font-size: 0.9em;
    }
    .compose-menu-item:hover { background: rgba(255,255,255,0.06); }

    /* Scroll-to-latest FAB — only shown when scrolled up. */
    .messages-scroll { position: relative; }
    .scroll-fab {
        position: sticky;
        bottom: 12px;
        align-self: flex-end;
        margin-right: 4px;
        background: var(--accent);
        color: #1a1a1a;
        border: none;
        border-radius: 50%;
        width: 36px;
        height: 36px;
        font-size: 1.1rem;
        cursor: pointer;
        box-shadow: 0 4px 12px rgba(0,0,0,0.4);
    }
    .scroll-fab:hover { background: var(--accent-hover); }
</style>

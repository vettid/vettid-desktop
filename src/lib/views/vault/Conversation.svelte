<script lang="ts">
    import { invoke } from '@tauri-apps/api/core';
    import { listen } from '@tauri-apps/api/event';
    import { open } from '@tauri-apps/plugin-shell';
    import type { Connection, Message, VaultOpResponse } from '../../types';
    import { clearSelectedConnection, selectedConnectionStore } from '../../stores/navigation';
    import { markConversationRead } from '../../stores/vault';
    import { placeCall, type CallType } from '../../stores/calls';
    import { peerName } from '../../connectionName';

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

    interface PaymentPayload {
        amount_sats?: number;
        memo?: string;
        address?: string;
        txid?: string;
        label?: string;
    }

    function parsePayment(content: string): PaymentPayload | null {
        try {
            const j = JSON.parse(content);
            return typeof j === 'object' && j !== null ? (j as PaymentPayload) : null;
        } catch {
            return null;
        }
    }

    function formatBtc(sats?: number): string {
        if (typeof sats !== 'number' || !isFinite(sats)) return '';
        const btc = (sats / 100_000_000).toFixed(8);
        return btc.replace(/\.?0+$/, '') + ' BTC';
    }

    async function loadMessages() {
        loading = true;
        error = '';
        try {
            const resp: VaultOpResponse = await invoke('get_conversation', {
                peerConnectionId: connection.connection_id,
            });
            if (resp.success && resp.data) {
                const data = resp.data as { messages?: Message[] };
                messages = (data.messages ?? []).sort(
                    (a, b) => Date.parse(a.sent_at) - Date.parse(b.sent_at),
                );
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
            await placeCall(connection.peer_guid, peerName(connection), type);
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
            {#each messages as msg (msg.id)}
                {@const sent = isSent(msg)}
                <div class="message" class:sent class:received={!sent}>
                    <div class="bubble">
                        {#if msg.content_type === 'payment_request'}
                            {@const p = parsePayment(msg.content)}
                            <div class="pay-head">{sent ? '📤 Payment request sent' : '📥 Payment request'}</div>
                            {#if p?.amount_sats !== undefined}
                                <div class="pay-amount">{formatBtc(p.amount_sats)}</div>
                            {/if}
                            {#if p?.memo}<div class="pay-memo">"{p.memo}"</div>{/if}
                            {#if p?.address}<div class="pay-addr mono">{p.address.slice(0, 18)}…</div>{/if}
                            {#if !sent}
                                <div class="pay-hint">Pay or decline from your phone — desktop pay coming soon.</div>
                            {/if}
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

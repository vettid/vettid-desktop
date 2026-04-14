<script lang="ts">
    import { invoke } from '@tauri-apps/api/core';
    import { listen } from '@tauri-apps/api/event';
    import { open } from '@tauri-apps/plugin-shell';
    import type { Connection, Message, VaultOpResponse } from '../../types';
    import { clearSelectedConnection, selectedConnectionStore } from '../../stores/navigation';
    import { markConversationRead } from '../../stores/vault';
    import { placeCall, type CallType } from '../../stores/calls';

    interface Props {
        connection: Connection;
        onShowProfile: () => void;
    }

    let { connection, onShowProfile }: Props = $props();

    let messages = $state<Message[]>([]);
    let composeText = $state('');
    let loading = $state(true);
    let sending = $state(false);
    let error = $state('');
    let scrollEl: HTMLDivElement | undefined = $state();

    function peerName(c: Connection): string {
        const p = c.peer_profile;
        const full = `${p?.first_name ?? ''} ${p?.last_name ?? ''}`.trim();
        return full || c.label || c.peer_guid.slice(0, 8);
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
        try {
            const peerName = `${connection.peer_profile?.first_name ?? ''} ${connection.peer_profile?.last_name ?? ''}`.trim()
                || connection.label
                || 'Peer';
            await placeCall(connection.peer_guid, peerName, type);
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

    {#if loading && messages.length === 0}
        <div class="status">Loading…</div>
    {:else if error}
        <div class="status error">{error}</div>
    {:else}
        <div class="messages-scroll" bind:this={scrollEl}>
            {#each messages as msg (msg.id)}
                {@const sent = isSent(msg)}
                <div class="message" class:sent class:received={!sent}>
                    <div class="bubble">
                        {#each tokenize(msg.content) as tok}
                            {#if tok.isLink && tok.href}
                                <button
                                    type="button"
                                    class="link-btn"
                                    onclick={() => openLink(tok.href!)}
                                >{tok.text}</button>
                            {:else}<span>{tok.text}</span>{/if}
                        {/each}
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
</style>

<script lang="ts">
    import { invoke } from '@tauri-apps/api/core';
    import { listen } from '@tauri-apps/api/event';
    import type { Connection, Message, VaultOpResponse } from '../../types';

    let connections: Connection[] = $state([]);
    let activeConnectionId: string | null = $state(null);
    let messages: Message[] = $state([]);
    let composeText = $state('');
    let loading = $state(true);
    let sending = $state(false);
    let error = $state('');
    let sendError = $state('');

    async function loadConnections() {
        loading = true;
        error = '';
        try {
            const resp: VaultOpResponse = await invoke('list_connections');
            if (resp.success && resp.data) {
                const data = resp.data as { connections?: Connection[] };
                connections = (data.connections ?? []).filter(c => c.status === 'active');
            } else {
                error = resp.error ?? 'Failed to load connections';
            }
        } catch (e) {
            error = String(e);
        }
        loading = false;
    }

    async function selectConnection(connId: string) {
        activeConnectionId = connId;
        messages = [];
        try {
            const resp: VaultOpResponse = await invoke('get_conversation', { peerConnectionId: connId });
            if (resp.success && resp.data) {
                const data = resp.data as { messages?: Message[] };
                messages = data.messages ?? [];
            }
        } catch (e) {
            error = `Failed to load conversation: ${e}`;
        }
    }

    async function sendMessage() {
        if (!composeText.trim() || !activeConnectionId || sending) return;
        sending = true;
        try {
            const resp: VaultOpResponse = await invoke('send_message', {
                peerConnectionId: activeConnectionId,
                content: composeText,
            });
            if (resp.success) {
                composeText = '';
                // Reload conversation
                await selectConnection(activeConnectionId!);
            }
        } catch (e) {
            sendError = `Failed to send: ${e}`;
        }
        sending = false;
    }

    function handleKeydown(e: KeyboardEvent) {
        if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
            sendMessage();
        }
    }

    $effect(() => { loadConnections(); });

    // Listen for real-time messages
    $effect(() => {
        const unlisten = listen<Message>('vault:message-received', (event) => {
            if (event.payload.connection_id === activeConnectionId) {
                messages = [...messages, event.payload];
            }
        });
        return () => { unlisten.then(fn => fn()); };
    });
</script>

<div class="messaging-view">
    <!-- Conversation list (left pane) -->
    <div class="conversation-list">
        <h3>Messages</h3>
        {#if loading}
            <div class="status">Loading...</div>
        {:else if error}
            <div class="status error">{error}</div>
        {:else if connections.length === 0}
            <div class="status">No conversations</div>
        {:else}
            {#each connections as conn}
                <button
                    class="conversation-item"
                    class:active={activeConnectionId === conn.connection_id}
                    onclick={() => selectConnection(conn.connection_id)}
                >
                    <div class="conv-name">{conn.label || conn.peer_guid}</div>
                </button>
            {/each}
        {/if}
    </div>

    <!-- Active conversation (right pane) -->
    <div class="conversation-pane">
        {#if !activeConnectionId}
            <div class="status">Select a conversation</div>
        {:else}
            <div class="messages-scroll">
                {#each messages as msg}
                    <div class="message" class:sent={msg.sender_id !== activeConnectionId}>
                        <div class="bubble">{msg.content}</div>
                        <div class="msg-meta">{new Date(msg.sent_at).toLocaleTimeString()}</div>
                    </div>
                {/each}
            </div>

            {#if sendError}
                <div class="send-error">{sendError}</div>
            {/if}

            <div class="compose">
                <textarea
                    bind:value={composeText}
                    onkeydown={handleKeydown}
                    placeholder="Type a message... (Ctrl+Enter to send)"
                    rows="2"
                ></textarea>
                <button onclick={sendMessage} disabled={sending || !composeText.trim()}>
                    {sending ? '...' : 'Send'}
                </button>
            </div>
        {/if}
    </div>
</div>

<style>
    .messaging-view { display: flex; height: 100%; gap: 1px; background: var(--border); }
    .conversation-list { width: 260px; background: var(--bg); overflow-y: auto; padding: 12px; flex-shrink: 0; }
    .conversation-list h3 { margin: 0 0 12px; }
    .conversation-pane { flex: 1; display: flex; flex-direction: column; background: var(--bg); }
    .conversation-item { display: block; width: 100%; text-align: left; padding: 10px; border: none; background: none; border-radius: 6px; cursor: pointer; }
    .conversation-item:hover { background: var(--bg-hover); }
    .conversation-item.active { background: var(--accent-bg); }
    .conv-name { font-weight: 500; }
    .status { color: var(--text-secondary); padding: 24px; text-align: center; }
    .status.error { color: var(--danger); }
    .send-error { color: var(--danger); font-size: 0.8em; padding: 4px 12px; }
    .messages-scroll { flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 8px; }
    .message { display: flex; flex-direction: column; max-width: 70%; }
    .message.sent { align-self: flex-end; }
    .bubble { padding: 8px 12px; border-radius: 12px; background: var(--bg-hover); }
    .message.sent .bubble { background: var(--accent-bg); }
    .msg-meta { font-size: 0.75em; color: var(--text-secondary); margin-top: 2px; }
    .compose { display: flex; gap: 8px; padding: 12px; border-top: 1px solid var(--border); }
    .compose textarea { flex: 1; resize: none; padding: 8px; border: 1px solid var(--border); border-radius: 6px; font-family: inherit; }
    .compose button { padding: 8px 16px; border: none; background: var(--accent); color: white; border-radius: 6px; cursor: pointer; }
    .compose button:disabled { opacity: 0.5; cursor: default; }
</style>

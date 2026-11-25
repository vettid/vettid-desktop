<script module lang="ts">
    import type { Local } from '../../conversationView.js';

    // This window's own sends and drafts, per connection, kept while the
    // conversation is closed or the session isn't live (a send left
    // unconfirmed may still be carried out, and its answer may come back to
    // a closed view). In memory only: message text is never stored or
    // logged.
    const kept = $state<{ locals: Local[]; drafts: Record<string, string>; errors: Record<string, string> }>({
        locals: [],
        drafts: {},
        errors: {},
    });
</script>

<script lang="ts">
    // A conversation (DESKTOP-REWORK-PLAN Phase 5, 5.3): `get_conversation`
    // (`message.list`, newest page, then older pages with `before`),
    // `send_message` and `mark_message_read`, live `message.new` and
    // receipts from `vault:inbound`. The rules are in conversationView.js.
    // Only what the vault answered is shown: a failed read clears the
    // messages and shows the backend's text; nothing is shown while the
    // session isn't live; a send is never shown as sent before the vault
    // said so.
    import { invoke } from '@tauri-apps/api/core';
    import { listen } from '@tauri-apps/api/event';
    import { open } from '@tauri-apps/plugin-shell';
    import { onMount, tick, untrack } from 'svelte';
    import type { Connection, VaultOpResponse } from '../../connections';
    import { INBOUND_EVENT, type InboundBatch } from '../../inbound';
    import { sessionStore } from '../../stores/session';
    import { connectionTitle } from '../../connectionView.js';
    import {
        PAGE_LIMIT,
        SERVICE_NO_MESSAGES,
        MESSAGES_NOT_LIVE_TEXT,
        UNREADABLE_MESSAGES,
        UNCONFIRMED_EXPIRED_TEXT,
        EMPTY_MESSAGE,
        LINE_ISOLATE,
        LINK_NOT_OPENED,
        mergeMessages,
        applySyncEvent,
        markedRead,
        nextToMark,
        newLocal,
        sameUnconfirmed,
        applySendAnswer,
        retrying,
        expireStale,
        afterReload,
        withReturned,
        viewMessages,
        deliveryState,
        deliveryText,
        bubbleContent,
        textBytes,
        canSend,
        tooLongText,
        MAX_TEXT_BYTES,
        takesMessages,
        conversationAction,
        openLinkQuestion,
    } from '../../conversationView.js';
    import type { Message } from '../../conversationView.js';

    interface Props {
        connection: Connection;
        /** Hide the local header when embedded in ConnectionWorkspace,
         *  which owns the workspace header. */
        compact?: boolean;
    }

    let { connection, compact = false }: Props = $props();

    // The workspace mounts one Conversation per connection ({#key}).
    const cid = untrack(() => connection.id);

    let live = $derived($sessionStore.state === 'active');
    let takes = $derived(takesMessages(connection));
    let title = $derived(connectionTitle(connection));

    /** The vault's messages as the last reads gave them, and live ones since. */
    let messages = $state<Message[]>([]);
    let nextBefore = $state<string | null>(null);
    let unreadable = $state(0);
    let loading = $state(false);
    let loaded = $state(false);
    let loadError = $state('');
    let olderLoading = $state(false);
    let olderError = $state('');
    let sending = $state(false);
    let linkAsk = $state<{ href: string; host: string } | null>(null);
    let linkError = $state('');
    let scrollEl: HTMLDivElement | undefined = $state();

    /** Counts newest-page reads: only the latest one's answer is applied,
     *  and an older page read before it is dropped. */
    let seq = 0;
    /** `message.new` and receipts that arrive while the newest page is read. */
    let buffer: { messages: Message[]; events: Array<{ kind?: string; members?: Record<string, unknown> }> } | null = null;

    if (kept.drafts[cid] === undefined) kept.drafts[cid] = '';
    let draft = $derived(kept.drafts[cid] ?? '');
    let draftBytes = $derived(textBytes(draft));
    let sendError = $derived(kept.errors[cid] ?? '');

    let items = $derived(viewMessages(messages, kept.locals, cid));

    /** Messages tried in this read of the conversation; a failed mark is
     *  tried again after the next read. */
    const tried = new Set<string>();
    let marking = false;
    /** Set once the view is closed: a send's answer still lands in `kept`,
     *  but nothing is read for a closed view. */
    let closed = false;

    function clear(): void {
        seq++;
        buffer = null;
        messages = [];
        nextBefore = null;
        unreadable = 0;
        loading = false;
        loaded = false;
        loadError = '';
        olderLoading = false;
        olderError = '';
        linkAsk = null;
        linkError = '';
        tried.clear();
    }

    async function loadNewest(): Promise<void> {
        const mine = ++seq;
        const startedAt = Date.now();
        buffer = { messages: [], events: [] };
        loading = true;
        olderLoading = false;
        olderError = '';
        let resp: VaultOpResponse<{ messages?: Message[]; next_before?: string; unreadable?: number }> | null = null;
        let err = '';
        try {
            resp = await invoke('get_conversation', { connectionId: cid, limit: PAGE_LIMIT });
        } catch (e) {
            err = String(e);
        }
        if (mine !== seq) return;
        const got = buffer;
        buffer = null;
        loading = false;
        loaded = true;
        if (resp?.success && resp.data) {
            let next = mergeMessages(resp.data.messages ?? [], got?.messages ?? [], cid);
            for (const ev of got?.events ?? []) next = applySyncEvent(next, ev, cid);
            messages = next;
            nextBefore = resp.data.next_before ?? null;
            unreadable = resp.data.unreadable ?? 0;
            loadError = '';
            tried.clear();
            const after = afterReload(kept.locals, cid, new Set(next.map((m) => m.message_id)), startedAt);
            kept.locals = after.locals;
            if (after.returned.length) {
                kept.drafts[cid] = withReturned(kept.drafts[cid] ?? '', after.returned);
                kept.errors[cid] = UNCONFIRMED_EXPIRED_TEXT;
            }
            await tick();
            scrollToBottom();
        } else {
            // Nothing that wasn't confirmed stays on screen.
            messages = [];
            nextBefore = null;
            unreadable = 0;
            loadError = resp?.error ?? err;
        }
    }

    async function loadOlder(): Promise<void> {
        const before = nextBefore;
        if (!before || olderLoading || loading) return;
        const mine = seq;
        olderLoading = true;
        olderError = '';
        let resp: VaultOpResponse<{ messages?: Message[]; next_before?: string; unreadable?: number }> | null = null;
        let err = '';
        try {
            resp = await invoke('get_conversation', { connectionId: cid, before, limit: PAGE_LIMIT });
        } catch (e) {
            err = String(e);
        }
        if (mine !== seq) return;
        olderLoading = false;
        if (resp?.success && resp.data) {
            const height = scrollEl?.scrollHeight ?? 0;
            messages = mergeMessages(messages, resp.data.messages ?? [], cid);
            nextBefore = resp.data.next_before ?? null;
            unreadable += resp.data.unreadable ?? 0;
            await tick();
            // Keep the messages that were on screen where they were.
            if (scrollEl) scrollEl.scrollTop += scrollEl.scrollHeight - height;
        } else if (resp?.error_code === 'page_gone') {
            // That message is gone (§10.5.2): start again from the newest page.
            void loadNewest();
        } else {
            olderError = resp?.error ?? err;
        }
    }

    function nearBottom(): boolean {
        if (!scrollEl) return true;
        return scrollEl.scrollHeight - scrollEl.scrollTop - scrollEl.clientHeight < 80;
    }

    function scrollToBottom(): void {
        if (scrollEl) scrollEl.scrollTop = scrollEl.scrollHeight;
    }

    async function onInbound(batch: InboundBatch): Promise<void> {
        const action = conversationAction(batch, live && takes);
        if (action === 'drop') return;
        if (action === 'reload') {
            void loadNewest();
            return;
        }
        const atBottom = nearBottom();
        let added = false;
        for (const m of batch.messages ?? []) {
            if (m?.type === 'message.new') {
                if (m.body?.connection_id !== cid) continue;
                if (buffer) buffer.messages.push(m.body);
                messages = mergeMessages(messages, [m.body], cid);
                added = true;
            } else if (m?.type === 'sync.event') {
                if (buffer) buffer.events.push(m.body);
                messages = applySyncEvent(messages, m.body, cid);
                kept.locals = applySyncEvent(kept.locals, m.body, cid);
            }
        }
        if (added && atBottom) {
            await tick();
            scrollToBottom();
        }
    }

    // ---- Marking read: one call at a time, never in the way of the view.

    function pumpReads(): void {
        if (closed || marking || !live || !takes || document.visibilityState !== 'visible') return;
        const id = nextToMark(messages, tried);
        if (!id) return;
        tried.add(id);
        marking = true;
        const mine = seq;
        invoke<VaultOpResponse<unknown>>('mark_message_read', { connectionId: cid, messageId: id })
            .then((resp) => {
                if (resp.success && mine === seq) messages = markedRead(messages, id);
            })
            .catch(() => {})
            .finally(() => {
                marking = false;
                pumpReads();
            });
    }

    $effect(() => {
        // Marked once they are on screen: whenever the messages change.
        void messages;
        void live;
        untrack(pumpReads);
    });

    // ---- Sending

    async function send(): Promise<void> {
        const text = kept.drafts[cid] ?? '';
        if (sending || !live || !takes || !canSend(text)) return;
        // The same text as an unconfirmed send is that send's retry (the
        // backend sends it again under its id), never a second message.
        const same = sameUnconfirmed(kept.locals, cid, text);
        let key: string;
        if (same) {
            key = same.key;
            kept.locals = retrying(kept.locals, key);
        } else {
            const l = newLocal(cid, text, Date.now());
            key = l.key;
            kept.locals = [...kept.locals, l];
        }
        kept.drafts[cid] = '';
        kept.errors[cid] = '';
        sending = true;
        await tick();
        scrollToBottom();
        let resp: VaultOpResponse<any> | null = null;
        try {
            resp = await invoke('send_message', { connectionId: cid, text });
        } catch {
            // No answer at all: it may have gone, so it is unconfirmed.
            resp = null;
        }
        const r = applySendAnswer(kept.locals, key, resp, Date.now());
        kept.locals = r.locals;
        if (r.draft !== null) kept.drafts[cid] = withReturned(kept.drafts[cid] ?? '', [r.draft]);
        kept.errors[cid] = r.error;
        sending = false;
        if (r.refresh && live && !closed) void loadNewest();
    }

    function onKeydown(e: KeyboardEvent): void {
        if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
            e.preventDefault();
            void send();
        }
    }

    // ---- Links (§10.5): the host is shown and the member asked first.

    function askOpen(p: { href: string; host: string }): void {
        linkError = '';
        linkAsk = { href: p.href, host: p.host };
    }

    async function openAsked(): Promise<void> {
        const ask = linkAsk;
        linkAsk = null;
        if (!ask) return;
        try {
            await open(ask.href);
        } catch {
            linkError = LINK_NOT_OPENED;
        }
    }

    function when(iso: string): string {
        if (!iso) return '';
        const t = new Date(iso);
        return Number.isNaN(t.getTime()) ? '' : t.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
    }

    // Read when the session goes live (and on opening); cleared when it stops.
    $effect(() => {
        const on = live && takes;
        untrack(() => {
            if (on) void loadNewest();
            else clear();
        });
    });

    onMount(() => {
        kept.locals = expireStale(kept.locals, Date.now()).locals;
        const un = listen<InboundBatch>(INBOUND_EVENT, (event) => void onInbound(event.payload));
        // A send left unconfirmed past its time, by this clock, is read
        // about again before its text is offered again.
        const timer = setInterval(() => {
            const e = expireStale(kept.locals, Date.now());
            if (!e.changed) return;
            kept.locals = e.locals;
            if (live && takes) void loadNewest();
        }, 15_000);
        const onVisible = () => pumpReads();
        document.addEventListener('visibilitychange', onVisible);
        return () => {
            closed = true;
            seq++;
            clearInterval(timer);
            document.removeEventListener('visibilitychange', onVisible);
            void un.then((f) => f());
        };
    });
</script>

<div class="conversation">
    {#if !compact}
        <header class="bar">
            <h3><bdi>{title}</bdi></h3>
        </header>
    {/if}

    {#if !takes}
        <div class="status">{SERVICE_NO_MESSAGES}</div>
    {:else if !live}
        <div class="status">{MESSAGES_NOT_LIVE_TEXT}</div>
    {:else}
        <div class="tools">
            <button class="refresh" aria-label="Refresh" title="Refresh" onclick={() => void loadNewest()} disabled={loading}>↻</button>
        </div>

        {#if loading && !loaded}
            <div class="status">Loading…</div>
        {:else if loadError}
            <div class="status error">{loadError}</div>
        {:else}
            <div class="messages-scroll" bind:this={scrollEl}>
                {#if unreadable > 0}
                    <div class="note">{UNREADABLE_MESSAGES}</div>
                {/if}
                {#if nextBefore}
                    <div class="older">
                        {#if olderLoading}
                            <span class="muted">Loading…</span>
                        {:else}
                            <!-- NEW TEXT (owner approval needed) -->
                            <button class="older-btn" onclick={() => void loadOlder()}>Load older</button>
                        {/if}
                    </div>
                {/if}
                {#if olderError}
                    <div class="older error">{olderError}</div>
                {/if}

                {#each items as m (m.key)}
                    {@const content = bubbleContent(m)}
                    {@const st = deliveryState(m, { relayHeld: !!connection.relay_held })}
                    {@const stText = deliveryText(st, { notice: m.local?.notice, title })}
                    <div class="message" class:sent={m.direction === 'out'} class:received={m.direction !== 'out'}>
                        <div
                            class="bubble"
                            class:pending={st === 'sending' || st === 'unconfirmed'}
                            class:check={st === 'expired' || st === 'unreadable'}
                        >
                            {#if content.placeholder}
                                <div class="attachment">{content.placeholder}</div>
                            {/if}
                            {#if content.body}
                                {#if content.body.empty}
                                    <div class="empty">{EMPTY_MESSAGE}</div>
                                {:else}
                                    <div class="text" class:caption={!!content.placeholder}>
                                        {#each content.body.lines as line}
                                            <div class="line">{LINE_ISOLATE.start}{#each line as p}{#if 'href' in p}<button type="button" class="link" onclick={() => askOpen(p)}>{p.text}</button>{:else}{p.text}{/if}{/each}{LINE_ISOLATE.end}</div>
                                        {/each}
                                    </div>
                                {/if}
                            {/if}
                        </div>
                        <div class="meta">
                            {#if when(m.sent_at)}<span class="time">{when(m.sent_at)}</span>{/if}
                            {#if stText}
                                <span
                                    class="state"
                                    class:unconfirmed={st === 'unconfirmed' || st === 'held'}
                                    class:check={st === 'expired' || st === 'unreadable'}
                                    class:read={st === 'read'}
                                >{stText}</span>
                            {/if}
                        </div>
                    </div>
                {/each}
            </div>

            {#if linkAsk}
                <div class="link-ask" role="dialog" aria-modal="false">
                    <span>{openLinkQuestion(linkAsk.host)}</span>
                    <!-- NEW TEXT (owner approval needed): "Open" -->
                    <button type="button" class="primary" onclick={() => void openAsked()}>Open</button>
                    <button type="button" onclick={() => (linkAsk = null)}>Cancel</button>
                </div>
            {/if}
            {#if linkError}
                <div class="compose-note error">{linkError}</div>
            {/if}

            <form class="compose" onsubmit={(e) => { e.preventDefault(); void send(); }}>
                <!-- NEW TEXT (owner approval needed): the box's label, "Message" -->
                <textarea
                    bind:value={kept.drafts[cid]}
                    onkeydown={onKeydown}
                    rows="2"
                    aria-label="Message"
                ></textarea>
                <button type="submit" disabled={sending || !canSend(draft)}>{sending ? '…' : 'Send'}</button>
            </form>
            {#if draftBytes > MAX_TEXT_BYTES}
                <div class="compose-note error">{tooLongText(draftBytes)}</div>
            {/if}
            {#if sendError}
                <div class="compose-note error">{sendError}</div>
            {/if}
        {/if}
    {/if}
</div>

<style>
    .conversation { height: 100%; display: flex; flex-direction: column; min-height: 0; }
    .bar {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 0 0 12px;
        border-bottom: 1px solid var(--border);
    }
    .bar h3 { margin: 0; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    .tools { display: flex; justify-content: flex-end; }
    .refresh {
        background: none;
        border: 1px solid var(--border);
        border-radius: 4px;
        padding: 2px 8px;
        cursor: pointer;
        color: inherit;
    }

    .status { padding: 24px; text-align: center; color: var(--text-muted); }
    .error { color: var(--error); }
    .muted { color: var(--text-muted); }
    .note {
        font-size: 0.85em;
        color: var(--text-muted);
        border: 1px solid var(--border);
        border-radius: 6px;
        padding: 6px 10px;
        margin-bottom: 8px;
    }

    .messages-scroll {
        flex: 1;
        min-height: 0;
        overflow-y: auto;
        display: flex;
        flex-direction: column;
        gap: 6px;
        padding: 8px 2px;
    }
    .older { text-align: center; font-size: 0.85em; padding: 4px 0; }
    .older-btn {
        background: none;
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 3px 12px;
        cursor: pointer;
        color: inherit;
    }

    .message { display: flex; flex-direction: column; max-width: 75%; }
    .message.sent { align-self: flex-end; align-items: flex-end; }
    .message.received { align-self: flex-start; align-items: flex-start; }
    .bubble {
        border-radius: 12px;
        padding: 7px 11px;
        background: var(--bg-elevated);
        border: 1px solid var(--border);
        overflow-wrap: anywhere;
    }
    .message.sent .bubble { background: var(--accent-muted, var(--bg-elevated)); }
    .bubble.pending { opacity: 0.75; border-style: dashed; }
    .bubble.check { border-color: var(--warning); }
    .line { white-space: pre-wrap; min-height: 1.3em; }
    .text.caption { margin-top: 6px; }
    .attachment { font-style: italic; color: var(--text-muted); }
    .empty { font-style: italic; color: var(--text-muted); }
    .link {
        background: none;
        border: none;
        padding: 0;
        font: inherit;
        color: var(--accent);
        text-decoration: underline;
        cursor: pointer;
    }
    .meta { display: flex; gap: 8px; font-size: 0.75em; color: var(--text-muted); margin-top: 2px; max-width: 100%; }
    .state.unconfirmed { color: var(--warning); }
    .state.check { color: var(--warning); }
    .state.read { color: var(--accent); }

    .link-ask {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 8px;
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 8px 10px;
        margin-top: 6px;
        font-size: 0.9em;
    }
    .link-ask span { flex: 1; min-width: 12em; overflow-wrap: anywhere; }
    .link-ask button {
        background: none;
        border: 1px solid var(--border);
        border-radius: 4px;
        padding: 3px 10px;
        cursor: pointer;
        color: inherit;
    }
    .link-ask button.primary { border-color: var(--accent); color: var(--accent); }

    .compose { display: flex; gap: 8px; margin-top: 8px; }
    .compose textarea {
        flex: 1;
        resize: vertical;
        min-height: 2.4em;
        max-height: 12em;
        font: inherit;
        padding: 6px 8px;
        border: 1px solid var(--border);
        border-radius: 6px;
        background: var(--bg);
        color: var(--text);
    }
    .compose button {
        border: 1px solid var(--accent);
        background: var(--accent);
        color: var(--bg-pure, #fff);
        border-radius: 6px;
        padding: 0 16px;
        cursor: pointer;
    }
    .compose button:disabled { opacity: 0.5; cursor: default; }
    .compose-note { font-size: 0.85em; margin-top: 4px; }
</style>

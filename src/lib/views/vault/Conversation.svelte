<script lang="ts">
    // A conversation (DESKTOP-REWORK-PLAN Phase 5, 5.3): `get_conversation`
    // (`message.list`, newest page, then older pages with `before`),
    // `send_message`, `retry_send` and `mark_message_read`, live
    // `message.new` and receipts from `vault:inbound`. The rules are in
    // conversationView.js; this window's own sends and drafts are kept in
    // stores/conversations.svelte.ts. Only what the vault answered is shown:
    // a failed read clears the messages and shows the backend's text;
    // nothing is shown while the session isn't live; a send is never shown
    // as sent before the vault said so, and never offered again before a
    // read of the conversation showed it isn't there.
    import { invoke } from '@tauri-apps/api/core';
    import { listen } from '@tauri-apps/api/event';
    import { onMount, tick, untrack } from 'svelte';
    import type { Connection, VaultOpResponse } from '../../connections';
    import { INBOUND_EVENT, type InboundBatch } from '../../inbound';
    import { sessionStore } from '../../stores/session';
    import { kept } from '../../stores/conversations.svelte.js';
    import { connectionsStore } from '../../stores/vault';
    import { connectionTitle } from '../../connectionView.js';
    import {
        PAGE_LIMIT,
        SERVICE_NO_MESSAGES,
        MESSAGES_NOT_LIVE_TEXT,
        UNREADABLE_MESSAGES,
        EMPTY_MESSAGE,
        LINE_ISOLATE,
        LINK_NOT_OPENED,
        EDIT_NEEDS_EMPTY_BOX,
        returnedElsewhereText,
        knownOutgoing,
        seenInView,
        shouldReread,
        mergeNewest,
        rereadDelay,
        DELIVERY_TEXT,
        mergeMessages,
        applySyncEvent,
        markedRead,
        nextToMark,
        newLocal,
        startRetry,
        applySendAnswer,
        applyRetryAnswer,
        expireDue,
        afterReload,
        placeReturned,
        unsentToDraft,
        knowsEvent,
        releaseHeld,
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
    } from '../../conversationView.js';
    import type { Message, Returned, SyncEv } from '../../conversationView.js';

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
    let linkError = $state('');
    let scrollEl: HTMLDivElement | undefined = $state();

    /** Counts newest-page reads: only the latest one's answer is applied,
     *  and an older page read before it is dropped. */
    let seq = 0;
    /** When the last newest-page read began, by `performance.now()`. */
    let lastReadAt = -Infinity;
    /** Newest-page reads in a row that failed: the reads the view makes on
     *  its own back off (rereadDelay). */
    let readFailures = 0;
    /** `message.new` and receipts that arrive while the newest page is read. */
    let buffer: { messages: Message[]; events: SyncEv[] } | null = null;

    if (kept.drafts[cid] === undefined) kept.drafts[cid] = '';
    let draft = $derived(kept.drafts[cid] ?? '');
    let draftBytes = $derived(textBytes(draft));
    let sendError = $derived(kept.errors[cid] ?? '');
    let sending = $derived(!!kept.sending[cid]);

    let items = $derived(viewMessages(messages, kept.locals, cid));

    /** Each bubble's cleaned content, worked out once per text. */
    const contentCache = new Map<string, { text: string; att: boolean; value: ReturnType<typeof bubbleContent> }>();
    function contentOf(m: { key: string; text: string; attachment?: unknown }) {
        const att = !!m.attachment;
        const hit = contentCache.get(m.key);
        if (hit && hit.text === m.text && hit.att === att) return hit.value;
        const value = bubbleContent(m);
        contentCache.set(m.key, { text: m.text, att, value });
        return value;
    }

    /** Messages tried in this read of the conversation; a failed mark is
     *  tried again after the next read. */
    const tried = new Set<string>();
    /** Incoming messages the member has seen: shown in the viewport while
     *  the window was visible. Only these are marked read. */
    const seen = new Set<string>();
    /** Incoming unread messages in the viewport now. */
    const inView = new Set<string>();
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
        linkError = '';
        tried.clear();
        // No cleaned message text stays in memory for a conversation not shown.
        contentCache.clear();
        // Receipts held for messages not known yet are stale by the next read.
        kept.held = [];
    }

    /** Texts back to the member: the box when it is empty, else bubbles. */
    function giveBack(returned: Returned[]): void {
        if (!returned.length) return;
        const p = placeReturned(kept.locals, kept.drafts, returned, Date.now());
        kept.locals = p.locals;
        kept.drafts = p.drafts;
        for (const [c, e] of Object.entries(p.errors)) kept.errors[c] = e;
        // A text back in another conversation is said here too.
        const others = returned.map((r) => r.connection_id).filter((c) => c !== cid && !kept.returnedTo.includes(c));
        if (others.length) kept.returnedTo = [...kept.returnedTo, ...new Set(others)];
    }

    /** The other conversations a text went back to, by title. */
    let elsewhere = $derived(
        kept.returnedTo
            .filter((c) => c !== cid)
            .map((c) => {
                const conn = $connectionsStore.find((x) => x.id === c);
                return { id: c, text: returnedElsewhereText(conn ? connectionTitle(conn) : '') };
            }),
    );

    /** Receipts held for messages of this connection that are known now. */
    function releaseNow(): void {
        if (!kept.held.length) return;
        const r = releaseHeld(
            kept.held,
            (ev) => ev.members?.connection_id === cid && knowsEvent(messages, kept.locals, ev, cid),
            Date.now(),
        );
        kept.held = r.held;
        for (const ev of r.ready) applyEvent(ev);
    }

    function applyEvent(ev: SyncEv): void {
        messages = applySyncEvent(messages, ev, cid);
        kept.locals = applySyncEvent(kept.locals, ev, cid);
    }

    async function loadNewest(): Promise<void> {
        if (closed) return;
        const mine = ++seq;
        const startedAt = Date.now();
        lastReadAt = performance.now();
        // A send past its expires_at is read about now.
        const due = expireDue(kept.locals, startedAt);
        if (due.changed) kept.locals = due.locals;
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
            const firstRead = messages.length === 0;
            const atBottom = nearBottom();
            // The older pages loaded stay, when this page meets them.
            const merged = mergeNewest(messages, resp.data.messages ?? [], nextBefore, resp.data.next_before ?? null, cid);
            const keptOlder = merged.messages.length > (resp.data.messages ?? []).length;
            let next = mergeMessages(merged.messages, got?.messages ?? [], cid);
            for (const ev of got?.events ?? []) next = applySyncEvent(next, ev, cid);
            messages = next;
            nextBefore = merged.nextBefore;
            unreadable = keptOlder ? Math.max(unreadable, resp.data.unreadable ?? 0) : (resp.data.unreadable ?? 0);
            loadError = '';
            tried.clear();
            const after = afterReload(kept.locals, cid, next, startedAt);
            kept.locals = after.locals;
            releaseNow();
            readFailures = 0;
            await tick();
            // Someone reading history stays where they are.
            if (firstRead || atBottom) scrollToBottom();
            // A send that expired or came back unreadable during this read
            // is read about again by the timer (shouldReread).
        } else {
            readFailures += 1;
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
            releaseNow();
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
                if (knowsEvent(messages, kept.locals, m.body, cid)) applyEvent(m.body);
                // Its message isn't known yet (send_message's answer may be
                // on its way, or a page will have it): held a while.
                else kept.held = [...kept.held, { ev: m.body, at: Date.now() }];
            }
        }
        if (added) releaseNow();
        if (added && atBottom) {
            await tick();
            scrollToBottom();
        }
    }

    // ---- Marking read: only what was seen, one call at a time, never in
    // the way of the view.

    function pumpReads(): void {
        if (closed || marking || !live || !takes || !attending()) return;
        const id = nextToMark(messages, tried, seen);
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

    /** Dense thresholds, every 0.05, so that a bubble taller than the pane
     *  is measured as it scrolls (seenInView's second rule). */
    const THRESHOLDS = Array.from({ length: 21 }, (_, i) => i / 20);
    /** The incoming unread bubbles watched, whatever the observer is now. */
    const watched = new Set<HTMLElement>();
    /** Watches against the message pane itself (`root`), so `rootBounds`
     *  is the pane, not the window; made again whenever the pane is. */
    let observer: IntersectionObserver | null = null;
    $effect(() => {
        const root = scrollEl;
        if (!root || typeof IntersectionObserver === 'undefined') return;
        const o = new IntersectionObserver(
            (entries) => {
                for (const e of entries) {
                    const id = (e.target as HTMLElement).dataset.unreadId ?? '';
                    if (!id) continue;
                    if (seenInView(e)) inView.add(id);
                    else inView.delete(id);
                }
                noteSeen();
            },
            { root, threshold: THRESHOLDS },
        );
        observer = o;
        for (const n of watched) o.observe(n);
        return () => {
            o.disconnect();
            if (observer === o) observer = null;
            inView.clear();
        };
    });

    /** What is in the viewport counts as seen while the window is visible. */
    /** The member can see the window: shown, and focused. */
    function attending(): boolean {
        return document.visibilityState === 'visible' && document.hasFocus();
    }

    function noteSeen(): void {
        if (!attending()) return;
        for (const id of inView) seen.add(id);
        pumpReads();
    }

    /** Watches an incoming unread bubble (id ''): nothing to watch. */
    function watchUnread(node: HTMLElement, id: string) {
        const set = (v: string) => {
            node.dataset.unreadId = v;
            if (v) {
                watched.add(node);
                observer?.observe(node);
            } else {
                watched.delete(node);
                observer?.unobserve(node);
            }
        };
        set(id);
        return {
            update(v: string) {
                if (!v) inView.delete(node.dataset.unreadId ?? '');
                set(v);
            },
            destroy() {
                inView.delete(node.dataset.unreadId ?? '');
                watched.delete(node);
                observer?.unobserve(node);
            },
        };
    }

    // ---- Sending

    async function send(): Promise<void> {
        const text = kept.drafts[cid] ?? '';
        if (kept.sending[cid] || !live || !takes || !canSend(text)) return;
        // Always a new message (send_message); an unconfirmed one is tried
        // again by its own "Try again".
        // What the view has of this connection's outgoing messages now, so a
        // later read can tell a new one from those (in the vault's terms).
        const l = newLocal(cid, text, Date.now(), knownOutgoing(messages, kept.locals, cid));
        kept.locals = [...kept.locals, l];
        kept.drafts[cid] = '';
        kept.errors[cid] = '';
        kept.sending[cid] = true;
        await tick();
        scrollToBottom();
        let refresh = false;
        try {
            let resp: VaultOpResponse<any> | null = null;
            try {
                resp = await invoke('send_message', { connectionId: cid, text });
            } catch {
                // No answer at all: it may have gone, so it is unconfirmed.
                resp = null;
            }
            const r = applySendAnswer(kept.locals, l.key, resp, Date.now());
            kept.locals = r.locals;
            giveBack(r.returned);
            refresh = r.refresh;
        } finally {
            kept.sending[cid] = false;
        }
        if (!closed) releaseNow();
        if (refresh && live && !closed) void loadNewest();
    }

    async function retry(key: string): Promise<void> {
        const l = kept.locals.find((x) => x.key === key);
        if (!l?.pending_id || l.state !== 'unconfirmed' || kept.sending[cid] || !live || !takes) return;
        const pendingId = l.pending_id;
        kept.locals = startRetry(kept.locals, key);
        kept.sending[cid] = true;
        let refresh = false;
        try {
            let resp: VaultOpResponse<any> | null = null;
            try {
                resp = await invoke('retry_send', { connectionId: cid, pendingId });
            } catch {
                resp = null;
            }
            const r = applyRetryAnswer(kept.locals, key, resp, Date.now());
            kept.locals = r.locals;
            giveBack(r.returned);
            refresh = r.refresh;
        } finally {
            kept.sending[cid] = false;
        }
        if (!closed) releaseNow();
        if (refresh && live && !closed) void loadNewest();
    }

    function editUnsent(key: string): void {
        const r = unsentToDraft(kept.locals, kept.drafts, key);
        if (!r) return;
        kept.locals = r.locals;
        kept.drafts = r.drafts;
        kept.errors[cid] = '';
    }

    function removeUnsent(key: string): void {
        kept.locals = kept.locals.filter((x) => !(x.key === key && x.state === 'unsent'));
    }

    function onKeydown(e: KeyboardEvent): void {
        // An Enter that confirms an IME candidate (WebKit says keyCode 229) isn't a send.
        if (e.key === 'Enter' && !e.shiftKey && !e.isComposing && e.keyCode !== 229) {
            e.preventDefault();
            void send();
        }
    }

    // ---- Links (§10.5): open_message_link checks the link, shows its host
    // in a native prompt and opens it only on the member's "Open". The
    // window itself can't open a URL.

    async function openLink(p: { text: string }): Promise<void> {
        linkError = '';
        try {
            // `opened`, or nothing to say: cancelled, or "Open" too soon
            // after the prompt showed (MIN_CONFIRM_MS in commands/links.rs).
            await invoke<string>('open_message_link', { text: p.text });
        } catch {
            // Refused, busy (another link's prompt shown, or one declined
            // just now), the prompt not shown, or not opened.
            linkError = LINK_NOT_OPENED;
        }
    }

    function when(iso: string): string {
        if (!iso) return '';
        const t = new Date(iso);
        return Number.isNaN(t.getTime()) ? '' : t.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
    }

    // Read when the session goes live (and on opening, which also reads
    // about any send that expired while the view was closed); cleared when
    // it stops.
    $effect(() => {
        const on = live && takes;
        untrack(() => {
            if (on) void loadNewest();
            else clear();
        });
    });

    onMount(() => {
        // Opened: a note that a text came back here is no longer needed.
        if (kept.returnedTo.includes(cid)) kept.returnedTo = kept.returnedTo.filter((c) => c !== cid);
        const un = listen<InboundBatch>(INBOUND_EVENT, (event) => void onInbound(event.payload));
        // A send past its deadline, or still being checked (a read that
        // failed leaves it so), is read about again, every few seconds.
        const timer = setInterval(() => {
            if (!live || !takes || loading) return;
            if (shouldReread(kept.locals, cid, Date.now(), performance.now() - lastReadAt, readFailures)) void loadNewest();
        }, 1_000);
        const onVisible = () => noteSeen();
        document.addEventListener('visibilitychange', onVisible);
        // Marking resumes when the window gets focus again.
        window.addEventListener('focus', onVisible);
        window.addEventListener('blur', onVisible);
        return () => {
            closed = true;
            seq++;
            contentCache.clear();
            clearInterval(timer);
            document.removeEventListener('visibilitychange', onVisible);
            window.removeEventListener('focus', onVisible);
            window.removeEventListener('blur', onVisible);
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
        {#each elsewhere as e (e.id)}
            <div class="note">{e.text}</div>
        {/each}
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
                    {@const content = contentOf(m)}
                    {@const st = deliveryState(m, { relayHeld: !!connection.relay_held })}
                    {@const stText = deliveryText(st, { notice: m.local?.notice, title })}
                    <div
                        class="message"
                        class:sent={m.direction === 'out'}
                        class:received={m.direction !== 'out'}
                        use:watchUnread={m.direction === 'in' && !m.read ? m.message_id : ''}
                    >
                        <div
                            class="bubble"
                            class:pending={st === 'sending' || st === 'unconfirmed'}
                            class:check={st === 'expired' || st === 'unreadable' || st === 'unsent'}
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
                                            <div class="line">{LINE_ISOLATE.start}{#each line as p}{#if 'href' in p}<button type="button" class="link" onclick={() => void openLink(p)}>{p.text}</button>{:else}{p.text}{/if}{/each}{LINE_ISOLATE.end}</div>
                                        {/each}
                                    </div>
                                {/if}
                            {/if}
                        </div>
                        <div class="meta">
                            {#if when(m.sent_at)}<span class="time">{when(m.sent_at)}</span>{/if}
                            {#if stText}
                                <span
                                    aria-live="polite"
                                    class="state"
                                    class:unconfirmed={st === 'unconfirmed' || st === 'held'}
                                    class:check={st === 'expired' || st === 'unreadable' || st === 'unsent'}
                                    class:read={st === 'read'}
                                >{stText}</span>
                            {/if}
                        </div>
                        {#if st === 'unconfirmed' && m.local?.pending_id}
                            <div class="actions">
                                <!-- NEW TEXT (owner approval needed): "Try again" -->
                                <button type="button" onclick={() => void retry(m.key)} disabled={sending}>Try again</button>
                            </div>
                        {:else if st === 'unsent'}
                            <div class="actions">
                                <!-- NEW TEXT (owner approval needed): "Edit", "Remove" -->
                                <!-- Focusable while the box has text (it does nothing then), with the hint said and shown. -->
                                <button
                                    type="button"
                                    onclick={() => editUnsent(m.key)}
                                    aria-disabled={draft !== '' ? 'true' : undefined}
                                    aria-describedby={draft !== '' ? `${m.key}-edit-hint` : undefined}
                                >Edit</button>
                                <button type="button" onclick={() => removeUnsent(m.key)}>Remove</button>
                            </div>
                            {#if draft !== ''}
                                <div class="hint" id="{m.key}-edit-hint">{EDIT_NEEDS_EMPTY_BOX}</div>
                            {/if}
                        {/if}
                    </div>
                {/each}
            </div>

            <div aria-live="polite">
                {#if linkError}
                    <div class="compose-note error">{linkError}</div>
                {/if}
            </div>

            <form class="compose" onsubmit={(e) => { e.preventDefault(); void send(); }}>
                <!-- NEW TEXT (owner approval needed): the box's label, "Message" -->
                <textarea
                    bind:value={kept.drafts[cid]}
                    onkeydown={onKeydown}
                    rows="2"
                    aria-label="Message"
                ></textarea>
                <button type="submit" disabled={sending || !canSend(draft)}>{sending ? DELIVERY_TEXT.sending : 'Send'}</button>
            </form>
            <div aria-live="polite">
                {#if draftBytes > MAX_TEXT_BYTES}
                    <div class="compose-note error">{tooLongText(draftBytes)}</div>
                {/if}
                {#if sendError}
                    <div class="compose-note error">{sendError}</div>
                {/if}
            </div>
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

    .actions { display: flex; gap: 6px; margin-top: 3px; }
    .actions button {
        background: none;
        border: 1px solid var(--border);
        border-radius: 4px;
        padding: 2px 8px;
        font-size: 0.8em;
        cursor: pointer;
        color: inherit;
    }
    .actions button:disabled,
    .actions button[aria-disabled='true'] { opacity: 0.5; cursor: default; }
    .hint { font-size: 0.75em; color: var(--text-muted); margin-top: 2px; }

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

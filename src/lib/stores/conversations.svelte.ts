// The conversations' own sends and drafts, per connection (DESKTOP-REWORK-PLAN
// Phase 5, 5.3), kept while a conversation is closed or the session isn't
// live: a send left unconfirmed may still be carried out, and an answer may
// come back to a closed view. In memory only: message text is never stored
// or logged.
import type { Local, SyncEv } from '../conversationView.js';
import { pruneKept } from '../conversationView.js';

export const kept = $state<{
    locals: Local[];
    drafts: Record<string, string>;
    errors: Record<string, string>;
    /** A send or a retry in flight, per connection: Send waits for it. */
    sending: Record<string, boolean>;
    /** Receipts for messages not known yet (an answer still on its way). */
    held: Array<{ ev: SyncEv; at: number }>;
}>({ locals: [], drafts: {}, errors: {}, sending: {}, held: [] });

/**
 * The list was read: sends, drafts and errors of connections it no longer
 * has are dropped. Only on a list the vault answered (a failed or not-live
 * list says nothing about which connections remain).
 */
export function keepOnly(ids: Set<string>): void {
    const p = pruneKept(kept.locals, kept.drafts, ids);
    kept.locals = p.locals;
    kept.drafts = p.drafts;
    kept.errors = Object.fromEntries(Object.entries(kept.errors).filter(([k]) => ids.has(k)));
}

/** A reset (log out: the pairing is wiped and the link's kept send is gone): everything goes. */
export function clearKept(): void {
    kept.locals = [];
    kept.drafts = {};
    kept.errors = {};
    kept.sending = {};
    kept.held = [];
}

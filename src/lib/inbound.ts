// What the vault sends this desktop for the connection and message views
// (DESKTOP-REWORK-PLAN Phase 5, 5.1), as `src-tauri/src/link/inbound.rs`
// emits it: the `vault:inbound` event. The shapes are VAULT-MESSAGING
// 0.94.1's (§10.1, §10.5). Message text is plaintext: keep it in memory
// only, never in storage or logs.

/** The Tauri event name. */
export const INBOUND_EVENT = 'vault:inbound';

/** An attachment as a desktop sees it (§10.5.1): no thumb, no name. */
export interface AttachmentView {
  att_id: string;
  kind: string;
  mime?: string;
  size: number;
  width: number;
  height: number;
  /** Outgoing: preparing | sending | delivered | failed; incoming: fetching | stored | failed. */
  state: string;
  reason?: string;
}

/** `message.new` (§10.5). */
export interface MessageNew {
  connection_id: string;
  message_id: string;
  direction: 'in' | 'out';
  /** `""` for an attachment without a caption. */
  text: string;
  sent_at: string;
  delivered: boolean;
  read: boolean;
  attachment: AttachmentView | null;
}

/** A `sync.event` of a kind the views follow (§10.1). */
export interface SyncEvent {
  kind:
    | 'message.receipt'
    | 'message.read'
    | 'message.attachment'
    | 'connection.changed'
    | 'connection.request'
    | 'block.added'
    | 'block.removed'
    | 'feed.updated'
    | 'feed.deleted'
    | 'owner_check';
  /** The event's other members: ids and states, never secret values. */
  members: Record<string, unknown>;
}

export type Inbound = { type: 'message.new'; body: MessageNew } | { type: 'sync.event'; body: SyncEvent };

/** One delivery. With `resync`, some messages were lost or dropped (a hold,
 *  a lock, an ended session, an unreadable message): read the views again. */
export interface InboundBatch {
  messages: Inbound[];
  resync: boolean;
}

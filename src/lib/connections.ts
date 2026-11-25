// The vault's connections as a desktop reads them (DESKTOP-REWORK-PLAN
// Phase 5, 5.2): VAULT-MESSAGING 0.94.1 §10.4's `<connection>` and
// `connection.request.list`. Read-only: a desktop never creates or accepts
// a connection (§3.1); it may decline a request.
//
// These hold personal data (names, profiles): keep them in memory, never
// in storage or logs.

/** A profile as a connection shares it (§10.8). */
export interface ConnectionProfile {
  version: number;
  first_name: string;
  last_name: string;
  ik: string;
  name?: string;
  photo?: string;
  items: unknown[];
}

/** `<connection>` (§10.4). */
export interface Connection {
  id: string;
  kind: 'connection';
  state: 'active';
  name: string;
  ik: string;
  profile: ConnectionProfile;
  created_at: string;
  last_active_at: string;
  version: number;
  alias: string;
  note: string;
  tags: string[];
  favorite: boolean;
  archived: boolean;
  /** `service` connections take no messages (§10.5). */
  peer_kind?: string;
  asks: { muted: boolean; paused: boolean };
  /** Set while the peer's vault is at a new address: messages without a
   *  `delivered` receipt are shown as held, never as sent (§3.4.2 RK14). */
  relay_held?: { since: string };
}

/** `connection.list` as the backend passes it on: a connection that didn't
 *  check out is left out and counted in `unreadable`. */
export interface ConnectionList {
  connections: Connection[];
  unreadable?: number;
}

/** An incoming request (`connection.request.list`). */
export interface IncomingRequest {
  pending_id: string;
  invite_id: string;
  sas: string;
  remote: string;
  state: string;
  peer_approved: boolean;
  created_at: string;
  exp: string;
  profile?: ConnectionProfile;
  introduced_by?: string;
}

/** An outgoing request (`connection.request.list`). */
export interface OutgoingRequest {
  connection_id: string;
  sas?: string;
  ik?: string;
  remote: string;
  state: string;
  peer_approved: boolean;
  created_at: string;
  exp: string;
  name?: string;
  peer_kind?: string;
  introduced_by?: string;
}

/** A request that didn't check out: kept by its id only, so it can still
 *  be declined. */
export interface UnreadableIncomingRequest {
  pending_id: string;
  unreadable: true;
}

/** An outgoing request that didn't check out, kept by its id only. */
export interface UnreadableOutgoingRequest {
  connection_id: string;
  unreadable: true;
}

export interface ConnectionRequests {
  incoming: (IncomingRequest | UnreadableIncomingRequest)[];
  outgoing: (OutgoingRequest | UnreadableOutgoingRequest)[];
}

/** What every vault command answers (`VaultOpResponse` in Rust). */
export interface VaultOpResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  /** Stable codes: no_session, held, locked, unknown, unconfirmed (it may
   *  still happen), clock, not_saved, not_sent, refused, forbidden,
   *  not_found, vault_error, malformed, bad_argument. */
  error_code?: string;
  pending_approval: boolean;
}

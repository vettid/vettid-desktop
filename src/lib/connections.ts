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
  asks: { muted: boolean; paused: boolean; cooldowns: unknown };
  /** Set while the peer's vault is at a new address: messages without a
   *  `delivered` receipt are shown as held, never as sent (§3.4.2 RK14). */
  relay_held?: { since: string };
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

export interface ConnectionRequests {
  incoming: IncomingRequest[];
  outgoing: OutgoingRequest[];
}

/** What every vault command answers (`VaultOpResponse` in Rust). */
export interface VaultOpResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  /** Stable codes: no_session, held, locked, unknown, unreachable, refused,
   *  forbidden, not_found, vault_error, malformed. */
  error_code?: string;
  pending_approval: boolean;
}

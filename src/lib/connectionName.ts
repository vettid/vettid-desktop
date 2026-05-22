// Display-name helper for connections — shared by every surface that
// renders one (ConnectionsList, Conversation, ConnectionDetail,
// RequestPaymentSheet).
//
// This was copy-pasted as a local `peerName` in all four components.
// Every copy did `c.peer_guid.slice(0, 8)` unguarded, and `peer_guid`
// is `omitempty` server-side — absent for the system connection,
// device pairings, and agents. The first such connection in the list
// threw `TypeError: undefined is not an object`, which aborted the
// whole `{#each}` render and left the Connections tab stuck on
// "Loading connections…". One helper, guarded once, kills the bug
// everywhere and stops it being reintroduced by the next copy-paste.
import type { Connection } from './types';

/**
 * Best-effort human label for a connection. Never throws, never empty.
 * Preference order:
 *   1. peer's profile name (first + last)
 *   2. peer_alias — the vault's user-facing connection label
 *   3. label — legacy field, kept only as a fallback
 *   4. first 8 chars of peer_guid, when present
 *   5. "Connection" — final fallback
 */
export function peerName(c: Connection): string {
    const p = c.peer_profile;
    const full = `${p?.first_name ?? ''} ${p?.last_name ?? ''}`.trim();
    const guidShort = c.peer_guid ? c.peer_guid.slice(0, 8) : '';
    return full || c.peer_alias || c.label || guidShort || 'Connection';
}

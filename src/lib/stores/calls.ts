import { writable, type Writable } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import { invoke } from '@tauri-apps/api/core';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CallType = 'audio' | 'video';
export type CallDirection = 'incoming' | 'outgoing';
export type CallState =
    | 'ringing'      // incoming, awaiting accept/decline
    | 'dialing'      // outgoing, awaiting answer
    | 'connecting'   // accepted, ICE/SDP negotiation in flight
    | 'active'       // media flowing
    | 'ended';

export interface ActiveCall {
    callId: string;
    peerGuid: string;
    peerDisplayName: string;
    callType: CallType;
    direction: CallDirection;
    state: CallState;
    startedAt: number;
    /** When the call moved to `active` — used to derive elapsed duration. */
    activeSince?: number;
    error?: string;
}

interface CallEventPayload {
    // CallEvent root fields (vault-manager/calls.go::CallEvent)
    call_id?: string;
    caller_id?: string;
    caller_display_name?: string;
    call_type?: CallType;
    sdp_offer?: string;
    sdp_answer?: string;
    candidate?: unknown;
    reason?: string;
    // `payload` is the inner blob from a `call.signal` request — the
    // desktop puts SDP/ICE under it (see commands/calls.rs::send_signal).
    payload?: {
        sdp?: string;
        candidate?: unknown;
        [k: string]: unknown;
    };
}

/**
 * Most recent SDP offer received with `call.offer`. Held outside the
 * call store so the accept handler can hand it to `answer_call` — the
 * Rust side needs the full SDP to drive the WebRTC `setRemoteDescription`
 * step before generating an answer.
 *
 * The vault-routed flow delivers the offer in a separate event from
 * `call.incoming` (which carries no SDP), so this buffer may briefly
 * be null between ringing and offer arrival. Practically the offer
 * arrives within a few ms of incoming since the caller publishes both
 * back-to-back.
 */
let pendingRemoteOffer: string | null = null;

// ---------------------------------------------------------------------------
// Stores
// ---------------------------------------------------------------------------

export const currentCallStore: Writable<ActiveCall | null> = writable(null);

let initialized = false;

/**
 * Subscribe to `vault:call-event` from the Phase 1 listener and translate
 * each subject suffix into a state-machine transition. Subjects we
 * handle (vault-side names from `vault-manager/calls.go`):
 *
 *   - `call.incoming`   — peer is ringing us (no SDP yet)
 *   - `call.offer`      — peer's SDP offer (buffer for `acceptCall`)
 *   - `call.accepted`   — peer accepted our outgoing call (SDP answer at root)
 *   - `call.rejected`   — peer rejected our outgoing call
 *   - `call.candidate`  — peer ICE candidate (forward to active session)
 *   - `call.cancelled`  — peer hung up before connect
 *   - `call.ended`      — peer hung up after connect
 *
 * Subject format from the vault: `OwnerSpace.{ownGuid}.forApp.call.{action}`
 * — we pull the action from the suffix. Payload is base64 JSON of the
 * full CallEvent.
 */
export function initCallListener(): void {
    if (initialized) return;
    initialized = true;

    // WebRTC peer-connection state changes (only fires when --features
    // webrtc is compiled in). Promotes us from `connecting` to `active` once
    // ICE establishes, and back to `ended` on disconnect/failure.
    listen<{ call_id: string; state: string }>('vault:call-state', (event) => {
        const { call_id, state } = event.payload;
        currentCallStore.update((c) => {
            if (!c || c.callId !== call_id) return c;
            switch (state) {
                case 'active':
                    return { ...c, state: 'active', activeSince: Date.now() };
                case 'connecting':
                    return { ...c, state: 'connecting' };
                case 'failed':
                case 'disconnected':
                case 'ended':
                    return { ...c, state: 'ended', error: state === 'failed' ? 'connection failed' : undefined };
                default:
                    return c;
            }
        });
    });

    listen<{ subject: string; payload_b64: string }>('vault:call-event', (event) => {
        const subject = event.payload?.subject ?? '';
        const action = subject.split('.forApp.call.')[1] ?? '';
        const payload = decodePayload(event.payload?.payload_b64);
        if (!payload) return;

        switch (action) {
            case 'incoming': {
                if (!payload.call_id) return;
                // call.incoming carries no SDP; clear any stale buffer
                // so we don't accept with an offer from a previous call.
                pendingRemoteOffer = null;
                currentCallStore.set({
                    callId: payload.call_id,
                    peerGuid: payload.caller_id ?? '',
                    peerDisplayName: payload.caller_display_name ?? 'Unknown',
                    callType: payload.call_type ?? 'audio',
                    direction: 'incoming',
                    state: 'ringing',
                    startedAt: Date.now(),
                });
                break;
            }
            case 'offer': {
                // Peer's SDP offer arrived (separate event from `incoming`
                // in the vault-routed flow). Buffer for `acceptCall`.
                const sdp = payload.payload?.sdp;
                if (typeof sdp === 'string' && sdp.length > 0) {
                    pendingRemoteOffer = sdp;
                }
                break;
            }
            case 'accepted': {
                currentCallStore.update((c) => {
                    if (!c || c.callId !== payload.call_id) return c;
                    return { ...c, state: 'connecting' };
                });
                // Hand the remote SDP answer to the WebRTC layer. The
                // backend listener also intercepts `call.accepted` to
                // bind the per-call shared_secret to the cryptor — that
                // path is independent of this emit (secret never enters
                // JS). Backend no-ops on apply_remote_answer without
                // the webrtc feature.
                if (payload.sdp_answer) {
                    invoke('apply_remote_answer', { sdp: payload.sdp_answer })
                        .catch((e) => console.warn('apply_remote_answer failed:', e));
                }
                break;
            }
            case 'rejected':
            case 'ended':
            case 'cancelled': {
                pendingRemoteOffer = null;
                currentCallStore.update((c) => {
                    if (!c || (payload.call_id && c.callId !== payload.call_id)) return c;
                    return { ...c, state: 'ended', error: payload.reason };
                });
                // Auto-clear after a brief delay so the UI can show "Call ended".
                setTimeout(() => {
                    currentCallStore.update((c) =>
                        c && c.state === 'ended' ? null : c,
                    );
                }, 1500);
                break;
            }
            case 'candidate': {
                // Forward the remote ICE candidate to the active session.
                // Vault-routed flow: candidate sits inside `payload.payload`
                // (the call.signal blob); legacy direct-peer events used
                // `payload.candidate` at root. Accept both for safety.
                const candidate = payload.payload?.candidate ?? payload.candidate;
                if (candidate !== undefined && candidate !== null) {
                    invoke('apply_remote_ice', { candidate })
                        .catch((e) => console.warn('apply_remote_ice failed:', e));
                }
                break;
            }
            default:
                console.debug('Unhandled call action:', action);
        }
    });
}

function decodePayload(b64?: string): CallEventPayload | null {
    if (!b64) return null;
    try {
        const json = atob(b64);
        return JSON.parse(json) as CallEventPayload;
    } catch (e) {
        console.warn('Failed to decode call payload:', e);
        return null;
    }
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

export async function placeCall(
    connectionId: string,
    peerGuid: string,
    displayName: string,
    callType: CallType,
): Promise<void> {
    const resp = await invoke<{ success: boolean; call_id?: string; error?: string }>(
        'initiate_call',
        {
            connectionId,
            peerGuid,
            displayName,
            callType,
        },
    );
    if (!resp.success || !resp.call_id) {
        throw new Error(resp.error ?? 'Failed to initiate call');
    }
    currentCallStore.set({
        callId: resp.call_id,
        peerGuid,
        peerDisplayName: displayName,
        callType,
        direction: 'outgoing',
        state: 'dialing',
        startedAt: Date.now(),
    });
}

export async function acceptCall(call: ActiveCall): Promise<void> {
    currentCallStore.update((c) =>
        c && c.callId === call.callId ? { ...c, state: 'connecting' } : c,
    );
    const sdpOffer = pendingRemoteOffer;
    pendingRemoteOffer = null;
    try {
        await invoke('answer_call', {
            callId: call.callId,
            peerGuid: call.peerGuid,
            sdpOffer,
        });
        // In WebRTC mode the `vault:call-state` listener will promote us to
        // `active` once ICE establishes. In signaling-only mode that
        // event never fires — flip to `active` after a brief delay so
        // the UX still works for testing.
        if (!sdpOffer) {
            currentCallStore.update((c) =>
                c && c.callId === call.callId
                    ? { ...c, state: 'active', activeSince: Date.now() }
                    : c,
            );
        }
    } catch (e) {
        currentCallStore.update((c) =>
            c && c.callId === call.callId
                ? { ...c, state: 'ended', error: String(e) }
                : c,
        );
    }
}

export async function declineCall(call: ActiveCall): Promise<void> {
    try {
        await invoke('decline_call', {
            callId: call.callId,
            reason: 'declined',
        });
    } finally {
        currentCallStore.set(null);
    }
}

export async function hangUp(call: ActiveCall): Promise<void> {
    try {
        await invoke('end_call', { callId: call.callId });
    } finally {
        currentCallStore.set(null);
    }
}

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
    call_id?: string;
    caller_id?: string;
    caller_display_name?: string;
    call_type?: CallType;
    sdp_offer?: string;
    sdp_answer?: string;
    candidate?: unknown;
    reason?: string;
}

/**
 * Most recent SDP offer received with `call.incoming`. Held outside the
 * call store so the accept handler can hand it to `answer_call` — the
 * Rust side needs the full SDP to drive the WebRTC `setRemoteDescription`
 * step before generating an answer.
 */
let pendingRemoteOffer: string | null = null;

// ---------------------------------------------------------------------------
// Stores
// ---------------------------------------------------------------------------

export const currentCallStore: Writable<ActiveCall | null> = writable(null);

let initialized = false;

/**
 * Subscribe to `vault:call-event` from the Phase 1 listener and translate
 * call.incoming / answered / ended into state machine transitions.
 *
 * Subject format from the vault: `OwnerSpace.{ownGuid}.forApp.call.{action}`
 * — we pull the action from the suffix. Payload is base64 JSON.
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
                pendingRemoteOffer = payload.sdp_offer ?? null;
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
            case 'answered': {
                currentCallStore.update((c) => {
                    if (!c || c.callId !== payload.call_id) return c;
                    return { ...c, state: 'connecting' };
                });
                // Hand the remote SDP answer to the WebRTC layer (the
                // Rust side no-ops if the webrtc feature isn't compiled
                // in, so this stays safe in signaling-only builds).
                if (payload.sdp_answer) {
                    invoke('apply_remote_answer', { sdp: payload.sdp_answer })
                        .catch((e) => console.warn('apply_remote_answer failed:', e));
                }
                break;
            }
            case 'ended':
            case 'declined':
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
                // Backend no-ops without the webrtc feature.
                if (payload.candidate) {
                    invoke('apply_remote_ice', { candidate: payload.candidate })
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
    targetGuid: string,
    displayName: string,
    callType: CallType,
): Promise<void> {
    // SDP offer is generated from the WebRTC stack — null until that's wired.
    const resp = await invoke<{ success: boolean; call_id?: string; error?: string }>(
        'initiate_call',
        { targetGuid, displayName, callType, sdpOffer: null },
    );
    if (!resp.success || !resp.call_id) {
        throw new Error(resp.error ?? 'Failed to initiate call');
    }
    currentCallStore.set({
        callId: resp.call_id,
        peerGuid: targetGuid,
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
            sdpOffer,         // backend uses this to drive setRemoteDescription
            sdpAnswer: null,  // backend generates the answer when webrtc is on
        });
        // In WebRTC mode the `vault:call-state` listener will promote us to
        // `active` once ICE establishes. In signaling-only mode, that event
        // never fires — flip to `active` after a brief delay so the UX still
        // works for testing.
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
            peerGuid: call.peerGuid,
        });
    } finally {
        currentCallStore.set(null);
    }
}

export async function hangUp(call: ActiveCall): Promise<void> {
    try {
        await invoke('end_call', {
            callId: call.callId,
            peerGuid: call.peerGuid,
        });
    } finally {
        currentCallStore.set(null);
    }
}

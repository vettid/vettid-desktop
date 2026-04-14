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

    listen<{ subject: string; payload_b64: string }>('vault:call-event', (event) => {
        const subject = event.payload?.subject ?? '';
        const action = subject.split('.forApp.call.')[1] ?? '';
        const payload = decodePayload(event.payload?.payload_b64);
        if (!payload) return;

        switch (action) {
            case 'incoming': {
                if (!payload.call_id) return;
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
                // Once a real WebRTC stack is wired, this is where we'd
                // setRemoteDescription with payload.sdp_answer and let ICE
                // complete to push us into `active`.
                break;
            }
            case 'ended':
            case 'declined':
            case 'cancelled': {
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
                // ICE candidate from peer — would feed RTCPeerConnection
                // .addIceCandidate once WebRTC is wired.
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
    try {
        await invoke('answer_call', {
            callId: call.callId,
            peerGuid: call.peerGuid,
            sdpAnswer: null, // populated once WebRTC is wired
        });
        // Move straight to active for now — without media, "active" simply
        // means "both ends agreed to the call." Real activation will wait
        // for ICE completion.
        currentCallStore.update((c) =>
            c && c.callId === call.callId
                ? { ...c, state: 'active', activeSince: Date.now() }
                : c,
        );
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

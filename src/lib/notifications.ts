// ---------------------------------------------------------------------------
// Desktop notifications
// ---------------------------------------------------------------------------
//
// Wires OS desktop notifications to the vault event surface. Rework-plan
// §6 item 24 — four triggers: incoming message, incoming call, phone-
// approval request, and session expiry.
//
// Notifications fire only when the app window is NOT focused. When the
// window is in front of the user the in-app UI (call overlay, conversation
// view, pending-approval sheet, session pill) already conveys the event —
// a duplicate OS toast would just be noise. This is the conventional
// desktop-app rule and keeps notifications meaningful.

import { listen } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from '@tauri-apps/plugin-notification';
import { currentCallStore, type ActiveCall } from './stores/calls';
import { sessionStore, type SessionState } from './stores/session';

let initialized = false;
// null = not yet checked; resolved to a boolean on first use.
let permissionGranted: boolean | null = null;

/** Resolve (and cache) notification permission. On Linux libnotify needs
 *  no grant; on macOS the first call surfaces the system prompt. */
async function ensurePermission(): Promise<boolean> {
  if (permissionGranted !== null) return permissionGranted;
  let granted = await isPermissionGranted();
  if (!granted) {
    granted = (await requestPermission()) === 'granted';
  }
  permissionGranted = granted;
  return granted;
}

async function windowFocused(): Promise<boolean> {
  try {
    return await getCurrentWindow().isFocused();
  } catch {
    // If focus state is unknowable, err toward notifying.
    return false;
  }
}

async function notify(title: string, body: string): Promise<void> {
  if (await windowFocused()) return;
  if (!(await ensurePermission())) return;
  sendNotification({ title, body });
}

/**
 * Initialise desktop notifications. Idempotent — call once at app start
 * (App.svelte onMount), alongside initCallListener / initNatsListener.
 */
export function initNotifications(): void {
  if (initialized) return;
  initialized = true;

  // --- Incoming message ------------------------------------------------
  // The push payload is connection-encrypted and not decoded here, so the
  // toast is intentionally content-free — which is also the right call
  // for privacy (no message text on the lock screen).
  listen('vault:message-received', () => {
    void notify('New message', 'You have a new message in VettID.');
  });

  // --- Phone-approval request -----------------------------------------
  // Fired when a phone-required op is awaiting approval — a nudge for the
  // user who kicked off an op then switched away to pick up their phone.
  listen('vault:operation-pending-approval', () => {
    void notify('Approval needed', 'Open VettID on your phone to approve.');
  });

  // --- Incoming call ---------------------------------------------------
  // Notify once per call, when it first appears as a ringing inbound
  // call. Tracking the last-notified id avoids re-firing as the same
  // call moves through its state machine.
  let lastNotifiedCallId: string | null = null;
  currentCallStore.subscribe((call: ActiveCall | null) => {
    if (!call) {
      lastNotifiedCallId = null;
      return;
    }
    if (
      call.direction === 'incoming' &&
      call.state === 'ringing' &&
      call.callId !== lastNotifiedCallId
    ) {
      lastNotifiedCallId = call.callId;
      const who = call.peerDisplayName || 'Someone';
      const kind = call.callType === 'video' ? 'video call' : 'call';
      void notify('Incoming call', `${who} is calling you (${kind}).`);
    }
  });

  // --- Session expiry --------------------------------------------------
  // Notify when an active session lapses. `everActive` gates out the
  // launch-time `inactive → expired` transition (a vault that is merely
  // locked at startup never had a session to expire).
  let everActive = false;
  let lastSessionState: SessionState['state'] | null = null;
  sessionStore.subscribe((s: SessionState) => {
    const prev = lastSessionState;
    lastSessionState = s.state;
    if (s.state === 'active') everActive = true;
    if (prev === null || s.state === prev) return;
    if (s.state === 'expired' && everActive) {
      void notify('Session expired', 'Start a new VettID session to continue.');
    }
  });
}

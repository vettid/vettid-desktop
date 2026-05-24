// events.ts — helpers for the vault:* Tauri event envelopes emitted by
// the Rust listener in src-tauri/src/nats/listener.rs.
//
// Every event payload is uniformly shaped as
//   { subject: string, payload_b64: string }
// where `payload_b64` is the base64-encoded JSON bytes of the original
// NATS message body. Parsing the inner JSON is needed for any listener
// that wants to filter by event-specific fields (e.g. connection_id) —
// the subject alone no longer carries the connection_id since the vault
// switched to per-device fan-out
// (MessageSpace.{owner}.forApp.device.{conn}.{event}).

export interface AppEventEnvelope {
  subject: string;
  payload_b64: string;
}

/**
 * Decode an event envelope's base64-encoded JSON payload. Returns null
 * if the payload is missing or unparseable — callers should treat that
 * as "skip this event" rather than throwing, since one malformed push
 * shouldn't break the listener for subsequent events.
 */
export function decodeEventPayload<T = unknown>(
  envelope: AppEventEnvelope | undefined,
): T | null {
  const b64 = envelope?.payload_b64;
  if (!b64) return null;
  try {
    // atob returns a binary string; we then need UTF-8 decode because
    // the JSON may contain multi-byte chars (names, addresses, etc.).
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    const text = new TextDecoder('utf-8').decode(bytes);
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

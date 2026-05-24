// features.ts — single source of truth for desktop feature flags.
//
// These are compile-time constants the bundler will tree-shake when
// false — they're meant as scaffolding for half-built features, not
// runtime toggles. Flip and rebuild.

/**
 * Voice + video calling. Currently disabled because the SFrame frame
 * cryptor interop with Android's libwebrtc has not been verified
 * end-to-end. When false, outgoing call buttons are hidden, the
 * global CallOverlay does not mount, and incoming `call.incoming`
 * events still fire on the store but no UI reacts to them.
 *
 * Re-enable by flipping this to true after the desktop ↔ Android
 * call interop test passes (see sframe-cryptor.md Phase E).
 */
export const CALLS_ENABLED = false;

// The fingerprint of a connection's pinned `ik` (VAULT-MESSAGING 0.94.1
// §10.8 "What apps show", vector in §16), kept free of Svelte and Tauri for
// `npm test`:
//
//   fp = SHA-256("vettid/vms/2/ik-fp" || ik)    # ik: the 32 raw bytes
//
// shown as its first 16 bytes in lowercase hex, in 8 groups of 4 digits
// separated by spaces.

const LABEL = new TextEncoder().encode('vettid/vms/2/ik-fp');
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * The 32 raw bytes of `ik` from its standard base64 with padding (§10.1:
 * non-canonical base64 is refused), or `null` for anything else.
 * @param {unknown} b64
 * @returns {Uint8Array | null}
 */
export function decodeIk(b64) {
  // 32 bytes: 43 symbols and one '='; the last symbol's low 2 bits are padding and must be zero.
  if (typeof b64 !== 'string' || !/^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/.test(b64)) return null;
  const out = new Uint8Array(32);
  let acc = 0;
  let bits = 0;
  let n = 0;
  for (let i = 0; i < 43; i++) {
    acc = ((acc & 0xff) << 6) | B64.indexOf(b64[i]);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[n++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

/**
 * The fingerprint as shown, or `null` when `ik` is not the standard base64
 * of 32 bytes: then no fingerprint is shown, never one of something else.
 * @param {unknown} ikB64
 * @returns {Promise<string | null>}
 */
export async function ikFingerprint(ikB64) {
  const ik = decodeIk(ikB64);
  if (!ik) return null;
  const input = new Uint8Array(LABEL.length + ik.length);
  input.set(LABEL, 0);
  input.set(ik, LABEL.length);
  const fp = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  const hex = Array.from(fp.subarray(0, 16), (b) => b.toString(16).padStart(2, '0')).join('');
  return hex.match(/.{4}/g)?.join(' ') ?? null;
}

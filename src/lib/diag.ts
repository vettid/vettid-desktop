// WEDGE-DIAG (2026-05-22): frontend breadcrumb sink for the Connections
// freeze hunt. `feLog` fire-and-forgets a line to the Rust `frontend_log`
// command so Svelte breadcrumbs land in the same `cargo tauri dev` stdout
// as the Rust WEDGE-DIAG lines — one continuous freeze timeline.
//
// The invoke is dispatched synchronously to the IPC channel, so a line
// queued immediately before a JS-thread freeze still reaches Rust; only
// its (ignored) response is lost. The `console.warn` mirror survives even
// if the invoke can't dispatch.
//
// Remove this whole file (and its callers + the Rust `frontend_log`
// command + the WEDGE-DIAG logs) once the freeze is fixed.
import { invoke } from '@tauri-apps/api/core';

export function feLog(msg: string): void {
    const line = `${performance.now().toFixed(0)}ms ${msg}`;
    console.warn('[FE-DIAG]', line);
    try {
        void invoke('frontend_log', { msg: line }).catch(() => {});
    } catch {
        /* invoke unavailable (e.g. non-Tauri context) — console line stands */
    }
}

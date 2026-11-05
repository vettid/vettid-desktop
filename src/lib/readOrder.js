// The order of the session store's reads of the backend (#77), kept free
// of Svelte and Tauri for `npm test`. Reads overlap: the 30 s poll, the
// backend's `vault:changed` event, a window focus, the re-read when an
// Open runs out, End session. One begun before a change (a lock) can
// resolve after the read that change triggered, and must not put the
// store back as it was.
//
// The backend stamps each published snapshot with a counter (`seq` in
// `get_session_info`): an answer older than the last one applied is
// dropped. A read that failed (no link open, so no counter) is ordered by
// when it began: dropped if a read begun after it was already applied.

/**
 * @returns {{ begin: () => number, accept: (readNo: number, seq: number | null) => boolean }}
 */
export function createReadOrder() {
  let begun = 0;
  /** @type {{ readNo: number, seq: number | null }} */
  let last = { readNo: 0, seq: null };
  return {
    /** A read begins: its number. */
    begin() {
      begun += 1;
      return begun;
    },
    /**
     * Read `readNo` answered, with the snapshot's counter `seq` (`null` if
     * it failed): whether to apply it. If so, it becomes the last applied.
     */
    accept(readNo, seq) {
      const ok = seq !== null && last.seq !== null ? seq >= last.seq : readNo >= last.readNo;
      if (ok) last = { readNo, seq };
      return ok;
    },
  };
}

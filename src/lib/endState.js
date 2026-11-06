// What the session store does with an End session's state after each read
// of the backend (#80), kept free of Svelte and Tauri for `npm test`.

/**
 * After a read.
 * - `wasPending`, `nowPending`: whether an End session was waiting for the
 *   vault before and after it (`nowPending` null: the read couldn't tell,
 *   for example with no link open).
 * - `notice`: the notice on screen. `endNotice`: the not-confirmed notice
 *   End session showed (null if none).
 * - `confirmed`: the backend settled the stored end and the vault confirmed
 *   it. `settledNotice`: it settled without that confirmation, and says
 *   what to show instead.
 *
 * A pending end that stops being pending is cleared only when confirmed:
 * a stored end going away is not, on its own, a confirmation. With no
 * confirmation the person is told what the backend says, or the notice
 * stays. A read that couldn't tell changes nothing.
 *
 * @param {{ wasPending: boolean, nowPending: boolean | null, notice: string | null, endNotice: string | null, confirmed?: boolean, settledNotice?: string | null }} s
 * @returns {{ notice: string | null, endNotice: string | null, pending: boolean }}
 */
export function afterRead({ wasPending, nowPending, notice, endNotice, confirmed = false, settledNotice = null }) {
  if (nowPending === null) return { notice, endNotice, pending: wasPending };
  if (wasPending && !nowPending) {
    const ours = notice === null || notice === endNotice;
    if (confirmed) return { notice: ours && endNotice !== null ? null : notice, endNotice: null, pending: false };
    if (settledNotice !== null) return { notice: ours ? settledNotice : notice, endNotice: null, pending: false };
    return { notice, endNotice: null, pending: false };
  }
  return { notice, endNotice, pending: nowPending };
}

/**
 * What End session's own return leaves (#80): `pending` is the backend's
 * `end_pending` after it. Still pending: its notice is kept as the end's own,
 * to go only on a later confirmation. Not pending: the outcome is final,
 * and nothing is left to clear later.
 *
 * @param {{ notice: string | null, pending: boolean }} s
 * @returns {{ endNotice: string | null, pending: boolean }}
 */
export function afterEnd({ notice, pending }) {
  return pending ? { endNotice: notice, pending: true } : { endNotice: null, pending: false };
}

/**
 * A read of the backend that started before the latest End session press
 * (`startSeq` older than `nowSeq`) describes the session before it: dropped
 * whole, so it can't undo the press (#80, lead review L4).
 *
 * @param {number} startSeq
 * @param {number} nowSeq
 * @returns {boolean}
 */
export function readIsStale(startSeq, nowSeq) {
  return startSeq !== nowSeq;
}

// What the session store does with an End session's state after each read
// of the backend (#80), kept free of Svelte and Tauri for `npm test`.

/**
 * After a read: `wasPending` and `nowPending` are whether an End session
 * was waiting for the vault before and after it; `notice` is the notice on
 * screen; `endNotice` is the not-confirmed notice End session showed (null
 * if none). Once a pending end is no longer pending, the vault has answered
 * it, so that notice ("may still be open") no longer applies and goes.
 * Any other notice stays. A read that couldn't tell (`nowPending` null, the
 * link is gone) changes nothing: the notice is never cleared on a guess.
 *
 * @param {{ wasPending: boolean, nowPending: boolean | null, notice: string | null, endNotice: string | null }} s
 * @returns {{ notice: string | null, endNotice: string | null, pending: boolean }}
 */
export function afterRead({ wasPending, nowPending, notice, endNotice }) {
  if (nowPending === null) return { notice, endNotice, pending: false };
  if (wasPending && !nowPending && endNotice !== null) {
    return { notice: notice === endNotice ? null : notice, endNotice: null, pending: false };
  }
  return { notice, endNotice, pending: nowPending };
}

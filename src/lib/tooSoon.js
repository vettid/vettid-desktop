// The too-soon notice with its time (#83), in the reader's own locale:
// 12-hour "10:48 AM" in the US, 24-hour "10:48" in most of Europe. Kept
// free of Svelte and Tauri for `npm test`.

/**
 * @param {number} retryAt Unix seconds (the backend rounds it up to the minute)
 * @param {string | undefined} [locale] For tests; the computer's own by default
 * @returns {string}
 */
export function tooSoonNotice(retryAt, locale) {
  const time = new Intl.DateTimeFormat(locale, { hour: 'numeric', minute: '2-digit' }).format(new Date(retryAt * 1000));
  return `Your vault asks this desktop to wait before asking again. You can ask again at ${time}.`;
}

/**
 * A failed pairing or session response's notice (#83): the too-soon one
 * with its time when the backend sent `retry_at`, otherwise its `error`.
 * Both the pairing and the Start-a-new-session screens use it, so they
 * agree.
 *
 * @param {{ retry_at?: number | null, error?: string | null }} result
 * @param {string} [fallback]
 * @param {string | undefined} [locale]
 * @returns {string}
 */
export function noticeOf(result, fallback = '', locale) {
  return result.retry_at ? tooSoonNotice(result.retry_at, locale) : (result.error || fallback);
}

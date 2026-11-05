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

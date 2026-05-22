// Small shared time helper. The connections list shows "2h ago" /
// "3d ago" / "Mar 12" style relative times for the last-activity
// subtitle; the conversation header shows full date/time. One helper
// here keeps the formatting consistent.

/**
 * "in the last day" relative time, falling back to a short absolute
 * date (e.g. "Mar 12") once a week has passed. Returns an empty
 * string for missing input so callers can safely use the result in
 * templates without guarding.
 */
export function formatRelativeOrAbsolute(iso: string | undefined | null): string {
    if (!iso) return '';
    const t = Date.parse(iso);
    if (Number.isNaN(t)) return '';
    const diffSec = Math.max(0, (Date.now() - t) / 1000);

    if (diffSec < 60) return 'just now';
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86_400) return `${Math.floor(diffSec / 3600)}h ago`;
    if (diffSec < 7 * 86_400) return `${Math.floor(diffSec / 86_400)}d ago`;

    // Older than a week → fall back to a short absolute date.
    return new Date(t).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

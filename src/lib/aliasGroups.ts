// Alias-card grouping — the desktop counterpart of the Android client's
// buildDisplayGroups. Within a category, items the user filed under one
// alias collapse into a single card; an item with no alias — or the
// only item carrying its alias — stays a lone single.

export interface AliasGroup<T> {
  /** Stable key — the alias for a group, the item id for a single. */
  key: string;
  /** Alias name for a group; null for a lone ungrouped item. */
  label: string | null;
  items: T[];
}

/**
 * Groups `items` by alias. Items sharing a non-blank alias (2+ of them)
 * become one group; an item with no alias, or the only one carrying its
 * alias, stays a lone single. First occurrence drives ordering, so the
 * caller's sort is preserved.
 */
export function buildAliasGroups<T>(
  items: T[],
  aliasOf: (t: T) => string,
  idOf: (t: T) => string,
): AliasGroup<T>[] {
  const result: AliasGroup<T>[] = [];
  const seen = new Set<string>();
  for (const item of items) {
    const id = idOf(item);
    if (seen.has(id)) continue;
    const alias = (aliasOf(item) ?? '').trim();
    const members = alias ? items.filter((x) => (aliasOf(x) ?? '').trim() === alias) : [item];
    if (alias && members.length > 1) {
      if (seen.has(alias)) continue;
      seen.add(alias);
      for (const m of members) seen.add(idOf(m));
      result.push({ key: alias, label: alias, items: members });
    } else {
      seen.add(id);
      result.push({ key: id, label: null, items: [item] });
    }
  }
  return result;
}

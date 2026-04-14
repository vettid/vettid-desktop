import { writable, type Writable } from 'svelte/store';
import type { Connection } from '../types';

/**
 * Currently-selected connection for detail / conversation views. `null` means
 * no detail view is open and the parent should render its list view. Setting
 * this is the single source of truth for "did the user click into a peer?"
 */
export const selectedConnectionStore: Writable<Connection | null> = writable(null);

export function clearSelectedConnection(): void {
    selectedConnectionStore.set(null);
}

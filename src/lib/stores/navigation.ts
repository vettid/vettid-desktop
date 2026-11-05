import { writable, type Writable } from 'svelte/store';
import type { Connection } from '../types';

/**
 * Currently-selected connection for detail / conversation views. `null` means
 * no detail view is open and the parent should render its list view. Setting
 * this is the single source of truth for "did the user click into a peer?"
 */
export const selectedConnectionStore: Writable<Connection | null> = writable(null);

/**
 * True while the pairing view holds a pairing under way: from Connect until
 * the person leaves its result (Continue or Try Again). Routing leaves the
 * pairing view alone meanwhile (#79). Set only by the pairing view.
 */
export const pairingHeld: Writable<boolean> = writable(false);

export function clearSelectedConnection(): void {
    selectedConnectionStore.set(null);
}

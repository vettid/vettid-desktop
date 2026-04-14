import { writable } from 'svelte/store';

export type Theme = 'light' | 'dark' | 'auto';

const STORAGE_KEY = 'vettid:theme';

function readInitial(): Theme {
    if (typeof localStorage === 'undefined') return 'auto';
    const v = localStorage.getItem(STORAGE_KEY) as Theme | null;
    return v === 'light' || v === 'dark' || v === 'auto' ? v : 'auto';
}

export const themeStore = writable<Theme>(readInitial());

/**
 * Apply the chosen theme to the document root. We toggle a `theme-light` or
 * `theme-dark` class so CSS can swap variables; `auto` follows the OS via
 * `prefers-color-scheme`.
 */
function apply(theme: Theme): void {
    if (typeof document === 'undefined') return;
    const root = document.documentElement;
    root.classList.remove('theme-light', 'theme-dark');
    if (theme === 'light') root.classList.add('theme-light');
    else if (theme === 'dark') root.classList.add('theme-dark');
    // `auto` leaves both classes off — CSS @media handles it.
}

themeStore.subscribe((theme) => {
    apply(theme);
    if (typeof localStorage !== 'undefined') {
        localStorage.setItem(STORAGE_KEY, theme);
    }
});

export function setTheme(theme: Theme): void {
    themeStore.set(theme);
}

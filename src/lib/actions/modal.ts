// Accessibility wiring shared by every dialog / sheet. Apply to the
// dialog element itself (not the backdrop):
//
//   <div class="modal" role="dialog" aria-modal="true"
//        use:modal={{ onEscape: close }}>
//
// What it does:
//   - Moves focus into the modal on open — to the element marked
//     `data-autofocus`, else the first focusable element.
//   - Traps Tab / Shift+Tab inside the modal so focus can't reach the
//     page behind it.
//   - Calls `onEscape` on the Escape key — wire it to the caller's
//     close handler.
//   - Restores focus to whatever held it before the modal opened, so
//     a keyboard user lands back where they were.
import type { Action } from 'svelte/action';

const FOCUSABLE = [
    'a[href]',
    'button:not([disabled])',
    'input:not([disabled])',
    'select:not([disabled])',
    'textarea:not([disabled])',
    '[tabindex]:not([tabindex="-1"])',
].join(',');

export interface ModalOptions {
    /** Called on Escape — wire this to the caller's close handler. */
    onEscape?: () => void;
}

export const modal: Action<HTMLElement, ModalOptions | undefined> = (
    node,
    options,
) => {
    let opts: ModalOptions = options ?? {};
    const restoreTo = document.activeElement as HTMLElement | null;

    // Laid-out focusables only — skips anything an `{#if}` left in the
    // tree but `display:none`'d.
    const focusable = (): HTMLElement[] =>
        Array.from(node.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
            (el) => el.getClientRects().length > 0,
        );

    function onKeydown(e: KeyboardEvent) {
        if (e.key === 'Escape') {
            e.preventDefault();
            opts.onEscape?.();
            return;
        }
        if (e.key !== 'Tab') return;
        const items = focusable();
        if (items.length === 0) {
            e.preventDefault();
            return;
        }
        const first = items[0];
        const last = items[items.length - 1];
        const active = document.activeElement as HTMLElement | null;
        if (e.shiftKey) {
            if (active === first || !node.contains(active)) {
                e.preventDefault();
                last.focus();
            }
        } else if (active === last || !node.contains(active)) {
            e.preventDefault();
            first.focus();
        }
    }

    // Move focus into the modal now that it's in the DOM.
    const initial =
        node.querySelector<HTMLElement>('[data-autofocus]') ?? focusable()[0];
    initial?.focus();

    // Capture phase so the trap wins over any background key handler.
    document.addEventListener('keydown', onKeydown, true);

    return {
        update(next: ModalOptions | undefined) {
            opts = next ?? {};
        },
        destroy() {
            document.removeEventListener('keydown', onKeydown, true);
            // Only pull focus back if it's loose (on <body>) or still in
            // the modal being torn down — never yank it from somewhere
            // the user has since moved to.
            const active = document.activeElement;
            if (!active || active === document.body || node.contains(active)) {
                restoreTo?.focus?.();
            }
        },
    };
};

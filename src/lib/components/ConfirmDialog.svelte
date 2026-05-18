<script lang="ts">
  /**
   * Modal confirmation dialog matching the desktop's gold-on-warm-
   * black palette. Replaces `window.confirm()` because Tauri's
   * underlying WebKit renders that as a system dialog titled
   * "JavaScript - tauri://localhost" — unbranded and unsettling.
   *
   * Caller controls visibility via the `open` prop (two-way bound
   * with $bindable). Click backdrop or Cancel to dismiss; Confirm
   * fires `onConfirm` and the parent closes the dialog.
   */
  let {
    open = $bindable(false),
    title = 'Confirm',
    message = '',
    confirmLabel = 'Confirm',
    cancelLabel = 'Cancel',
    tone = 'default',
    onConfirm,
  } = $props<{
    open: boolean;
    title?: string;
    message?: string;
    confirmLabel?: string;
    cancelLabel?: string;
    /** "danger" tints the Confirm button red for destructive actions. */
    tone?: 'default' | 'danger';
    onConfirm: () => void;
  }>();

  function close() {
    open = false;
  }

  function confirm() {
    onConfirm();
    close();
  }

  // Close on Escape — matches OS-level dialog behavior so the user
  // doesn't have to mouse over to Cancel for a quick dismiss.
  function handleKey(e: KeyboardEvent) {
    if (!open) return;
    if (e.key === 'Escape') close();
    if (e.key === 'Enter') confirm();
  }
</script>

<svelte:window onkeydown={handleKey} />

{#if open}
  <!-- Backdrop — click to dismiss. -->
  <div class="backdrop" onclick={close} role="presentation"></div>

  <div class="dialog" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
    <h2 id="confirm-title">{title}</h2>
    {#if message}<p class="message">{message}</p>{/if}
    <div class="actions">
      <button class="btn ghost" onclick={close}>{cancelLabel}</button>
      <button
        class="btn primary"
        class:danger={tone === 'danger'}
        onclick={confirm}
        autofocus
      >{confirmLabel}</button>
    </div>
  </div>
{/if}

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
    z-index: 100;
    backdrop-filter: blur(2px);
  }
  .dialog {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    z-index: 101;
    background: var(--surface);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 12px;
    padding: 20px 22px;
    min-width: 340px;
    max-width: 440px;
    box-shadow: 0 18px 50px rgba(0, 0, 0, 0.5);
  }
  h2 {
    font-size: 1.05rem;
    margin: 0 0 8px;
    color: var(--text);
    font-weight: 600;
  }
  .message {
    color: var(--text-muted);
    font-size: 0.9rem;
    line-height: 1.5;
    margin: 0 0 18px;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }
  .btn {
    padding: 8px 16px;
    border-radius: 6px;
    cursor: pointer;
    font: inherit;
    font-size: 0.9rem;
    border: 1px solid transparent;
  }
  .btn.ghost {
    background: transparent;
    color: var(--text-muted);
    border-color: rgba(255, 255, 255, 0.1);
  }
  .btn.ghost:hover { background: rgba(255, 255, 255, 0.05); color: var(--text); }
  .btn.primary {
    background: var(--accent);
    color: #1a1a1a;
    font-weight: 500;
  }
  .btn.primary:hover { background: var(--accent-hover); }
  .btn.primary.danger {
    background: rgba(244, 67, 54, 0.85);
    color: white;
  }
  .btn.primary.danger:hover { background: rgba(244, 67, 54, 1); }
</style>

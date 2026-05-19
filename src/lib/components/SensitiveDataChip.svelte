<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { onDestroy } from 'svelte';
  import { secretsUnlockStore, isSecretsUnlocked } from '../stores/secrets';

  // Session-wide gate for sensitive vault data. One source of truth
  // for the lock state — every tab reads from it instead of running
  // its own approval flow. Three states:
  //
  //   Locked   → tap to request phone approval (default)
  //   Pending  → vault sent the approval request to the phone; chip
  //              shows a spinner + elapsed time + Cancel
  //   Unlocked → grant active; shows mm:ss remaining + a Lock-now ✕
  //
  // Lock-now is client-only for now — clears the local mirror so the
  // UI re-hides Reveal buttons. The vault-side grant times out on its
  // own (SecretsUnlockedUntil). A future enclave change can add an
  // explicit `secret.lock-session` op for a hard server-side revoke.

  let pending = $state(false);
  let pendingRequestId = $state<string | null>(null);
  let pendingStartedAt = $state(0);
  let pendingElapsed = $state(0);
  let tickerId: ReturnType<typeof setInterval> | null = null;

  let unlockState = $derived($secretsUnlockStore);
  let unlocked = $derived(isSecretsUnlocked(unlockState));

  // Countdown shown on the chip while unlocked. Derived from the
  // store's unix-seconds timestamp; re-evaluated each tick.
  let nowSec = $state(Math.floor(Date.now() / 1000));
  let secondsRemaining = $derived(Math.max(0, unlockState.unlockedUntil - nowSec));
  let remainingLabel = $derived.by(() => {
    if (secondsRemaining <= 0) return '';
    const m = Math.floor(secondsRemaining / 60);
    const s = secondsRemaining % 60;
    return `${m}:${s.toString().padStart(2, '0')}`;
  });

  // Ticker for the countdown. Started while unlocked, stopped when
  // not — avoids running a 1s interval in the background when there's
  // nothing to count.
  $effect(() => {
    if (unlocked) {
      tickerId = setInterval(() => {
        nowSec = Math.floor(Date.now() / 1000);
      }, 1000);
      return () => {
        if (tickerId) clearInterval(tickerId);
        tickerId = null;
      };
    }
  });

  // Auto-clear the grant the instant the countdown hits zero so the
  // chip flips back to Locked without waiting for a fresh request to
  // be made.
  $effect(() => {
    if (unlockState.unlockedUntil > 0 && secondsRemaining === 0) {
      secretsUnlockStore.set({ unlockedUntil: 0, pending: false, error: null });
    }
  });

  // Listen for the vault's pending_approval ack so the chip can
  // switch into the "Waiting for phone" state with an elapsed timer.
  // The Secrets/Wallets tabs no longer carry their own banner — this
  // chip is the single status surface for sensitive-data access.
  let unlistenPending: UnlistenFn | null = null;
  $effect(() => {
    listen<any>('vault:operation-pending-approval', (e) => {
      const payload = e.payload ?? {};
      if (payload.operation !== 'secret.unlock-session') return;
      pendingRequestId = payload.request_id ?? null;
      pendingStartedAt = Date.now();
      pendingElapsed = 0;
    }).then((fn) => { unlistenPending = fn; });

    return () => {
      if (unlistenPending) unlistenPending();
    };
  });

  // Separate ticker for the pending elapsed counter — only runs
  // while pending.
  $effect(() => {
    if (pendingRequestId && pending) {
      const id = setInterval(() => {
        pendingElapsed = Math.floor((Date.now() - pendingStartedAt) / 1000);
      }, 500);
      return () => clearInterval(id);
    }
  });

  function clearPendingState() {
    pendingRequestId = null;
    pendingStartedAt = 0;
    pendingElapsed = 0;
  }

  async function requestUnlock() {
    if (unlocked || pending) return;
    pending = true;
    secretsUnlockStore.update((s) => ({ ...s, pending: true, error: null }));
    try {
      const resp: any = await invoke('request_secrets_unlock');
      clearPendingState();
      if (resp?.success && resp?.data?.unlocked_until) {
        const until = Number(resp.data.unlocked_until);
        secretsUnlockStore.set({ unlockedUntil: until, pending: false, error: null });
        return;
      }
      const errMsg = resp?.error || (resp?.data?.status === 'denied'
        ? 'You denied the approval on your phone.'
        : 'Approval did not complete.');
      secretsUnlockStore.update((s) => ({ ...s, pending: false, error: errMsg }));
    } catch (e) {
      clearPendingState();
      const msg = String(e);
      let friendly = msg;
      if (msg.includes('Phone approval timed out')) friendly = 'Phone approval timed out. Try again when you have your phone handy.';
      else if (msg.includes('cancelled')) friendly = 'Approval cancelled';
      else if (msg.includes('did not acknowledge')) friendly = 'Vault is not responding — try again in a moment.';
      secretsUnlockStore.update((s) => ({ ...s, pending: false, error: friendly }));
    } finally {
      pending = false;
    }
  }

  async function cancelPending() {
    if (!pendingRequestId) return;
    const rid = pendingRequestId;
    clearPendingState();
    try { await invoke('cancel_pending_operation', { requestId: rid }); } catch (_) {}
    secretsUnlockStore.update((s) => ({ ...s, pending: false, error: 'Approval cancelled' }));
    pending = false;
  }

  function lockNow() {
    secretsUnlockStore.set({ unlockedUntil: 0, pending: false, error: null });
  }

  onDestroy(() => {
    if (unlistenPending) unlistenPending();
    if (tickerId) clearInterval(tickerId);
  });
</script>

<div class="chip-wrap">
  {#if pending}
    <button class="chip pending" onclick={cancelPending} title="Cancel approval request">
      <span class="spinner-sm"></span>
      <span class="label">
        <span class="title">Waiting for phone…</span>
        <span class="meta">{pendingElapsed}s · tap to cancel</span>
      </span>
    </button>
  {:else if unlocked}
    <div class="chip unlocked" role="status">
      <span class="icon">🔓</span>
      <span class="label">
        <span class="title">Unlocked</span>
        <span class="meta">{remainingLabel} remaining</span>
      </span>
      <button class="lock-btn" onclick={lockNow} title="Lock now" aria-label="Lock now">✕</button>
    </div>
  {:else}
    <button class="chip locked" onclick={requestUnlock} title="Tap to request phone approval to view sensitive data">
      <span class="icon">🔒</span>
      <span class="label">
        <span class="title">Sensitive Data</span>
        <span class="meta">Tap to unlock</span>
      </span>
    </button>
  {/if}

  {#if unlockState.error && !pending}
    <div class="chip-error">{unlockState.error}</div>
  {/if}
</div>

<style>
  .chip-wrap {
    display: flex;
    flex-direction: column;
    align-items: stretch;
    gap: 6px;
    min-width: 200px;
  }

  .chip {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    padding: 8px 12px;
    border-radius: 999px;
    font: inherit;
    cursor: pointer;
    transition: background-color 0.15s, border-color 0.15s;
    border: 1px solid rgba(255, 255, 255, 0.1);
    background: rgba(255, 255, 255, 0.04);
    color: var(--text);
  }
  .chip.locked:hover {
    background: rgba(255, 255, 255, 0.08);
    border-color: rgba(255, 255, 255, 0.15);
  }
  .chip.unlocked {
    background: rgba(64, 196, 99, 0.12);
    border-color: rgba(64, 196, 99, 0.3);
    cursor: default;
  }
  .chip.pending {
    background: rgba(105, 180, 255, 0.12);
    border-color: rgba(105, 180, 255, 0.3);
  }
  .chip.pending:hover {
    background: rgba(105, 180, 255, 0.18);
  }

  .icon { font-size: 1.05rem; line-height: 1; }

  .label {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    line-height: 1.2;
  }
  .title {
    font-size: 0.85rem;
    font-weight: 500;
  }
  .meta {
    font-size: 0.7rem;
    color: var(--text-muted);
  }

  .lock-btn {
    margin-left: 6px;
    background: transparent;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    font-size: 0.85rem;
    padding: 2px 6px;
    border-radius: 4px;
  }
  .lock-btn:hover {
    background: rgba(255, 255, 255, 0.08);
    color: var(--text);
  }

  .spinner-sm {
    width: 14px;
    height: 14px;
    border: 2px solid rgba(255, 255, 255, 0.15);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: chip-spin 0.8s linear infinite;
    flex-shrink: 0;
  }
  @keyframes chip-spin { to { transform: rotate(360deg); } }

  .chip-error {
    font-size: 0.75rem;
    color: var(--error);
    background: rgba(244, 67, 54, 0.08);
    border: 1px solid rgba(244, 67, 54, 0.2);
    border-radius: 6px;
    padding: 4px 10px;
  }
</style>

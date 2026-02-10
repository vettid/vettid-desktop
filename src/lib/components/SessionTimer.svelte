<script lang="ts">
  import { sessionStore } from '../stores/session';
  import { onDestroy } from 'svelte';

  let remaining = $state(0);
  let warn30 = $derived(remaining > 0 && remaining <= 1800);
  let warn5 = $derived(remaining > 0 && remaining <= 300);

  const interval = setInterval(() => {
    const s = $sessionStore;
    if (s.expiresAt) {
      remaining = Math.max(0, Math.floor(s.expiresAt - Date.now() / 1000));
    }
  }, 1000);

  onDestroy(() => clearInterval(interval));

  function formatTime(seconds: number): string {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  }
</script>

<div class="timer" class:warn30 class:warn5>
  {formatTime(remaining)}
</div>

<style>
  .timer {
    font-variant-numeric: tabular-nums;
    padding: 2px 8px;
    border-radius: 4px;
    background: rgba(76, 175, 80, 0.15);
    color: var(--success);
    font-size: 0.8rem;
  }

  .warn30 {
    background: rgba(255, 152, 0, 0.15);
    color: var(--warning);
  }

  .warn5 {
    background: rgba(244, 67, 54, 0.15);
    color: var(--error);
    animation: pulse 1s ease-in-out infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.6; }
  }
</style>

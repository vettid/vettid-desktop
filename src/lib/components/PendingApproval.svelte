<script lang="ts">
  interface Props {
    operation: string;
    requestId: string;
  }

  let { operation, requestId }: Props = $props();
  let elapsed = $state(0);

  const interval = setInterval(() => elapsed++, 1000);

  import { onDestroy } from 'svelte';
  onDestroy(() => clearInterval(interval));
</script>

<div class="pending">
  <div class="icon">
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <rect x="5" y="2" width="14" height="20" rx="2" />
      <line x1="12" y1="18" x2="12" y2="18.01" stroke-width="3" stroke-linecap="round" />
    </svg>
  </div>
  <div class="info">
    <p class="title">Approve on your phone</p>
    <p class="detail">Operation: <strong>{operation}</strong></p>
    <p class="timer">Waiting... {elapsed}s</p>
  </div>
  <div class="spinner"></div>
</div>

<style>
  .pending {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 16px 20px;
    background: rgba(255, 152, 0, 0.1);
    border: 1px solid rgba(255, 152, 0, 0.3);
    border-radius: 8px;
    margin: 12px 0;
  }

  .icon {
    color: var(--warning);
    flex-shrink: 0;
  }

  .info {
    flex: 1;
  }

  .title {
    font-weight: 600;
    margin-bottom: 4px;
  }

  .detail, .timer {
    font-size: 0.85rem;
    color: var(--text-muted);
  }

  .spinner {
    width: 24px;
    height: 24px;
    border: 2px solid rgba(255, 152, 0, 0.3);
    border-top-color: var(--warning);
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }
</style>

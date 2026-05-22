<script lang="ts">
  // Connection status pill — color + label per status. Shared by the
  // connections list, the detail header, and anywhere else a
  // Connection's status surfaces.
  interface Props {
    status: 'pending' | 'active' | 'revoked' | 'expired';
  }
  let { status }: Props = $props();
</script>

<span class="chip {status}">{status}</span>

<style>
  .chip {
    font-size: 0.7rem;
    padding: 2px 8px;
    border-radius: 999px;
    text-transform: capitalize;
    letter-spacing: 0.02em;
    font-weight: 500;
    flex-shrink: 0;
    white-space: nowrap;
  }
  .chip.active  { background: rgba(76, 175, 80, 0.16);   color: #6bc77b;        border: 1px solid rgba(76, 175, 80, 0.30); }
  .chip.pending { background: rgba(255, 152, 0, 0.16);   color: #ffb74d;        border: 1px solid rgba(255, 152, 0, 0.30); }
  .chip.revoked { background: rgba(244, 67, 54, 0.16);   color: #ef5350;        border: 1px solid rgba(244, 67, 54, 0.30); }
  .chip.expired { background: rgba(120, 113, 108, 0.18); color: var(--text-muted); border: 1px solid rgba(120, 113, 108, 0.30); }
</style>

<script lang="ts">
  // Two-pane Connections shell (Phase B of CONNECTIONS-REWORK-PLAN).
  // ConnectionsList sits on the left and stays mounted across
  // selections — picking a connection no longer remounts the list or
  // refires connection.list. The right pane shows the selected
  // connection's workspace (header + Messages/Profile tabs) or an
  // empty-state hint when nothing is selected.
  import { selectedConnectionStore } from '../stores/navigation';
  import ConnectionsList from './vault/ConnectionsList.svelte';
  import ConnectionWorkspace from './vault/ConnectionWorkspace.svelte';

  let selected = $derived($selectedConnectionStore);
</script>

<div class="connections-shell">
  <aside class="list-pane">
    <ConnectionsList />
  </aside>
  <section class="detail-pane">
    {#if selected}
      <ConnectionWorkspace connection={selected} />
    {:else}
      <div class="empty">
        <div class="empty-icon" aria-hidden="true">👥</div>
        <p class="empty-title">Select a connection</p>
        <p class="empty-hint">
          Pick someone from the list on the left to view your
          conversation, profile, and call controls.
        </p>
      </div>
    {/if}
  </section>
</div>

<style>
  .connections-shell {
    flex: 1;
    display: flex;
    min-height: 0;
    padding: 16px 20px;
    gap: 16px;
  }
  .list-pane {
    width: 320px;
    flex-shrink: 0;
    display: flex;
    flex-direction: column;
    min-height: 0;
  }
  .detail-pane {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    border: 1px solid var(--border);
    border-radius: 10px;
    background: var(--surface);
    overflow: hidden;
  }
  .empty {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    color: var(--text-muted);
    padding: 32px 24px;
  }
  .empty-icon { font-size: 2.6rem; opacity: 0.4; margin-bottom: 8px; }
  .empty-title { font-size: 1.05rem; color: var(--text); margin: 0; font-weight: 500; }
  .empty-hint { font-size: 0.85rem; margin-top: 6px; max-width: 320px; line-height: 1.45; }
</style>

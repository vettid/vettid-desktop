<script lang="ts">
  // Phase 5 — Connections surface. Three sub-views, one shell:
  //
  //   ConnectionsList  → no connection selected
  //   Conversation     → a connection is selected, mode = chat
  //   ConnectionDetail → a connection is selected, mode = profile
  //
  // selectedConnectionStore is the single source of truth for "is a
  // connection open?". `mode` only matters while one is — it toggles
  // between the conversation and the peer's profile/manage card.
  import { selectedConnectionStore } from '../stores/navigation';
  import ConnectionsList from './vault/ConnectionsList.svelte';
  import Conversation from './vault/Conversation.svelte';
  import ConnectionDetail from './vault/ConnectionDetail.svelte';
  import { feLog } from '../diag';

  let selected = $derived($selectedConnectionStore);
  let mode = $state<'conversation' | 'detail'>('conversation');

  // WEDGE-DIAG (2026-05-22): which sub-view the shell resolves to.
  $effect(() => {
    feLog(`Connections shell: selected=${selected ? 'yes' : 'no'} mode=${mode}`);
  });

  // Land on the conversation every time a (different) connection is
  // opened from the list. The effect tracks `selected` only — flipping
  // `mode` from within Conversation/Detail doesn't re-trigger it, so
  // there's no fight between this reset and the in-view toggle.
  $effect(() => {
    if (selected) mode = 'conversation';
  });
</script>

<div class="connections-shell">
  {#if !selected}
    <ConnectionsList />
  {:else if mode === 'conversation'}
    <Conversation connection={selected} onShowProfile={() => (mode = 'detail')} />
  {:else}
    <ConnectionDetail connection={selected} onBack={() => (mode = 'conversation')} />
  {/if}
</div>

<style>
  .connections-shell {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
    padding: 16px 20px;
  }
</style>

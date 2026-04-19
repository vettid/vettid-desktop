<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { sessionStore, type SessionState, refreshSessionFromBackend } from './lib/stores/session';
  import { natsStore, initNatsListener } from './lib/stores/nats';
  import { themeStore } from './lib/stores/theme';
  import { initCallListener } from './lib/stores/calls';
  import Pairing from './lib/views/Pairing.svelte';
  import SessionExpired from './lib/views/SessionExpired.svelte';
  import Session from './lib/views/Session.svelte';
  import Vault from './lib/views/Vault.svelte';
  import Settings from './lib/views/Settings.svelte';
  import StatusBar from './lib/components/StatusBar.svelte';
  import CallOverlay from './lib/components/CallOverlay.svelte';

  let currentView = $state<'pairing' | 'expired' | 'session' | 'vault' | 'settings'>('pairing');
  let sessionState: SessionState = $derived($sessionStore);
  let pollTimer: ReturnType<typeof setInterval> | null = null;

  onMount(() => {
    initNatsListener();
    initCallListener();
    const unsub = themeStore.subscribe(() => {});
    unsub();

    // Resolve the session state once on launch, then every 30s. `is_active`
    // may flip to false between polls as the wall-clock expires; the effect
    // below routes the user to SessionExpired when that happens.
    refreshSessionFromBackend();
    pollTimer = setInterval(refreshSessionFromBackend, 30_000);
  });

  onDestroy(() => {
    if (pollTimer) clearInterval(pollTimer);
  });

  // Auto-navigate based on session state
  $effect(() => {
    if (sessionState.state === 'active') {
      if (currentView === 'pairing' || currentView === 'expired') currentView = 'vault';
    } else if (sessionState.state === 'expired') {
      // Registered but session ran out — show the extension flow, not pairing.
      if (currentView !== 'settings') currentView = 'expired';
    } else if (sessionState.state === 'inactive') {
      currentView = 'pairing';
    }
  });
</script>

<div class="app">
  <nav class="sidebar">
    <div class="logo">
      <h2>VettID</h2>
      <span class="badge">Desktop</span>
    </div>

    <div class="nav-items">
      <button
        class="nav-item"
        class:active={currentView === 'pairing'}
        onclick={() => currentView = 'pairing'}
      >
        Pair Device
      </button>
      <button
        class="nav-item"
        class:active={currentView === 'vault'}
        disabled={sessionState.state !== 'active'}
        onclick={() => currentView = 'vault'}
      >
        Vault
      </button>
      <button
        class="nav-item"
        class:active={currentView === 'session'}
        disabled={sessionState.state === 'inactive'}
        onclick={() => currentView = 'session'}
      >
        Session
      </button>
      <button
        class="nav-item"
        class:active={currentView === 'settings'}
        onclick={() => currentView = 'settings'}
      >
        Settings
      </button>
    </div>
  </nav>

  <main class="content">
    <StatusBar />

    {#if currentView === 'pairing'}
      <Pairing />
    {:else if currentView === 'expired'}
      <SessionExpired />
    {:else if currentView === 'vault'}
      <Vault />
    {:else if currentView === 'session'}
      <Session />
    {:else if currentView === 'settings'}
      <Settings />
    {/if}
  </main>

  <!-- Global call overlay — present in any view -->
  <CallOverlay />
</div>

<style>
  .app {
    display: flex;
    height: 100vh;
  }

  .sidebar {
    width: 200px;
    background: var(--surface);
    padding: 20px 0;
    display: flex;
    flex-direction: column;
    border-right: 1px solid rgba(255, 255, 255, 0.05);
  }

  .logo {
    padding: 0 20px 20px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .logo h2 {
    font-size: 1.2rem;
    font-weight: 600;
  }

  .badge {
    font-size: 0.65rem;
    background: var(--accent);
    padding: 2px 6px;
    border-radius: 4px;
    text-transform: uppercase;
    font-weight: 600;
  }

  .nav-items {
    padding: 12px 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .nav-item {
    background: none;
    border: none;
    color: var(--text-muted);
    padding: 10px 20px;
    text-align: left;
    cursor: pointer;
    font-size: 0.9rem;
    transition: all 0.15s;
  }

  .nav-item:hover:not(:disabled) {
    background: rgba(255, 255, 255, 0.05);
    color: var(--text);
  }

  .nav-item.active {
    color: var(--text);
    background: rgba(233, 69, 96, 0.1);
    border-left: 3px solid var(--accent);
  }

  .nav-item:disabled {
    opacity: 0.3;
    cursor: not-allowed;
  }

  .content {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow-y: auto;
  }
</style>

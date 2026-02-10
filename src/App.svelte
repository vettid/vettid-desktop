<script lang="ts">
  import { sessionStore, type SessionState } from './lib/stores/session';
  import { natsStore } from './lib/stores/nats';
  import Pairing from './lib/views/Pairing.svelte';
  import Session from './lib/views/Session.svelte';
  import Vault from './lib/views/Vault.svelte';
  import Settings from './lib/views/Settings.svelte';
  import StatusBar from './lib/components/StatusBar.svelte';

  let currentView = $state<'pairing' | 'session' | 'vault' | 'settings'>('pairing');
  let sessionState: SessionState = $derived($sessionStore);

  // Auto-navigate based on session state
  $effect(() => {
    if (sessionState.state === 'active') {
      if (currentView === 'pairing') currentView = 'vault';
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
    {:else if currentView === 'vault'}
      <Vault />
    {:else if currentView === 'session'}
      <Session />
    {:else if currentView === 'settings'}
      <Settings />
    {/if}
  </main>
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

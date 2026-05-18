<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';

  import { sessionStore, type SessionState, refreshSessionFromBackend } from './lib/stores/session';
  import { initNatsListener } from './lib/stores/nats';
  import { themeStore } from './lib/stores/theme';
  import { initCallListener } from './lib/stores/calls';

  import Pairing from './lib/views/Pairing.svelte';
  import SessionExpired from './lib/views/SessionExpired.svelte';
  import Session from './lib/views/Session.svelte';
  import Vault from './lib/views/Vault.svelte';
  import Connections from './lib/views/Connections.svelte';
  import Settings from './lib/views/Settings.svelte';
  import TopBar from './lib/components/TopBar.svelte';
  import CallOverlay from './lib/components/CallOverlay.svelte';

  // Top-level destinations the user navigates between explicitly.
  // Takeover routes (`pairing`, `expired`, `session-detail`) hide the
  // rail entirely — they're full-screen actions, not destinations
  // the user lives in. See DESKTOP-REWORK-PLAN.md §1 for the layout.
  type View =
    | 'pairing'
    | 'expired'
    | 'session-detail'
    | 'vault'
    | 'connections'
    | 'settings';

  let currentView = $state<View>('pairing');
  let sessionState: SessionState = $derived($sessionStore);
  let isRegistered = $state(false);
  let pollTimer: ReturnType<typeof setInterval> | null = null;

  async function refreshRegistration() {
    try {
      const status: any = await invoke('get_status');
      isRegistered = !!status?.is_registered;
    } catch {
      isRegistered = false;
    }
  }

  /**
   * If the desktop is paired (credentials on disk) but the in-memory
   * state is empty, auto-unlock it. Master key comes from the OS
   * keyring (or the machine-bound fallback); no user input.
   */
  async function autoUnlockIfNeeded() {
    if (!isRegistered) return;
    try {
      await invoke('unlock');
    } catch (e) {
      console.warn('Auto-unlock failed:', e);
    }
  }

  onMount(async () => {
    initNatsListener();
    initCallListener();
    const unsub = themeStore.subscribe(() => {});
    unsub();

    await refreshRegistration();
    await autoUnlockIfNeeded();
    await refreshSessionFromBackend();
    pollTimer = setInterval(async () => {
      await refreshRegistration();
      await refreshSessionFromBackend();
    }, 30_000);
  });

  onDestroy(() => {
    if (pollTimer) clearInterval(pollTimer);
  });

  // Auto-routing on state transitions. The user can navigate around
  // freely between Vault / Connections / Settings / Session-detail,
  // but state changes (session expires while you're using the app,
  // etc.) flip the view to the takeover that needs attention.
  //
  // `session-detail` is treated as a real destination, not a
  // takeover — the user clicked the pill explicitly to land there,
  // and we keep them there until they navigate away. Same for
  // Settings / Connections / Vault.
  $effect(() => {
    if (sessionState.state === 'active') {
      // Transition out of pre-session takeovers (pairing / expired)
      // → land on Vault. Already on a real destination → stay.
      if (currentView === 'pairing' || currentView === 'expired') {
        currentView = 'vault';
      }
    } else if (sessionState.state === 'expired' || sessionState.state === 'suspended') {
      // Session ran out (or got revoked from another device). Route
      // to the Start-New-Session takeover. Don't yank the user out
      // of Settings — they might be reading hostname info.
      if (currentView !== 'settings') currentView = 'expired';
    } else if (sessionState.state === 'revoked') {
      // Hard revoke — credentials no longer valid; user has to
      // re-pair. Settings stays accessible so the user can
      // logout + restart cleanly.
      if (currentView !== 'settings') currentView = 'pairing';
    } else if (sessionState.state === 'inactive') {
      if (isRegistered) {
        if (currentView !== 'settings') currentView = 'expired';
      } else {
        currentView = 'pairing';
      }
    }
  });

  /** Session pill click — routes per the state. See plan §1 table. */
  function onSessionPillClick() {
    switch (sessionState.state) {
      case 'active':
        currentView = 'session-detail';
        break;
      case 'suspended':
      case 'expired':
        currentView = 'expired';
        break;
      case 'revoked':
        // Pairing flow is the path back from a revoke. Settings
        // still has Logout if the user wants a clean wipe first.
        currentView = 'pairing';
        break;
      case 'inactive':
      default:
        currentView = isRegistered ? 'expired' : 'pairing';
        break;
    }
  }

  function onSettingsClick() {
    currentView = currentView === 'settings' ? defaultDestination() : 'settings';
  }

  function defaultDestination(): View {
    if (sessionState.state === 'active') return 'vault';
    if (isRegistered) return 'expired';
    return 'pairing';
  }

  // The rail is only useful when there's an active session — the
  // pre-session takeovers hide it to keep the user's attention on
  // the single thing they need to do.
  let railVisible = $derived(sessionState.state === 'active');
</script>

<div class="app">
  <TopBar
    onSessionClick={onSessionPillClick}
    onSettingsClick={onSettingsClick}
    isSettingsActive={currentView === 'settings'}
  />

  <div class="body">
    {#if railVisible}
      <nav class="rail">
        <button
          class="rail-item"
          class:active={currentView === 'vault'}
          onclick={() => currentView = 'vault'}
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="3" width="18" height="18" rx="2" />
            <circle cx="12" cy="12" r="3" />
          </svg>
          <span>Vault</span>
        </button>
        <button
          class="rail-item"
          class:active={currentView === 'connections'}
          onclick={() => currentView = 'connections'}
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="9" cy="7" r="3" />
            <circle cx="17" cy="17" r="3" />
            <path d="M9 10v4a3 3 0 0 0 3 3h2" />
          </svg>
          <span>Connections</span>
        </button>
      </nav>
    {/if}

    <main class="content">
      {#if currentView === 'pairing'}
        <Pairing />
      {:else if currentView === 'expired'}
        <SessionExpired />
      {:else if currentView === 'vault'}
        <Vault />
      {:else if currentView === 'connections'}
        <Connections />
      {:else if currentView === 'session-detail'}
        <Session />
      {:else if currentView === 'settings'}
        <Settings />
      {/if}
    </main>
  </div>

  <!-- Global call overlay — present in any view -->
  <CallOverlay />
</div>

<style>
  .app {
    display: flex;
    flex-direction: column;
    height: 100vh;
  }
  .body {
    flex: 1;
    display: flex;
    overflow: hidden;
  }

  .rail {
    width: 84px;
    background: var(--surface);
    border-right: 1px solid rgba(255, 255, 255, 0.05);
    padding: 12px 8px;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .rail-item {
    background: none;
    border: none;
    color: var(--text-muted);
    padding: 12px 4px;
    border-radius: 8px;
    cursor: pointer;
    font-size: 0.7rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
    transition: background 0.15s, color 0.15s;
  }
  .rail-item:hover {
    background: rgba(255, 255, 255, 0.05);
    color: var(--text);
  }
  .rail-item.active {
    color: var(--accent);
    background: var(--accent-muted);
  }

  .content {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow-y: auto;
  }
</style>

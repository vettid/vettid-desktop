<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';

  import { sessionStore, type SessionState, refreshSessionFromBackend } from './lib/stores/session';
  import { initNatsListener } from './lib/stores/nats';
  import { themeStore } from './lib/stores/theme';
  import { initCallListener } from './lib/stores/calls';
  import { initVaultListeners } from './lib/stores/vault';
  import { initNotifications } from './lib/notifications';
  import { resetSecretsUnlock } from './lib/stores/secrets';

  import Pairing from './lib/views/Pairing.svelte';
  import SessionExpired from './lib/views/SessionExpired.svelte';
  import Session from './lib/views/Session.svelte';
  import Vault from './lib/views/Vault.svelte';
  import Connections from './lib/views/Connections.svelte';
  import Sharing from './lib/views/Sharing.svelte';
  import Settings from './lib/views/Settings.svelte';
  import TopBar from './lib/components/TopBar.svelte';
  import CallOverlay from './lib/components/CallOverlay.svelte';
  import DataGrantApprovalModal from './lib/components/DataGrantApprovalModal.svelte';

  // Top-level destinations the user navigates between explicitly.
  // Takeover routes (`pairing`, `expired`, `session-detail`) hide the
  // rail entirely — they're full-screen actions, not destinations
  // the user lives in. See DESKTOP-REWORK-PLAN.md §1 for the layout.
  type View =
    | 'loading'
    | 'pairing'
    | 'expired'
    | 'session-detail'
    | 'vault'
    | 'connections'
    | 'sharing'
    | 'settings';

  // Start on a neutral loading view, NOT pairing. On launch the
  // backend has to be queried (registration + auto-unlock + session
  // state) before we know where the user belongs; defaulting to
  // 'pairing' flashed the QR-pair screen at an already-paired user
  // with an active session for the ~1s that took. stateResolved gates
  // the routing effect so it can't route off the store's pre-query
  // 'inactive' placeholder.
  let currentView = $state<View>('loading');
  let stateResolved = $state(false);
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
    initVaultListeners();
    initCallListener();
    initNotifications();
    const unsub = themeStore.subscribe(() => {});
    unsub();

    await refreshRegistration();
    await autoUnlockIfNeeded();
    await refreshSessionFromBackend();
    // State is now known — let the routing effect take over from the
    // loading view.
    stateResolved = true;
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
    // Hold on the loading view until the launch-time backend queries
    // have resolved — otherwise we'd route off the session store's
    // pre-query 'inactive' placeholder and flash the pairing screen.
    if (!stateResolved) return;

    if (sessionState.state === 'active') {
      // Transition out of pre-session takeovers (loading / pairing /
      // expired) → land on Connections, the default destination.
      // Already on a real destination → stay.
      if (currentView === 'loading' || currentView === 'pairing' || currentView === 'expired') {
        currentView = 'connections';
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

    // Any non-active state means the prior unlock grant (if any) is
    // meaningless — clear the local mirror so the chip doesn't show
    // a stale "Unlocked" reading or carry an old error across a
    // reconnect/end-session cycle.
    if (sessionState.state !== 'active') {
      resetSecretsUnlock();
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
    if (sessionState.state === 'active') return 'connections';
    if (isRegistered) return 'expired';
    return 'pairing';
  }

  /**
   * Global keyboard shortcuts — Cmd (macOS) or Ctrl (Linux) +
   *   1 → Connections, 2 → Vault, , → Settings.
   * The modifier requirement keeps these clear of text entry, so no
   * input-focus guard is needed. Rail destinations are gated on an
   * active session — the same rule the rail itself follows.
   */
  function handleKeydown(e: KeyboardEvent) {
    if (!stateResolved) return;
    if (!(e.metaKey || e.ctrlKey) || e.shiftKey || e.altKey) return;
    switch (e.key) {
      case '1':
        if (sessionState.state === 'active') {
          currentView = 'connections';
          e.preventDefault();
        }
        break;
      case '2':
        if (sessionState.state === 'active') {
          currentView = 'vault';
          e.preventDefault();
        }
        break;
      case '3':
        if (sessionState.state === 'active') {
          currentView = 'sharing';
          e.preventDefault();
        }
        break;
      case ',':
        onSettingsClick();
        e.preventDefault();
        break;
    }
  }

  // The rail is only useful when there's an active session — the
  // pre-session takeovers hide it to keep the user's attention on
  // the single thing they need to do.
  let railVisible = $derived(sessionState.state === 'active');
</script>

<svelte:window onkeydown={handleKeydown} />

{#if currentView === 'loading'}
  <!-- Launch-time takeover while we query the backend for registration
       + session state. Replaces the old pairing-screen flash. -->
  <div class="loading-screen">
    <div class="loading-spinner"></div>
    <p>Checking your vault session…</p>
  </div>
{:else}
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
          class:active={currentView === 'sharing'}
          onclick={() => currentView = 'sharing'}
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="18" cy="5" r="3" />
            <circle cx="6" cy="12" r="3" />
            <circle cx="18" cy="19" r="3" />
            <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
            <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
          </svg>
          <span>Sharing</span>
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
      {:else if currentView === 'sharing'}
        <Sharing />
      {:else if currentView === 'session-detail'}
        <Session />
      {:else if currentView === 'settings'}
        <Settings />
      {/if}
    </main>
  </div>

  <!-- Global call overlay — present in any view -->
  <CallOverlay />

  <!-- Global data-grant approval modal — auto-appears when a peer
       sends an incoming grant request. -->
  {#if sessionState.state === 'active'}
    <DataGrantApprovalModal />
  {/if}
</div>
{/if}

<style>
  .app {
    display: flex;
    flex-direction: column;
    height: 100vh;
  }
  .loading-screen {
    height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 16px;
    background: var(--bg, #0e0e12);
    color: var(--text-muted, #888);
    font-size: 0.9rem;
  }
  .loading-spinner {
    width: 28px;
    height: 28px;
    border: 3px solid rgba(255, 255, 255, 0.1);
    border-top-color: var(--accent, #6b8afd);
    border-radius: 50%;
    animation: app-spin 0.9s linear infinite;
  }
  @keyframes app-spin {
    to { transform: rotate(360deg); }
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

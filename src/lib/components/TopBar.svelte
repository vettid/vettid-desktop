<script lang="ts">
  import { sessionStore } from '../stores/session';
  import SessionTimer from './SessionTimer.svelte';

  // Hooks the parent wires up so the pill drives view selection.
  // Phase 2 keeps things simple: the pill is a click target that
  // emits a single "go to session" intent. Per the rework plan §1
  // table, the destination depends on the state — paired-but-locked
  // / expired land on Start-New-Session; active lands on a session
  // detail view; not-paired lands on Pairing.
  let { onSessionClick, onSettingsClick, isSettingsActive = false } = $props<{
    onSessionClick: () => void;
    onSettingsClick: () => void;
    isSettingsActive?: boolean;
  }>();

  let session = $derived($sessionStore);

  // The pill's text + color depend on the session state. See plan §1
  // for the full table. We keep this tight: a colored dot + a short
  // label, both always visible.
  let pill = $derived.by(() => {
    switch (session.state) {
      case 'active':
        return { text: 'Active', tone: 'good', showTimer: true };
      case 'suspended':
        return { text: 'Suspended', tone: 'warn', showTimer: false };
      case 'expired':
        return { text: 'Start new session', tone: 'warn', showTimer: false };
      case 'revoked':
        return { text: 'Revoked — re-pair', tone: 'bad', showTimer: false };
      case 'inactive':
      default:
        return { text: 'No session', tone: 'muted', showTimer: false };
    }
  });
</script>

<header class="topbar">
  <div class="brand">
    <span class="logo">VettID</span>
    <span class="badge">Desktop</span>
  </div>

  <button
    class="pill"
    class:good={pill.tone === 'good'}
    class:warn={pill.tone === 'warn'}
    class:bad={pill.tone === 'bad'}
    class:muted={pill.tone === 'muted'}
    onclick={onSessionClick}
  >
    <span class="dot"></span>
    <span class="pill-text">{pill.text}</span>
    {#if pill.showTimer}
      <span class="pill-timer">
        <SessionTimer />
      </span>
    {/if}
  </button>

  <button
    class="gear"
    class:active={isSettingsActive}
    onclick={onSettingsClick}
    aria-label="Settings"
    title="Settings"
  >
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </svg>
  </button>
</header>

<style>
  .topbar {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 10px 20px;
    background: var(--surface);
    border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    min-height: 56px;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .logo {
    font-family: 'Plus Jakarta Sans', 'Inter', sans-serif;
    font-weight: 600;
    font-size: 1.1rem;
    color: var(--text);
    letter-spacing: 0.02em;
  }
  .badge {
    font-size: 0.65rem;
    color: var(--accent);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 600;
  }

  /* Pill — sits in the middle of the bar, click target for the
     whole session-lifecycle flow. Color reflects state per §1. */
  .pill {
    margin: 0 auto;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 6px 14px;
    border-radius: 999px;
    border: 1px solid transparent;
    background: rgba(255, 255, 255, 0.04);
    color: var(--text);
    cursor: pointer;
    font: inherit;
    font-size: 0.85rem;
    transition: background 0.15s, border-color 0.15s;
  }
  .pill:hover { background: rgba(255, 255, 255, 0.07); }

  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--text-muted);
    display: inline-block;
  }
  .pill.good .dot { background: var(--success); }
  .pill.warn .dot { background: var(--warning); }
  .pill.bad  .dot { background: var(--error); }
  .pill.muted .dot { background: var(--text-muted); }

  .pill.good  { border-color: rgba(76, 175, 80, 0.3); }
  .pill.warn  { border-color: rgba(255, 152, 0, 0.4); }
  .pill.bad   { border-color: rgba(244, 67, 54, 0.4); }

  .pill-text  { font-weight: 500; }
  .pill-timer { color: var(--text-muted); font-feature-settings: 'tnum' 1; }

  /* Gear — visual weight matches the pill so they balance. The
     `active` state mirrors a routed nav button so the user knows
     when Settings is the open view. */
  .gear {
    background: transparent;
    border: 1px solid transparent;
    color: var(--text-muted);
    padding: 6px;
    border-radius: 8px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: background 0.15s, color 0.15s, border-color 0.15s;
  }
  .gear:hover {
    background: rgba(255, 255, 255, 0.05);
    color: var(--text);
  }
  .gear.active {
    color: var(--accent);
    border-color: var(--border-accent);
    background: var(--accent-muted);
  }
</style>

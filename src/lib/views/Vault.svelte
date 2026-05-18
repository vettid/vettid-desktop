<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { sessionStore } from '../stores/session';
  import PersonalData from './vault/PersonalData.svelte';

  // Tabbed Vault home — matches the Android app's vault tab layout
  // so the user has the same mental model on either device. Profile
  // preview pinned at the top; tabs (Data / Secrets / Wallets) below.
  // Phase 4 fills Secrets + Wallets with real content.
  type TabId = 'data' | 'secrets' | 'wallets';
  const tabs: { id: TabId; label: string }[] = [
    { id: 'data', label: 'Personal data' },
    { id: 'secrets', label: 'Secrets' },
    { id: 'wallets', label: 'Wallets' },
  ];
  let activeTab = $state<TabId>('data');

  let session = $derived($sessionStore);

  // Profile preview state.
  let firstName = $state('');
  let lastName = $state('');
  let email = $state('');
  let photoBase64 = $state<string | null>(null);
  let secretsCount = $state<number | null>(null);
  let walletsCount = $state<number | null>(null);
  // Header-load flag — flips true once profile.get has come back so
  // the tab content (and especially PersonalData's own fetch) stays
  // un-mounted until the header is rendered. Profile-first was the
  // visible win the user asked for: otherwise the screen sits on a
  // generic "loading" for 20-30s because 5 ops fight the same
  // serialized vault queue.
  let profileLoaded = $state(false);
  let errorMessage = $state('');

  /**
   * One-round-trip screen load via `vault.snapshot` — the vault
   * runs profile.get + profile.photo.get + personal-data.get in-
   * process and returns one bundle. Cuts the 3 per-op overheads
   * (queue serialization, ChaCha20, JSON encode/decode, response
   * routing) that dominate read-op wall-clock time. Personal-data
   * payload is also pre-cached so the data tab paints instantly
   * when the user navigates to it.
   *
   * Tab-count fetches (secrets, wallets) fire in the background
   * after the snapshot lands — they don't gate the header or the
   * data tab.
   */
  async function loadProfile() {
    if (session.state !== 'active') return;
    errorMessage = '';
    try {
      const snap: any = await invoke('get_vault_snapshot');
      if (snap?.success && snap?.data) {
        const profile = snap.data.profile;
        if (profile) {
          firstName = profile.first_name ?? '';
          lastName = profile.last_name ?? '';
          email = profile.email ?? '';
        }
        const photo = snap.data.photo;
        if (photo?.photo) {
          photoBase64 = photo.photo;
        }
        // Prime PersonalData's module-level cache so the data tab
        // paints from this snapshot the moment the user clicks the
        // tab — no extra round-trip.
        const pd = snap.data.personal_data;
        if (pd) {
          const fields = Object.entries(pd.fields ?? {}).map(([key, v]: [string, any]) => ({
            key,
            namespace: v.namespace ?? key.split('::')[0] ?? key,
            value: v.value ?? '',
            alias: v.alias ?? '',
            updatedAt: v.updated_at ?? '',
          }));
          (window as any).__pd_cache = {
            firstName: pd.first_name ?? '',
            lastName: pd.last_name ?? '',
            email: pd.email ?? '',
            fields,
            ts: Date.now(),
          };
        }
      } else if (snap?.error) {
        errorMessage = snap.error;
      }
      profileLoaded = true;

      // Tab counts in the background — failures here don't block the
      // header or the tab panel from rendering.
      Promise.all([
        invoke<any>('list_secrets_catalog').catch(() => null),
        invoke<any>('list_wallets').catch(() => null),
      ]).then(([secretsResp, walletsResp]) => {
        if (secretsResp?.success && secretsResp?.data?.items) {
          secretsCount = (secretsResp.data.items as unknown[]).length;
        }
        if (walletsResp?.success && walletsResp?.data?.wallets) {
          walletsCount = (walletsResp.data.wallets as unknown[]).length;
        }
      });
    } catch (e) {
      errorMessage = `Failed to load vault: ${e}`;
      profileLoaded = true; // unblock tab even on error so user can navigate
    }
  }

  $effect(() => {
    if (session.state === 'active') {
      loadProfile();
    }
  });

  let displayName = $derived.by(() => {
    const full = `${firstName} ${lastName}`.trim();
    return full || email || 'Your Vault';
  });

  let initials = $derived.by(() => {
    if (firstName || lastName) {
      return `${firstName[0] ?? ''}${lastName[0] ?? ''}`.toUpperCase();
    }
    return (email[0] ?? '?').toUpperCase();
  });

  // Photo data URI — vault returns raw base64; assume JPEG since
  // that's what the photo-upload pipeline encodes to. If the user
  // uploaded a PNG the browser still decodes it via the data: URL
  // sniff, so the explicit mime here is a hint, not a constraint.
  let photoSrc = $derived(photoBase64 ? `data:image/jpeg;base64,${photoBase64}` : null);
</script>

<div class="vault">
  <!-- Profile preview bar — pinned, always visible. Switching tabs
       keeps the user oriented; the profile is the anchor. Renders a
       shimmer skeleton until profile.get returns so the first impression
       isn't a flash of empty/anonymous chrome. -->
  <header class="profile-bar">
    {#if !profileLoaded}
      <div class="avatar skeleton-avatar"></div>
      <div class="profile-text">
        <div class="skeleton-line skeleton-name"></div>
        <div class="skeleton-line skeleton-email"></div>
      </div>
    {:else}
      <div class="avatar">
        {#if photoSrc}
          <img src={photoSrc} alt="Profile" />
        {:else}
          <span class="initials">{initials}</span>
        {/if}
      </div>
      <div class="profile-text">
        <h1>{displayName}</h1>
        {#if email}<p class="email">{email}</p>{/if}
      </div>
    {/if}
  </header>

  {#if errorMessage}<div class="error">{errorMessage}</div>{/if}

  <!-- Tab bar — same layout as the Android vault tabs. The
       inactive tabs are subdued but always clickable so the user
       can flip between sections without going back to a home. -->
  <nav class="tabs" role="tablist">
    {#each tabs as tab}
      <button
        class="tab"
        class:active={activeTab === tab.id}
        onclick={() => activeTab = tab.id}
        role="tab"
        aria-selected={activeTab === tab.id}
      >
        {tab.label}
        {#if tab.id === 'secrets' && secretsCount !== null}
          <span class="tab-count">{secretsCount}</span>
        {:else if tab.id === 'wallets' && walletsCount !== null}
          <span class="tab-count">{walletsCount}</span>
        {/if}
      </button>
    {/each}
  </nav>

  <div class="tab-panel" role="tabpanel">
    {#if !profileLoaded}
      <!-- Wait for the header before mounting any tab content so
           PersonalData's load doesn't fight the same vault queue
           that's still draining profile.get + profile.photo.get. -->
      <div class="loading-spinner-wrap"><span class="loading-spinner"></span></div>
    {:else if activeTab === 'data'}
      <PersonalData />
    {:else if activeTab === 'secrets'}
      <div class="placeholder">
        <h2>Secrets</h2>
        <p>Coming in Phase 4. Manage your critical credentials, PIN-protected items, and metadata visibility here.</p>
        <p class="hint">For now, manage secrets from the VettID app on your phone.</p>
      </div>
    {:else if activeTab === 'wallets'}
      <div class="placeholder">
        <h2>Wallets</h2>
        <p>Coming in Phase 4. Send and receive Bitcoin from this desktop with phone-side approval.</p>
        <p class="hint">For now, manage wallets from the VettID app on your phone.</p>
      </div>
    {/if}
  </div>
</div>

<style>
  .vault {
    display: flex;
    flex-direction: column;
    height: 100%;
  }

  .profile-bar {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 20px 24px;
    background: var(--surface);
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
  }
  .avatar {
    width: 56px;
    height: 56px;
    border-radius: 50%;
    background: var(--accent-muted);
    color: var(--accent);
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: 'Plus Jakarta Sans', 'Inter', sans-serif;
    font-weight: 600;
    font-size: 1.5rem;
    overflow: hidden;
    flex-shrink: 0;
  }
  .avatar img {
    width: 100%;
    height: 100%;
    object-fit: cover;
  }
  .profile-text { min-width: 0; }
  .profile-text h1 {
    font-size: 1.2rem;
    margin: 0;
    color: var(--text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .email {
    margin: 4px 0 0;
    font-size: 0.9rem;
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .tabs {
    display: flex;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    padding: 0 16px;
    background: var(--surface);
    flex-shrink: 0;
  }
  .tab {
    background: transparent;
    border: none;
    color: var(--text-muted);
    padding: 12px 18px;
    border-bottom: 2px solid transparent;
    cursor: pointer;
    font: inherit;
    font-size: 0.9rem;
    margin-bottom: -1px;
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }
  .tab:hover { color: var(--text); }
  .tab.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
    font-weight: 500;
  }
  .tab-count {
    font-size: 0.7rem;
    padding: 1px 7px;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.06);
    color: var(--text-muted);
  }
  .tab.active .tab-count {
    background: var(--accent-muted);
    color: var(--accent);
  }

  .tab-panel {
    flex: 1;
    overflow-y: auto;
  }

  .placeholder {
    padding: 40px 24px;
    text-align: center;
    color: var(--text-muted);
  }
  .placeholder h2 {
    font-size: 1.1rem;
    margin: 0 0 12px;
    color: var(--text);
  }
  .placeholder p {
    margin: 0 0 8px;
    line-height: 1.5;
    max-width: 460px;
    margin-left: auto;
    margin-right: auto;
  }
  .placeholder .hint {
    color: var(--text-subtle);
    font-size: 0.9rem;
  }

  .error {
    margin: 16px 24px 0;
    background: rgba(244, 67, 54, 0.1);
    border: 1px solid rgba(244, 67, 54, 0.25);
    color: var(--error);
    padding: 12px 16px;
    border-radius: 8px;
    font-size: 0.9rem;
  }
  /* ---- Loading skeletons (header + spinner) ---- */
  .skeleton-avatar {
    background: linear-gradient(
      90deg,
      rgba(255, 255, 255, 0.04) 0%,
      rgba(255, 255, 255, 0.10) 50%,
      rgba(255, 255, 255, 0.04) 100%
    );
    background-size: 200% 100%;
    animation: shimmer 1.4s ease-in-out infinite;
  }
  .skeleton-line {
    height: 14px;
    border-radius: 4px;
    background: linear-gradient(
      90deg,
      rgba(255, 255, 255, 0.04) 0%,
      rgba(255, 255, 255, 0.10) 50%,
      rgba(255, 255, 255, 0.04) 100%
    );
    background-size: 200% 100%;
    animation: shimmer 1.4s ease-in-out infinite;
    margin-bottom: 6px;
  }
  .skeleton-name { width: 180px; height: 18px; }
  .skeleton-email { width: 220px; }

  @keyframes shimmer {
    0% { background-position: 200% 0; }
    100% { background-position: -200% 0; }
  }

  .loading-spinner-wrap {
    display: flex;
    justify-content: center;
    padding: 60px 0;
  }
  .loading-spinner {
    width: 28px;
    height: 28px;
    border: 3px solid rgba(255, 255, 255, 0.1);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.9s linear infinite;
  }
  @keyframes spin {
    to { transform: rotate(360deg); }
  }
</style>

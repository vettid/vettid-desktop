<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';
  import { secretsUnlockStore, isSecretsUnlocked } from '../../stores/secrets';
  import { buildAliasGroups } from '../../aliasGroups';

  // Module-level cache so navigating away + back paints from the
  // snapshot instead of re-fetching.
  const cache: { secrets: SecretRow[]; ts: number } | null = (window as any).__secrets_cache ?? null;

  interface SecretRow {
    id: string;
    name: string;
    alias: string;
    category: string;
    type: string;
    description: string;
    discoverability: string; // "private" | "cataloged" | "public"
    created_at: string;
    updated_at: string;
  }

  let secrets = $state<SecretRow[]>(cache?.secrets ?? []);
  let loading = $state(cache === null);
  let refreshing = $state(false);
  let errorMessage = $state('');
  // Separate state for reveal failures so they don't get clobbered
  // when the catalog reloads (load() clears errorMessage on entry, and
  // load() also runs on the manual refresh + on every tab remount —
  // before this split, the reveal error flashed for milliseconds and
  // the user couldn't read it).
  let revealError = $state('');

  // Per-row reveal state. Keys are secret IDs. Values either contain
  // the revealed value or a pending/error marker so the row can
  // render its state without coordinating through the parent.
  let revealedById = $state<Record<string, string>>({});
  let revealingId = $state<string | null>(null); // currently fetching

  // The unlock flow lives in the SensitiveDataChip at the top of
  // the vault — this tab just reads the lock state and gates the
  // Reveal buttons on it. When locked, the Reveal column is hidden
  // and a hint points the user at the chip.
  let unlockState = $derived($secretsUnlockStore);
  let unlocked = $derived(isSecretsUnlocked(unlockState));

  // If the grant expires (or the user taps Lock now), collapse any
  // currently-visible values so we don't leave plaintext on screen.
  $effect(() => {
    if (!unlocked && Object.keys(revealedById).length > 0) {
      revealedById = {};
    }
  });

  async function load() {
    if (secrets.length) {
      refreshing = true;
    } else {
      loading = true;
    }
    errorMessage = '';
    try {
      const resp: any = await invoke('list_secrets_catalog');
      if (!resp?.success || !resp?.data) {
        errorMessage = resp?.error || 'Failed to load secrets';
        return;
      }
      const arr = (resp.data.secrets ?? []) as SecretRow[];
      secrets = arr;
      (window as any).__secrets_cache = { secrets, ts: Date.now() };
    } catch (e) {
      errorMessage = `Failed to load secrets: ${e}`;
    } finally {
      loading = false;
      refreshing = false;
    }
  }

  // onMount, NOT $effect: load() reads `secrets` in its entry guard
  // and then writes a fresh `secrets` array, so an $effect would
  // register it as a dependency and re-fire itself in a tight loop.
  onMount(() => { load(); });

  // Group secrets by category for display — matches the Android
  // secrets screen's grouping. Unknown categories fall under "Other".
  let grouped = $derived.by(() => {
    const groups = new Map<string, SecretRow[]>();
    for (const s of secrets) {
      const cat = s.category?.trim() || 'Other';
      const list = groups.get(cat) ?? [];
      list.push(s);
      groups.set(cat, list);
    }
    for (const list of groups.values()) {
      list.sort((a, b) => a.name.localeCompare(b.name));
    }
    return Array.from(groups.entries()).sort(([a], [b]) => a.localeCompare(b));
  });

  // Human-readable label for the secret type. Backend ships
  // SCREAMING_SNAKE — convert to Title case.
  function fmtType(t: string): string {
    if (!t) return '';
    return t.toLowerCase().split('_').map((w) => w[0]?.toUpperCase() + w.slice(1)).join(' ');
  }

  // Credential-bound ("critical") secrets keep their value in the
  // sealed credential, not the minor-secrets store the desktop's
  // secret.get path reads — so a Reveal here would always come back
  // empty. Surface them as phone-managed instead. The vault tags these
  // with a "Critical Secret" category.
  function isCredentialBound(s: SecretRow): boolean {
    return (s.category || '').toLowerCase().includes('critical');
  }

  // Fetch one secret's value into revealedById. Shared by the per-row
  // reveal and the alias-bundle reveal.
  async function fetchSecret(s: SecretRow) {
    revealingId = s.id;
    revealError = '';
    try {
      const resp: any = await invoke('get_secret', { id: s.id });
      if (resp?.success && resp?.data) {
        const raw = resp.data.value;
        if (raw == null || raw === '') {
          revealError = `${s.name}: no value to reveal here — this secret is managed on your phone.`;
        } else {
          revealedById = { ...revealedById, [s.id]: String(raw) };
        }
      } else {
        revealError = resp?.error || `${s.name}: failed to retrieve value`;
      }
    } catch (e) {
      revealError = `${s.name}: ${e}`;
    } finally {
      revealingId = null;
    }
  }

  async function reveal(s: SecretRow) {
    if (revealedById[s.id]) {
      const next = { ...revealedById };
      delete next[s.id];
      revealedById = next;
      return;
    }
    if (!unlocked || isCredentialBound(s)) return;
    await fetchSecret(s);
  }

  // Reveal — or hide — every revealable secret in an alias card at
  // once. The alias is the bundle; credential-bound members are skipped
  // (they have no desktop-revealable value).
  async function toggleGroupReveal(members: SecretRow[]) {
    const minors = members.filter((m) => !isCredentialBound(m));
    if (minors.length === 0) return;
    if (minors.some((m) => revealedById[m.id] !== undefined)) {
      const next = { ...revealedById };
      for (const m of minors) delete next[m.id];
      revealedById = next;
      return;
    }
    if (!unlocked) return;
    for (const m of minors) {
      if (revealedById[m.id] === undefined) await fetchSecret(m);
    }
  }

  async function copyValue(value: string) {
    try {
      await navigator.clipboard.writeText(value);
    } catch (e) {
      // Clipboard denied — fail silently.
    }
  }

  function fmtDiscoverability(d: string): { label: string; tone: string } {
    switch ((d || '').toLowerCase()) {
      case 'public': return { label: 'Public', tone: 'public' };
      case 'cataloged': return { label: 'Cataloged', tone: 'cataloged' };
      case 'private': return { label: 'Private', tone: 'private' };
      default: return { label: d || 'Unknown', tone: 'unknown' };
    }
  }

  // --- Add-secret modal (Phase 1 of DATA-SECRETS-ADD-PLAN: custom field).
  //     Templates land in Phase 2 — Phase 1 lets any single secret be
  //     added by name + value + category + optional alias + notes.
  //     Categories mirror the Android SecretCategory enum so a record
  //     added on desktop reads identically on the phone.
  const SECRET_CATEGORIES: string[] = [
    'IDENTITY', 'LOGIN', 'CERTIFICATE', 'CRYPTOCURRENCY', 'BANK_ACCOUNT',
    'CREDIT_CARD', 'INSURANCE', 'DRIVERS_LICENSE', 'PASSPORT', 'SSN',
    'API_KEY', 'PASSWORD', 'TOTP', 'WIFI', 'VPN', 'SSH',
    'SOFTWARE_LICENSE', 'VEHICLE', 'LOYALTY', 'TAX', 'NOTE', 'OTHER',
  ];

  let addOpen = $state(false);
  let addName = $state('');
  let addValue = $state('');
  let addCategory = $state('PASSWORD');
  let addAlias = $state('');
  let addNotes = $state('');
  let addValueVisible = $state(false);
  let addSaving = $state(false);
  let addError = $state('');

  function openAddSecret() {
    addName = '';
    addValue = '';
    addCategory = 'PASSWORD';
    addAlias = '';
    addNotes = '';
    addValueVisible = false;
    addError = '';
    addOpen = true;
  }

  function cancelAddSecret() {
    addOpen = false;
  }

  async function saveAddSecret() {
    if (!addName.trim() || !addValue) {
      addError = 'Name and value are required.';
      return;
    }
    addSaving = true;
    addError = '';
    try {
      const resp: any = await invoke('add_secret', {
        name: addName.trim(),
        value: addValue,
        category: addCategory,
        alias: addAlias.trim() || null,
        description: addNotes.trim() || null,
      });
      if (!resp?.success) {
        addError = resp?.error || 'Failed to add secret';
        return;
      }
      addOpen = false;
      await load();
    } catch (e) {
      addError = `Failed to add secret: ${e}`;
    } finally {
      addSaving = false;
    }
  }
</script>

<div class="secrets-view">
  <header>
    <h1>Secrets {#if refreshing}<span class="refresh-dot" title="Refreshing"></span>{/if}</h1>
    <button class="add-btn" onclick={openAddSecret}>+ Add</button>
  </header>

  {#if loading}
    <div class="loading-wrap"><span class="spinner"></span></div>
  {:else}
    {#if errorMessage}<div class="error">{errorMessage}</div>{/if}
    {#if revealError}
      <div class="error reveal-error">
        <span>{revealError}</span>
        <button class="dismiss-btn" onclick={() => (revealError = '')} aria-label="Dismiss">✕</button>
      </div>
    {/if}

    {#if secrets.length === 0 && !errorMessage}
      <div class="empty">
        <p>No secrets yet.</p>
        <p class="hint">Add secrets from the VettID app on your phone — desktop secret management is read-only for now.</p>
      </div>
    {:else if !errorMessage}
      {#each grouped as [category, list] (category)}
        {@const groups = buildAliasGroups(list, (s) => s.alias, (s) => s.id)}
        <section class="group">
          <h2>{category}</h2>
          <!-- Alias-card model: ungrouped secrets first, each its own
               card; then one card per alias with its secrets inside. -->
          {#each groups.filter((g) => g.label === null) as g (g.key)}
            <div class="card">{@render secretRow(g.items[0], false, true)}</div>
          {/each}
          {#each groups.filter((g) => g.label !== null) as g (g.key)}
            {@const minors = g.items.filter((s) => !isCredentialBound(s))}
            {@const anyRevealed = minors.some((m) => revealedById[m.id] !== undefined)}
            <div class="card">
              <!-- The alias is the bundle: one Reveal on the card
                   header reveals every revealable secret at once. -->
              <div class="alias-header">
                <span>{g.label}</span>
                {#if unlocked && minors.length > 0}
                  <button
                    class="reveal-btn small"
                    class:revealed={anyRevealed}
                    onclick={() => toggleGroupReveal(g.items)}
                  >
                    {anyRevealed ? 'Hide' : 'Reveal'}
                  </button>
                {/if}
              </div>
              {#each g.items as s (s.id)}
                {@render secretRow(s, true, false)}
              {/each}
            </div>
          {/each}
        </section>
      {/each}
      {#if !unlocked}
        <p class="hint footer-hint">
          🔒 Unlock <strong>Sensitive Data</strong> in the header above to reveal secret values.
        </p>
      {/if}
    {/if}
  {/if}
</div>

{#if addOpen}
  <div class="modal-backdrop" onclick={cancelAddSecret} role="presentation"></div>
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="add-secret-title">
    <h2 id="add-secret-title">Add secret</h2>
    {#if addError}<div class="error" style="margin-bottom: 10px;">{addError}</div>{/if}
    <label class="field-label">
      <span>Name</span>
      <input type="text" bind:value={addName} placeholder="e.g. Bank login" />
    </label>
    <label class="field-label">
      <span>Category</span>
      <select bind:value={addCategory}>
        {#each SECRET_CATEGORIES as c}
          <option value={c}>{c.replaceAll('_', ' ')}</option>
        {/each}
      </select>
    </label>
    <label class="field-label">
      <span>Value</span>
      <div class="value-row">
        {#if addValueVisible}
          <input type="text" bind:value={addValue} />
        {:else}
          <input type="password" bind:value={addValue} />
        {/if}
        <button
          type="button"
          class="reveal-toggle"
          onclick={() => (addValueVisible = !addValueVisible)}
        >{addValueVisible ? 'Hide' : 'Show'}</button>
      </div>
    </label>
    <label class="field-label">
      <span>Alias (optional)</span>
      <input type="text" bind:value={addAlias} placeholder="e.g. Visa, Amex, Trading Wallet" />
      <span class="hint">Helps tell similar entries apart in your catalog.</span>
    </label>
    <label class="field-label">
      <span>Notes (optional)</span>
      <textarea bind:value={addNotes} rows="2" placeholder="What is this for?"></textarea>
    </label>
    <div class="modal-actions">
      <button class="btn ghost" onclick={cancelAddSecret} disabled={addSaving}>Cancel</button>
      <button class="btn primary" onclick={saveAddSecret} disabled={addSaving}>
        {addSaving ? 'Saving…' : 'Save'}
      </button>
    </div>
    {#if addSaving}
      <p class="hint" style="margin-top: 8px;">Approve on your phone to complete the change.</p>
    {/if}
  </div>
{/if}

<!-- One secret row. `inGroup` drops the alias from the name (the card
     header shows it); `showRowReveal` is false for grouped rows since
     the alias card has one bundle Reveal in its header. -->
{#snippet secretRow(s: SecretRow, inGroup: boolean, showRowReveal: boolean)}
  {@const disc = fmtDiscoverability(s.discoverability)}
  {@const revealed = revealedById[s.id]}
  {@const credBound = isCredentialBound(s)}
  <div class="row">
    <div class="row-text">
      <div class="row-name">
        {s.name}{#if s.alias && !inGroup} <span class="alias">· {s.alias}</span>{/if}
      </div>
      <div class="row-meta">
        <span class="type">{fmtType(s.type)}</span>
        {#if s.description}<span class="desc">{s.description}</span>{/if}
      </div>
      {#if revealed !== undefined}
        <div class="revealed-value">
          <span class="mono">{revealed}</span>
          <button class="copy-btn" onclick={() => copyValue(revealed)} title="Copy">copy</button>
        </div>
      {/if}
    </div>
    <div class="row-actions">
      {#if credBound}
        <span
          class="cred-note"
          title="This secret's value is held in your credential — reveal it from the VettID app on your phone."
        >🔒 on phone</span>
      {:else if showRowReveal && unlocked}
        <button
          class="reveal-btn"
          class:revealed={revealed !== undefined}
          onclick={() => reveal(s)}
          disabled={revealingId === s.id}
        >
          {#if revealingId === s.id}…
          {:else if revealed !== undefined}Hide
          {:else}Reveal{/if}
        </button>
      {/if}
      <div class="pill {disc.tone}">{disc.label}</div>
    </div>
  </div>
{/snippet}

<style>
  .secrets-view { padding: 24px; max-width: 720px; margin: 0 auto; }
  header { display: flex; align-items: center; gap: 12px; margin-bottom: 20px; }
  header h1 { flex: 1; font-size: 1.3rem; margin: 0; }

  .group { margin-bottom: 18px; }
  .group h2 {
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
    margin: 0 0 8px 4px;
  }
  .card {
    background: var(--surface);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 10px;
    overflow: hidden;
    margin-bottom: 8px;
  }
  .card:last-child { margin-bottom: 0; }

  /* Alias-card header band — names the alias the card's secrets share,
     and carries the one bundle-Reveal button. */
  .alias-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    font-size: 0.78rem;
    font-weight: 600;
    color: var(--text-muted);
    padding: 7px 14px;
    background: rgba(255, 255, 255, 0.02);
    border-bottom: 1px solid rgba(255, 255, 255, 0.04);
  }
  .reveal-btn.small { padding: 3px 10px; font-size: 0.72rem; }

  /* Credential-bound secrets — value lives in the credential, revealed
     from the phone. Shown in place of a Reveal button. */
  .cred-note {
    font-size: 0.72rem;
    color: var(--text-muted);
    white-space: nowrap;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 14px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.04);
  }
  .row:last-child { border-bottom: none; }
  .row-text { flex: 1; min-width: 0; }
  .row-name {
    color: var(--text);
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .alias { color: var(--text-muted); font-weight: 400; font-size: 0.9rem; }
  .row-meta {
    display: flex;
    gap: 10px;
    margin-top: 3px;
    color: var(--text-muted);
    font-size: 0.85rem;
  }
  .type {
    color: var(--accent);
  }
  .desc {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }

  .row-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-shrink: 0;
  }
  .reveal-btn {
    background: var(--accent);
    color: #1a1a1a;
    border: none;
    padding: 5px 12px;
    border-radius: 5px;
    cursor: pointer;
    font: inherit;
    font-size: 0.8rem;
    font-weight: 500;
    white-space: nowrap;
  }
  .reveal-btn.revealed {
    background: rgba(255, 255, 255, 0.06);
    color: var(--text);
    border: 1px solid rgba(255, 255, 255, 0.1);
  }
  .reveal-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  .revealed-value {
    margin-top: 6px;
    display: flex;
    align-items: center;
    gap: 8px;
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 5px;
    padding: 6px 10px;
  }
  .revealed-value .mono {
    font-family: 'JetBrains Mono', 'Consolas', monospace;
    font-size: 0.9rem;
    color: var(--text);
    overflow: hidden;
    text-overflow: ellipsis;
    word-break: break-all;
    flex: 1;
    min-width: 0;
  }
  .copy-btn {
    background: rgba(255, 255, 255, 0.08);
    border: 1px solid rgba(255, 255, 255, 0.1);
    color: var(--text-muted);
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 0.7rem;
    cursor: pointer;
  }
  .copy-btn:hover {
    background: rgba(255, 255, 255, 0.15);
    color: var(--text);
  }

  .pill {
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    flex-shrink: 0;
  }
  .pill.public {
    background: rgba(64, 196, 99, 0.15);
    color: #6bc77b;
    border: 1px solid rgba(107, 199, 123, 0.3);
  }
  .pill.cataloged {
    background: rgba(255, 193, 7, 0.12);
    color: #e0b020;
    border: 1px solid rgba(224, 176, 32, 0.3);
  }
  .pill.private {
    background: rgba(255, 255, 255, 0.06);
    color: var(--text-muted);
    border: 1px solid rgba(255, 255, 255, 0.1);
  }
  .pill.unknown {
    background: rgba(255, 255, 255, 0.06);
    color: var(--text-muted);
    border: 1px solid rgba(255, 255, 255, 0.1);
  }

  .empty {
    text-align: center;
    padding: 60px 16px;
    color: var(--text-muted);
  }
  .hint {
    color: var(--text-muted);
    font-size: 0.85rem;
  }
  .footer-hint {
    margin-top: 16px;
    text-align: center;
  }
  .error {
    background: rgba(244, 67, 54, 0.1);
    border: 1px solid rgba(244, 67, 54, 0.25);
    color: var(--error);
    padding: 12px 16px;
    border-radius: 6px;
    margin-bottom: 12px;
  }
  .reveal-error {
    display: flex;
    align-items: flex-start;
    gap: 10px;
  }
  .reveal-error span { flex: 1; }
  .dismiss-btn {
    background: transparent;
    border: none;
    color: var(--error);
    cursor: pointer;
    font-size: 0.9rem;
    padding: 0 6px;
    line-height: 1;
    flex-shrink: 0;
  }
  .dismiss-btn:hover { opacity: 0.7; }

  .loading-wrap { display: flex; justify-content: center; padding: 48px 0; }
  .spinner {
    width: 28px;
    height: 28px;
    border: 3px solid rgba(255, 255, 255, 0.1);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: secret-spin 0.9s linear infinite;
  }
  @keyframes secret-spin { to { transform: rotate(360deg); } }
  .refresh-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    margin-left: 8px;
    border-radius: 50%;
    background: var(--accent);
    opacity: 0.7;
    animation: secret-pulse 1.2s ease-in-out infinite;
    vertical-align: middle;
  }
  @keyframes secret-pulse {
    0%, 100% { opacity: 0.3; }
    50% { opacity: 0.85; }
  }

  /* Add-secret button + modal — Phase 1 add UI. */
  .add-btn {
    background: var(--accent);
    color: #1a1a1a;
    border: none;
    padding: 6px 14px;
    border-radius: 6px;
    cursor: pointer;
    font: inherit;
    font-size: 0.85rem;
    font-weight: 500;
  }
  .add-btn:hover { background: var(--accent-hover); }

  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    z-index: 50;
  }
  .modal {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px 22px;
    width: min(440px, 92vw);
    max-height: 86vh;
    overflow-y: auto;
    z-index: 51;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
  }
  .modal h2 { margin: 0 0 14px; font-size: 1.05rem; }
  .field-label {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-bottom: 12px;
  }
  .field-label > span:first-child {
    font-size: 0.8rem;
    color: var(--text-muted);
  }
  .field-label input,
  .field-label select,
  .field-label textarea {
    padding: 7px 10px;
    background: var(--bg-elevated);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 5px;
    font: inherit;
    font-size: 0.9rem;
  }
  .field-label textarea { resize: vertical; min-height: 50px; font-family: inherit; }
  .field-label input:focus,
  .field-label select:focus,
  .field-label textarea:focus { outline: none; border-color: var(--accent); }
  .value-row { display: flex; gap: 6px; }
  .value-row input { flex: 1; }
  .reveal-toggle {
    background: rgba(255, 255, 255, 0.08);
    border: 1px solid var(--border);
    color: var(--text-muted);
    border-radius: 5px;
    padding: 6px 10px;
    cursor: pointer;
    font: inherit;
    font-size: 0.8rem;
  }
  .reveal-toggle:hover { color: var(--text); }
  .modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 8px;
  }
  .btn {
    padding: 7px 16px;
    border-radius: 6px;
    cursor: pointer;
    font: inherit;
    font-size: 0.9rem;
    border: 1px solid transparent;
  }
  .btn.ghost {
    background: transparent;
    border-color: var(--border);
    color: var(--text);
  }
  .btn.ghost:hover { background: var(--bg-elevated); }
  .btn.primary {
    background: var(--accent);
    color: #1a1a1a;
    font-weight: 500;
  }
  .btn.primary:hover:not(:disabled) { background: var(--accent-hover); }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }
</style>

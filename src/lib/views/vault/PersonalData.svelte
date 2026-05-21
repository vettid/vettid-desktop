<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';
  import ConfirmDialog from '../../components/ConfirmDialog.svelte';
  import { buildAliasGroups } from '../../aliasGroups';

  // PersonalData renders inside the Vault tab panel — the profile
  // header + tab nav sit above us, so this view stays focused on
  // the data list + add/edit/delete actions.
  //
  // Phase 3: list + add + update + delete personal data. Visibility
  // (catalog / private) is set on each field separately at write time
  // — phase-3 scope is values, not visibility. A future pass adds the
  // 3-state visibility segmented control mirroring Android.

  /**
   * Raw response shape from personal-data.get with no filter.
   * Fields are keyed by either bare namespace ("contact.phone.mobile")
   * or composite "namespace::alias" when the user grouped entries.
   * The vault returns the namespace + alias split-out per field.
   */
  interface Field {
    /** Composite key the response uses; what we send back on update/delete. */
    key: string;
    namespace: string;
    value: string;
    alias: string;
    updatedAt: string;
  }

  // Module-level cache so tab navigation away + back doesn't re-fire
  // personal-data.get. The first mount populates it; subsequent
  // mounts paint immediately from cache and refresh in the background.
  // Cleared on session change (App.svelte handles that via remount).
  const cache: { firstName: string; lastName: string; email: string; fields: Field[]; ts: number } | null = (window as any).__pd_cache ?? null;

  let firstName = $state(cache?.firstName ?? '');
  let lastName = $state(cache?.lastName ?? '');
  let email = $state(cache?.email ?? '');
  let fields = $state<Field[]>(cache?.fields ?? []);
  // Loading is true only when we have no cached data to show. With
  // cache, we render the stale snapshot immediately and refresh in
  // the background — no full-screen spinner on navigate-back.
  let loading = $state(cache === null);
  let refreshing = $state(false);
  let errorMessage = $state('');
  let saving = $state(false);

  // Edit form state — null when no field is being edited.
  let editing = $state<{ key: string; namespace: string; value: string; alias: string } | null>(null);

  let deleteDialogOpen = $state(false);
  let deleteTarget = $state<Field | null>(null);

  async function load() {
    // Background refresh when we already have cached data: don't
    // flash a spinner, just fade in updates.
    if (fields.length || firstName || lastName || email) {
      refreshing = true;
    } else {
      loading = true;
    }
    errorMessage = '';
    try {
      const resp: any = await invoke('list_personal_data');
      if (!resp?.success || !resp?.data) {
        errorMessage = resp?.error || 'Failed to load personal data';
        return;
      }
      const data = resp.data;
      firstName = data.first_name ?? '';
      lastName = data.last_name ?? '';
      email = data.email ?? '';
      const rawFields = data.fields ?? {};
      fields = Object.entries(rawFields).map(([key, v]: [string, any]) => ({
        key,
        namespace: v.namespace ?? key.split('::')[0] ?? key,
        value: v.value ?? '',
        alias: v.alias ?? '',
        updatedAt: v.updated_at ?? '',
      }));
      (window as any).__pd_cache = {
        firstName, lastName, email, fields, ts: Date.now(),
      };
    } catch (e) {
      errorMessage = `Failed to load personal data: ${e}`;
    } finally {
      loading = false;
      refreshing = false;
    }
  }

  // onMount, NOT $effect: load() reads `fields`/`firstName`/etc. in its
  // entry guard and then writes them, so an $effect would register them
  // as dependencies and re-fire itself forever. The slow vault hid this
  // (one reload/minute); a fast vault spins it into a freeze.
  onMount(() => { load(); });

  // Canonical category labels from the Android client's DataCategory
  // enum. Keeps the desktop in sync with what the app shows so the
  // user sees the same group names on either device.
  const CATEGORY_LABELS: Record<string, string> = {
    identity: 'Identity',
    contact: 'Contact',
    family: 'Family',
    address: 'Address',
    financial: 'Financial',
    medical: 'Medical',
    professional: 'Professional',
    education: 'Education',
    vehicle: 'Vehicle',
    legal: 'Legal',
    wallet: 'Wallet Addresses',
    digital: 'Digital',
    travel: 'Travel',
    membership: 'Membership',
    property: 'Property',
    other: 'Other',
  };
  // Display order — same order the Android screen uses so groups
  // line up top-to-bottom.
  const CATEGORY_ORDER = [
    'Identity', 'Contact', 'Family', 'Address', 'Financial', 'Medical',
    'Professional', 'Education', 'Vehicle', 'Legal', 'Wallet Addresses',
    'Digital', 'Travel', 'Membership', 'Property', 'Other',
  ];

  function categoryFor(namespace: string): string {
    const head = (namespace.split('.')[0] || 'other').toLowerCase();
    return CATEGORY_LABELS[head] ?? capitalize(head);
  }

  /**
   * Group fields by canonical category. System fields (first_name,
   * last_name, email) land in Identity so the desktop matches the
   * mobile app's full top-of-screen layout — earlier the desktop
   * read these but never rendered them.
   */
  let grouped = $derived.by(() => {
    const groups = new Map<string, Field[]>();
    const push = (cat: string, f: Field) => {
      const list = groups.get(cat) ?? [];
      list.push(f);
      groups.set(cat, list);
    };

    // Synthesize system fields as virtual entries so they render
    // alongside the rest under Identity. `key` starts with `__sys__`
    // so the row renderer can hide Edit/Delete (managed elsewhere).
    if (firstName) {
      push('Identity', { key: '__sys__first_name', namespace: 'identity.first_name', value: firstName, alias: '', updatedAt: '' });
    }
    if (lastName) {
      push('Identity', { key: '__sys__last_name', namespace: 'identity.last_name', value: lastName, alias: '', updatedAt: '' });
    }
    if (email) {
      push('Identity', { key: '__sys__email', namespace: 'contact.email', value: email, alias: '', updatedAt: '' });
    }

    for (const f of fields) {
      push(categoryFor(f.namespace), f);
    }
    for (const list of groups.values()) {
      list.sort((a, b) => a.namespace.localeCompare(b.namespace));
    }
    // Sort categories by CATEGORY_ORDER (known categories first, then
    // anything else alphabetically).
    return Array.from(groups.entries()).sort(([a], [b]) => {
      const ai = CATEGORY_ORDER.indexOf(a);
      const bi = CATEGORY_ORDER.indexOf(b);
      if (ai === -1 && bi === -1) return a.localeCompare(b);
      if (ai === -1) return 1;
      if (bi === -1) return -1;
      return ai - bi;
    });
  });

  function capitalize(s: string): string {
    return s ? s[0].toUpperCase() + s.slice(1) : s;
  }
  function isSystemField(f: Field): boolean {
    return f.key.startsWith('__sys__');
  }

  /**
   * Stable label for a namespace — last dotted segment, capitalized.
   * Composite "wife::phone" aliases render as "Wife: phone" so the
   * grouping is visible per Android's catalog UX.
   */
  function fieldLabel(f: Field, withAlias = true): string {
    const last = f.namespace.split('.').pop() ?? f.namespace;
    const cap = last.charAt(0).toUpperCase() + last.slice(1);
    // Inside an alias card the alias is the card header — don't repeat
    // it in every row.
    return (withAlias && f.alias) ? `${cap}: ${f.alias}` : cap;
  }

  function startEdit(f: Field) {
    editing = {
      key: f.key,
      namespace: f.namespace,
      value: f.value,
      alias: f.alias,
    };
  }

  function startAdd() {
    editing = { key: '', namespace: '', value: '', alias: '' };
  }

  function cancelEdit() {
    editing = null;
  }

  async function saveEdit() {
    if (!editing) return;
    const namespace = editing.namespace.trim();
    if (!namespace) {
      errorMessage = 'Field name (e.g. "contact.phone.mobile") is required';
      return;
    }
    saving = true;
    errorMessage = '';
    try {
      const entries: Array<{ field_id: string; value: string }> = [
        { field_id: namespace, value: editing.value },
      ];
      const resp: any = await invoke('update_personal_data', {
        section: namespace.split('.')[0] || 'general',
        entries,
      });
      if (!resp?.success) {
        errorMessage = resp?.error || 'Failed to save';
        return;
      }
      editing = null;
      await load();
    } catch (e) {
      errorMessage = `Failed to save: ${e}`;
    } finally {
      saving = false;
    }
  }

  function confirmDelete(f: Field) {
    deleteTarget = f;
    deleteDialogOpen = true;
  }

  async function doDelete() {
    if (!deleteTarget) return;
    saving = true;
    errorMessage = '';
    try {
      // The delete op is phone-required server-side. The Tauri layer
      // doesn't have a direct command for it yet, so we route through
      // a generic exec — for now we surface a hint until Phase 3
      // wires a `delete_personal_data` command. This avoids a half-
      // broken delete that updates the UI without confirming server
      // success.
      errorMessage = 'Delete from the phone for now — desktop delete coming next.';
    } catch (e) {
      errorMessage = `Failed to delete: ${e}`;
    } finally {
      saving = false;
      deleteTarget = null;
    }
  }
</script>

<div class="pd-view">
  <header>
    <h1>Personal data {#if refreshing}<span class="refresh-dot" title="Refreshing"></span>{/if}</h1>
    <button class="add-btn" onclick={startAdd}>+ Add</button>
  </header>

  {#if loading}
    <div class="loading-wrap"><span class="spinner"></span></div>
  {:else}
    {#if errorMessage}<div class="error">{errorMessage}</div>{/if}

    {#each grouped as [category, list] (category)}
      {@const groups = buildAliasGroups(list, (f) => f.alias, (f) => f.key)}
      <section class="group">
        <h2>{category}</h2>
        <!-- Alias-card model: ungrouped fields first, each its own
             card; then one card per alias with its fields inside. -->
        {#each groups.filter((g) => g.label === null) as g (g.key)}
          <div class="card">{@render dataRow(g.items[0], false)}</div>
        {/each}
        {#each groups.filter((g) => g.label !== null) as g (g.key)}
          <div class="card">
            <div class="alias-header">{g.label}</div>
            {#each g.items as f (f.key)}
              {@render dataRow(f, true)}
            {/each}
          </div>
        {/each}
      </section>
    {/each}

    {#if grouped.length === 0 && !(firstName || lastName || email)}
      <div class="empty">
        <p>No personal data yet.</p>
        <button class="add-btn-inline" onclick={startAdd}>Add your first field</button>
      </div>
    {/if}
  {/if}
</div>

<!-- Edit modal — both Add and Edit use the same form. Distinguish
     by editing.key being empty for Add (we'll create a new namespace)
     vs set for Edit (we update the existing key). -->
{#if editing}
  <div class="modal-backdrop" onclick={cancelEdit} role="presentation"></div>
  <div class="modal" role="dialog" aria-modal="true">
    <h2>{editing.key ? 'Edit field' : 'Add field'}</h2>
    <label class="field-label">
      <span>Field name</span>
      <input
        type="text"
        bind:value={editing.namespace}
        placeholder="e.g. contact.phone.mobile"
        disabled={!!editing.key}
      />
      <span class="hint">Dotted namespace — first segment is the category (Contact, Family, ...).</span>
    </label>
    <label class="field-label">
      <span>Value</span>
      <input type="text" bind:value={editing.value} />
    </label>
    <div class="modal-actions">
      <button class="btn ghost" onclick={cancelEdit} disabled={saving}>Cancel</button>
      <button class="btn primary" onclick={saveEdit} disabled={saving}>
        {saving ? 'Saving…' : 'Save'}
      </button>
    </div>
    {#if saving}
      <p class="hint" style="margin-top: 8px;">Approve on your phone to complete the change.</p>
    {/if}
  </div>
{/if}

<ConfirmDialog
  bind:open={deleteDialogOpen}
  title="Delete this field?"
  message={deleteTarget ? `Remove ${deleteTarget.namespace} from your vault?` : ''}
  confirmLabel="Delete"
  tone="danger"
  onConfirm={doDelete}
/>

<!-- One personal-data field row. `inGroup` drops the alias from the
     label since the alias card's header already shows it. -->
{#snippet dataRow(f: Field, inGroup: boolean)}
  {#if isSystemField(f)}
    {@render rowSnippet(fieldLabel(f, !inGroup), f.value, null)}
  {:else}
    {@render rowSnippet(fieldLabel(f, !inGroup), f.value, {
      onEdit: () => startEdit(f),
      onDelete: () => confirmDelete(f),
    })}
  {/if}
{/snippet}

<!-- Inline row composable. Svelte 5 snippets can stay in the same
     file; we declare it after the markup so the section structure
     reads top-to-bottom. -->
{#snippet rowSnippet(label: string, value: string, opts: { onEdit?: () => void; onDelete?: () => void } | null)}
  <div class="row">
    <div class="row-text">
      <div class="row-label">{label}</div>
      <div class="row-value">{value || '—'}</div>
    </div>
    {#if opts}
      <div class="row-actions">
        <button class="row-btn" onclick={opts.onEdit} aria-label="Edit">✎</button>
        <button class="row-btn danger" onclick={opts.onDelete} aria-label="Delete">×</button>
      </div>
    {/if}
  </div>
{/snippet}

<style>
  .pd-view {
    padding: 24px;
    max-width: 720px;
    margin: 0 auto;
  }

  header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 20px;
  }
  header h1 {
    flex: 1;
    font-size: 1.3rem;
    margin: 0;
  }
  .add-btn {
    background: var(--accent);
    color: #1a1a1a;
    border: none;
    padding: 7px 14px;
    border-radius: 6px;
    cursor: pointer;
    font: inherit;
    font-size: 0.9rem;
    font-weight: 500;
  }
  .add-btn:hover { background: var(--accent-hover); }
  .add-btn-inline {
    background: rgba(255, 193, 37, 0.15);
    color: var(--accent);
    border: 1px solid var(--border-accent);
    padding: 8px 16px;
    border-radius: 6px;
    cursor: pointer;
    font: inherit;
    font-size: 0.9rem;
    margin-top: 8px;
  }

  .group { margin-bottom: 20px; }
  .group h2 {
    font-size: 0.85rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin: 0 0 8px;
    font-weight: 600;
  }

  .card {
    background: var(--surface);
    border-radius: 8px;
    overflow: hidden;
    margin-bottom: 8px;
  }
  .card:last-child { margin-bottom: 0; }

  /* Alias-card header band — names the alias the card's fields share. */
  .alias-header {
    font-size: 0.78rem;
    font-weight: 600;
    color: var(--text-muted);
    padding: 8px 16px 6px;
    background: rgba(255, 255, 255, 0.02);
    border-bottom: 1px solid rgba(255, 255, 255, 0.04);
  }

  .row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.04);
  }
  .row:last-child { border-bottom: none; }
  .row-text { flex: 1; min-width: 0; }
  .row-label { font-size: 0.8rem; color: var(--text-muted); margin-bottom: 2px; }
  .row-value { font-size: 0.95rem; color: var(--text); word-break: break-word; }
  .row-actions { display: flex; gap: 4px; }
  .row-btn {
    background: transparent;
    border: 1px solid transparent;
    color: var(--text-muted);
    width: 28px;
    height: 28px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.9rem;
  }
  .row-btn:hover { background: rgba(255, 255, 255, 0.05); color: var(--text); }
  .row-btn.danger:hover { color: var(--error); }

  .empty {
    text-align: center;
    padding: 40px 16px;
    color: var(--text-muted);
  }
  .loading {
    text-align: center;
    padding: 24px;
    color: var(--text-muted);
  }
  .loading-wrap {
    display: flex;
    justify-content: center;
    padding: 48px 0;
  }
  .spinner {
    width: 28px;
    height: 28px;
    border: 3px solid rgba(255, 255, 255, 0.1);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: pd-spin 0.9s linear infinite;
  }
  @keyframes pd-spin { to { transform: rotate(360deg); } }
  .refresh-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    margin-left: 8px;
    border-radius: 50%;
    background: var(--accent);
    opacity: 0.7;
    animation: pulse 1.2s ease-in-out infinite;
    vertical-align: middle;
  }
  @keyframes pulse {
    0%, 100% { opacity: 0.3; }
    50% { opacity: 0.85; }
  }
  .error {
    background: rgba(244, 67, 54, 0.1);
    border: 1px solid rgba(244, 67, 54, 0.25);
    color: var(--error);
    padding: 12px 16px;
    border-radius: 6px;
    margin-bottom: 16px;
    font-size: 0.9rem;
  }

  /* Edit modal — uses ConfirmDialog's layout pattern but with form
     inputs. Keeping the form inline rather than building a generic
     FormModal since this is the only call site for now. */
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
    z-index: 100;
    backdrop-filter: blur(2px);
  }
  .modal {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    z-index: 101;
    background: var(--surface);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 12px;
    padding: 22px;
    min-width: 380px;
    max-width: 460px;
    box-shadow: 0 18px 50px rgba(0, 0, 0, 0.5);
  }
  .modal h2 {
    font-size: 1.05rem;
    margin: 0 0 16px;
    font-weight: 600;
  }
  .field-label {
    display: flex;
    flex-direction: column;
    gap: 6px;
    margin-bottom: 12px;
    font-size: 0.85rem;
    color: var(--text-muted);
  }
  .field-label input {
    background: var(--bg);
    border: 1px solid rgba(255,255,255,0.08);
    color: var(--text);
    padding: 8px 12px;
    border-radius: 6px;
    font-size: 0.95rem;
    outline: none;
  }
  .field-label input:focus { border-color: var(--accent); }
  .field-label input:disabled { opacity: 0.7; }
  .field-label .hint { font-size: 0.75rem; color: var(--text-subtle); }
  .modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 6px;
  }
  .btn {
    padding: 8px 16px;
    border-radius: 6px;
    cursor: pointer;
    font: inherit;
    font-size: 0.9rem;
    border: 1px solid transparent;
  }
  .btn.ghost {
    background: transparent;
    color: var(--text-muted);
    border-color: rgba(255, 255, 255, 0.1);
  }
  .btn.primary {
    background: var(--accent);
    color: #1a1a1a;
    font-weight: 500;
  }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }

  .hint {
    color: var(--text-subtle);
    font-size: 0.85rem;
  }
</style>

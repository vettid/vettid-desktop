<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import ConfirmDialog from '../../components/ConfirmDialog.svelte';

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

  let firstName = $state('');
  let lastName = $state('');
  let email = $state('');
  let fields = $state<Field[]>([]);
  let loading = $state(true);
  let errorMessage = $state('');
  let saving = $state(false);

  // Edit form state — null when no field is being edited.
  let editing = $state<{ key: string; namespace: string; value: string; alias: string } | null>(null);

  let deleteDialogOpen = $state(false);
  let deleteTarget = $state<Field | null>(null);

  async function load() {
    loading = true;
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
    } catch (e) {
      errorMessage = `Failed to load personal data: ${e}`;
    } finally {
      loading = false;
    }
  }

  $effect(() => { load(); });

  /**
   * Group fields by their top-level category (first segment of the
   * namespace). Falls back to "Other" for namespaces that don't
   * follow the convention. Within a category, sort by namespace
   * for stable display; the vault's sort_order op is a Phase-4
   * concern.
   */
  let grouped = $derived.by(() => {
    const groups = new Map<string, Field[]>();
    for (const f of fields) {
      const cat = capitalize(f.namespace.split('.')[0] || 'Other');
      const list = groups.get(cat) ?? [];
      list.push(f);
      groups.set(cat, list);
    }
    for (const list of groups.values()) {
      list.sort((a, b) => a.namespace.localeCompare(b.namespace));
    }
    return Array.from(groups.entries()).sort(([a], [b]) => a.localeCompare(b));
  });

  function capitalize(s: string): string {
    return s ? s[0].toUpperCase() + s.slice(1) : s;
  }

  /**
   * Stable label for a namespace — last dotted segment, capitalized.
   * Composite "wife::phone" aliases render as "Wife: phone" so the
   * grouping is visible per Android's catalog UX.
   */
  function fieldLabel(f: Field): string {
    const last = f.namespace.split('.').pop() ?? f.namespace;
    const cap = last.charAt(0).toUpperCase() + last.slice(1);
    return f.alias ? `${cap}: ${f.alias}` : cap;
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
    <h1>Personal data</h1>
    <button class="add-btn" onclick={startAdd}>+ Add</button>
  </header>

  {#if loading}
    <div class="loading">Loading…</div>
  {:else}
    {#if errorMessage}<div class="error">{errorMessage}</div>{/if}

    {#each grouped as [category, list] (category)}
      <section class="group">
        <h2>{category}</h2>
        <div class="card">
          {#each list as f (f.key)}
            {@render rowSnippet(fieldLabel(f), f.value, {
              onEdit: () => startEdit(f),
              onDelete: () => confirmDelete(f),
            })}
          {/each}
        </div>
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

<!-- Inline row composable. Svelte 5 snippets can stay in the same
     file; we declare it after the markup so the section structure
     reads top-to-bottom. -->
{#snippet rowSnippet(label: string, value: string, opts: { readonly?: boolean; onEdit?: () => void; onDelete?: () => void })}
  <div class="row">
    <div class="row-text">
      <div class="row-label">{label}</div>
      <div class="row-value">{value || '—'}</div>
    </div>
    {#if !opts.readonly}
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

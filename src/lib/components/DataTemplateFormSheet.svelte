<script lang="ts">
  // Renders a DataTemplate's fields with per-hint inputs and a shared
  // alias. On save fires one personal-data.update with {fields, aliases}
  // covering every non-blank value — single phone approval, unlike the
  // secret template which is one approval per field.
  import { invoke } from '@tauri-apps/api/core';
  import { modal } from '../actions/modal';
  import type { DataTemplate } from '../personalDataTemplates';
  import type { FieldHint } from '../secretTemplates';

  interface Props {
    template: DataTemplate;
    onClose: () => void;
    onSaved: () => void;
  }
  let { template, onClose, onSaved }: Props = $props();

  let alias = $state('');
  let values = $state<Record<string, string>>(
    Object.fromEntries(template.fields.map((f) => [f.namespace, '']))
  );
  let saving = $state(false);
  let error = $state('');

  function inputType(hint: FieldHint): string {
    switch (hint) {
      case 'EMAIL': return 'email';
      case 'PHONE': return 'tel';
      case 'URL':   return 'url';
      case 'NUMBER': return 'number';
      case 'DATE':  return 'date';
      case 'EXPIRY_DATE': return 'month';
      default: return 'text';
    }
  }

  async function save() {
    const fields: Record<string, string> = {};
    const aliases: Record<string, string> = {};
    const a = alias.trim();
    for (const f of template.fields) {
      const v = (values[f.namespace] ?? '').trim();
      if (!v) continue;
      fields[f.namespace] = v;
      if (a) aliases[f.namespace] = a;
    }
    if (Object.keys(fields).length === 0) {
      error = 'Enter a value for at least one field.';
      return;
    }
    saving = true;
    error = '';
    try {
      const args: { fields: Record<string, string>; aliases?: Record<string, string> } = { fields };
      if (a) args.aliases = aliases;
      const resp: any = await invoke('update_personal_data', args);
      if (!resp?.success) {
        error = resp?.error || 'Failed to save';
        return;
      }
      onSaved();
    } catch (e) {
      error = `Failed to save: ${e}`;
    } finally {
      saving = false;
    }
  }
</script>

<div class="backdrop" onclick={onClose} role="presentation"></div>
<div class="sheet" role="dialog" aria-modal="true" aria-labelledby="data-form-title" use:modal={{ onEscape: onClose }}>
  <header class="sheet-head">
    <span class="sheet-ic">{template.icon}</span>
    <h2 id="data-form-title">{template.name}</h2>
    <button class="close" onclick={onClose} aria-label="Close">✕</button>
  </header>
  {#if error}<div class="error">{error}</div>{/if}

  <label class="fl">
    <span>Alias (optional)</span>
    <input type="text" bind:value={alias} placeholder="e.g. Wife, Mom, Work, Home" />
    <span class="h">Helps tell similar entries apart in your catalog.</span>
  </label>

  {#each template.fields as f (f.namespace)}
    <label class="fl">
      <span>{f.name}</span>
      {#if f.hint === 'NOTE'}
        <textarea bind:value={values[f.namespace]} rows="2"></textarea>
      {:else}
        <input type={inputType(f.hint)} bind:value={values[f.namespace]} />
      {/if}
    </label>
  {/each}

  <div class="actions">
    <button class="btn ghost" onclick={onClose} disabled={saving}>Cancel</button>
    <button class="btn primary" onclick={save} disabled={saving}>
      {saving ? 'Saving…' : 'Save'}
    </button>
  </div>
  {#if saving}<p class="h" style="margin-top:8px;">Approve on your phone to complete the change.</p>{/if}
</div>

<style>
  .backdrop { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 50; }
  .sheet {
    position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%);
    background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px;
    width: min(440px, 94vw); max-height: 86vh; overflow-y: auto;
    z-index: 51; box-shadow: 0 10px 40px rgba(0,0,0,0.5);
    padding: 18px 20px 20px;
  }
  .sheet-head { display: flex; align-items: center; gap: 10px; margin-bottom: 14px; }
  .sheet-head h2 { margin: 0; font-size: 1.05rem; flex: 1; }
  .sheet-ic { font-size: 1.5rem; }
  .close {
    background: none; border: 1px solid var(--border); border-radius: 4px;
    padding: 3px 9px; cursor: pointer; color: var(--text-muted); font: inherit;
  }
  .close:hover { color: var(--text); background: var(--bg-elevated); }

  .error {
    background: rgba(244,67,54,0.1);
    border: 1px solid rgba(244,67,54,0.25);
    color: var(--error);
    padding: 10px 12px;
    border-radius: 6px;
    margin-bottom: 12px;
    font-size: 0.85rem;
  }

  .fl { display: flex; flex-direction: column; gap: 4px; margin-bottom: 11px; }
  .fl > span:first-child { font-size: 0.78rem; color: var(--text-muted); }
  .fl input, .fl textarea {
    padding: 7px 10px;
    background: var(--bg-elevated);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 5px;
    font: inherit;
    font-size: 0.9rem;
  }
  .fl textarea { resize: vertical; min-height: 50px; font-family: inherit; }
  .fl input:focus, .fl textarea:focus { outline: none; border-color: var(--accent); }
  .h { font-size: 0.78rem; color: var(--text-muted); }

  .actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 10px; }
  .btn {
    padding: 7px 16px;
    border-radius: 6px;
    cursor: pointer;
    font: inherit;
    font-size: 0.9rem;
    border: 1px solid transparent;
  }
  .btn.ghost { background: transparent; border-color: var(--border); color: var(--text); }
  .btn.ghost:hover { background: var(--bg-elevated); }
  .btn.primary { background: var(--accent); color: #1a1a1a; font-weight: 500; }
  .btn.primary:hover:not(:disabled) { background: var(--accent-hover); }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }
</style>

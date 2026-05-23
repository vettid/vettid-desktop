<script lang="ts">
  // Shared template chooser — used by both Secrets and Personal Data
  // add-flows. Renders a "Custom Field" tile at the top followed by
  // templates grouped by category. The caller passes a flat list of
  // templates plus a callback that fires with either 'custom' or the
  // picked template's id.
  import { modal } from '../actions/modal';

  interface TemplateLike {
    id: string;
    name: string;
    category: string;
    icon: string;
    description: string;
  }

  interface Props {
    title: string;
    templates: TemplateLike[];
    onPick: (id: string) => void;   // 'custom' or template.id
    onClose: () => void;
  }
  let { title, templates, onPick, onClose }: Props = $props();

  let grouped = $derived.by(() => {
    const map = new Map<string, TemplateLike[]>();
    for (const t of templates) {
      const arr = map.get(t.category) ?? [];
      arr.push(t);
      map.set(t.category, arr);
    }
    for (const v of map.values()) v.sort((a, b) => a.name.localeCompare(b.name));
    return Array.from(map.entries()).sort(([a], [b]) => a.localeCompare(b));
  });

  function fmtCategory(c: string): string {
    return c.replaceAll('_', ' ').replace(/\b\w/g, (m) => m.toUpperCase());
  }
</script>

<div class="backdrop" onclick={onClose} role="presentation"></div>
<div class="sheet" role="dialog" aria-modal="true" aria-labelledby="tpl-chooser-title" use:modal={{ onEscape: onClose }}>
  <header class="sheet-head">
    <h2 id="tpl-chooser-title">{title}</h2>
    <button class="close" onclick={onClose} aria-label="Close">✕</button>
  </header>

  <button class="custom-card" onclick={() => onPick('custom')}>
    <span class="ic">✏️</span>
    <div class="text">
      <div class="row1">Custom Field</div>
      <div class="row2">Pick any category and enter a single field by hand.</div>
    </div>
  </button>

  <h3 class="section-head">Templates</h3>
  {#each grouped as [cat, list] (cat)}
    <div class="cat-head">{fmtCategory(cat)}</div>
    <div class="cat-list">
      {#each list as t (t.id)}
        <button class="tpl-card" onclick={() => onPick(t.id)}>
          <span class="ic">{t.icon}</span>
          <div class="text">
            <div class="row1">{t.name}</div>
            <div class="row2">{t.description}</div>
          </div>
        </button>
      {/each}
    </div>
  {/each}
</div>

<style>
  .backdrop { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 50; }
  .sheet {
    position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%);
    background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px;
    width: min(520px, 94vw); max-height: 86vh; overflow-y: auto;
    z-index: 51; box-shadow: 0 10px 40px rgba(0,0,0,0.5);
    padding: 18px 20px 22px;
  }
  .sheet-head { display: flex; align-items: center; gap: 10px; margin-bottom: 14px; }
  .sheet-head h2 { margin: 0; font-size: 1.05rem; flex: 1; }
  .close {
    background: none; border: 1px solid var(--border); border-radius: 4px;
    padding: 3px 9px; cursor: pointer; color: var(--text-muted); font: inherit;
  }
  .close:hover { color: var(--text); background: var(--bg-elevated); }

  .custom-card, .tpl-card {
    display: flex; align-items: center; gap: 12px;
    width: 100%; text-align: left;
    padding: 11px 13px; margin: 0 0 8px;
    background: var(--surface); color: inherit;
    border: 1px solid var(--border); border-radius: 8px;
    cursor: pointer; font: inherit;
    transition: background 0.12s, border-color 0.12s;
  }
  .custom-card { border-color: var(--border-accent); background: var(--accent-muted); }
  .custom-card:hover, .tpl-card:hover { background: var(--bg-elevated); }
  .custom-card:hover { border-color: var(--accent); }
  .ic { font-size: 1.4rem; width: 32px; text-align: center; flex-shrink: 0; }
  .text { min-width: 0; flex: 1; }
  .row1 { font-weight: 500; }
  .row2 { font-size: 0.8rem; color: var(--text-muted); margin-top: 2px; }

  .section-head {
    margin: 16px 0 8px;
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
  }
  .cat-head {
    margin: 12px 0 6px 4px;
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-subtle);
    font-weight: 600;
  }
  .cat-list { display: flex; flex-direction: column; gap: 0; }
</style>

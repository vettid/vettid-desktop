<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';

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

  $effect(() => { load(); });

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

  function fmtDiscoverability(d: string): { label: string; tone: string } {
    switch ((d || '').toLowerCase()) {
      case 'public': return { label: 'Public', tone: 'public' };
      case 'cataloged': return { label: 'Cataloged', tone: 'cataloged' };
      case 'private': return { label: 'Private', tone: 'private' };
      default: return { label: d || 'Unknown', tone: 'unknown' };
    }
  }
</script>

<div class="secrets-view">
  <header>
    <h1>Secrets {#if refreshing}<span class="refresh-dot" title="Refreshing"></span>{/if}</h1>
  </header>

  {#if loading}
    <div class="loading-wrap"><span class="spinner"></span></div>
  {:else}
    {#if errorMessage}<div class="error">{errorMessage}</div>{/if}

    {#if secrets.length === 0 && !errorMessage}
      <div class="empty">
        <p>No secrets yet.</p>
        <p class="hint">Add secrets from the VettID app on your phone — desktop secret management is read-only for now.</p>
      </div>
    {:else if !errorMessage}
      {#each grouped as [category, list] (category)}
        <section class="group">
          <h2>{category}</h2>
          <div class="card">
            {#each list as s (s.id)}
              {@const disc = fmtDiscoverability(s.discoverability)}
              <div class="row">
                <div class="row-text">
                  <div class="row-name">
                    {s.name}{#if s.alias} <span class="alias">· {s.alias}</span>{/if}
                  </div>
                  <div class="row-meta">
                    <span class="type">{fmtType(s.type)}</span>
                    {#if s.description}<span class="desc">{s.description}</span>{/if}
                  </div>
                </div>
                <div class="pill {disc.tone}">{disc.label}</div>
              </div>
            {/each}
          </div>
        </section>
      {/each}
      <p class="hint footer-hint">
        Secret values stay on the phone — desktop sees only metadata. To retrieve a value, use the VettID app.
      </p>
    {/if}
  {/if}
</div>

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
</style>

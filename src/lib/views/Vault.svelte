<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { sessionStore } from '../stores/session';
  import PendingApproval from '../components/PendingApproval.svelte';

  let session = $derived($sessionStore);
  let activeTab = $state<'connections' | 'secrets' | 'feed' | 'messages'>('connections');

  // Connections
  let connections = $state<any[]>([]);
  let connectionsLoading = $state(false);

  // Secrets catalog
  let secrets = $state<any[]>([]);
  let secretsLoading = $state(false);

  // Feed
  let feedItems = $state<any[]>([]);
  let feedLoading = $state(false);

  // Messages
  let messages = $state<any[]>([]);
  let messagesLoading = $state(false);

  // Pending approval
  let pendingApproval = $state<{ operation: string; requestId: string } | null>(null);

  // Error
  let errorMessage = $state('');

  async function loadConnections() {
    connectionsLoading = true;
    errorMessage = '';
    try {
      const result: any = await invoke('list_connections');
      connections = result.connections || [];
    } catch (e: any) {
      errorMessage = e.toString();
    } finally {
      connectionsLoading = false;
    }
  }

  async function loadSecretsCatalog() {
    secretsLoading = true;
    errorMessage = '';
    try {
      const result: any = await invoke('list_secrets_catalog');
      secrets = result.secrets || [];
    } catch (e: any) {
      errorMessage = e.toString();
    } finally {
      secretsLoading = false;
    }
  }

  async function loadFeed() {
    feedLoading = true;
    errorMessage = '';
    try {
      const result: any = await invoke('list_feed');
      feedItems = result.items || [];
    } catch (e: any) {
      errorMessage = e.toString();
    } finally {
      feedLoading = false;
    }
  }

  async function loadMessages() {
    messagesLoading = true;
    errorMessage = '';
    try {
      const result: any = await invoke('list_messages');
      messages = result.messages || [];
    } catch (e: any) {
      errorMessage = e.toString();
    } finally {
      messagesLoading = false;
    }
  }

  async function requestSecret(secretId: string, name: string) {
    errorMessage = '';
    try {
      const result: any = await invoke('request_secret', { secretId });
      if (result.pending_approval) {
        pendingApproval = { operation: `Retrieve: ${name}`, requestId: result.request_id };
      }
    } catch (e: any) {
      errorMessage = e.toString();
    }
  }

  function switchTab(tab: typeof activeTab) {
    activeTab = tab;
    errorMessage = '';
    pendingApproval = null;
    if (tab === 'connections' && connections.length === 0) loadConnections();
    if (tab === 'secrets' && secrets.length === 0) loadSecretsCatalog();
    if (tab === 'feed' && feedItems.length === 0) loadFeed();
    if (tab === 'messages' && messages.length === 0) loadMessages();
  }

  // Load connections on mount
  $effect(() => {
    if (session.state === 'active') loadConnections();
  });
</script>

<div class="vault-view">
  <h1>Vault</h1>

  <div class="tabs">
    <button class="tab" class:active={activeTab === 'connections'} onclick={() => switchTab('connections')}>
      Connections
    </button>
    <button class="tab" class:active={activeTab === 'secrets'} onclick={() => switchTab('secrets')}>
      Secrets
    </button>
    <button class="tab" class:active={activeTab === 'feed'} onclick={() => switchTab('feed')}>
      Feed
    </button>
    <button class="tab" class:active={activeTab === 'messages'} onclick={() => switchTab('messages')}>
      Messages
    </button>
  </div>

  {#if pendingApproval}
    <PendingApproval operation={pendingApproval.operation} requestId={pendingApproval.requestId} />
  {/if}

  {#if errorMessage}
    <p class="error-text">{errorMessage}</p>
  {/if}

  <div class="tab-content">
    {#if activeTab === 'connections'}
      {#if connectionsLoading}
        <div class="loading">Loading connections...</div>
      {:else if connections.length === 0}
        <div class="empty">No connections found</div>
      {:else}
        <div class="list">
          {#each connections as conn}
            <div class="list-item">
              <div class="item-main">
                <span class="item-name">{conn.name || conn.connection_id}</span>
                <span class="item-type badge">{conn.connection_type}</span>
              </div>
              <div class="item-meta">
                <span class="item-status" class:active={conn.status === 'active'}
                      class:inactive={conn.status !== 'active'}>
                  {conn.status}
                </span>
              </div>
            </div>
          {/each}
        </div>
      {/if}

    {:else if activeTab === 'secrets'}
      {#if secretsLoading}
        <div class="loading">Loading secrets catalog...</div>
      {:else if secrets.length === 0}
        <div class="empty">No secrets in vault</div>
      {:else}
        <div class="list">
          {#each secrets as secret}
            <div class="list-item">
              <div class="item-main">
                <span class="item-name">{secret.name}</span>
                {#if secret.category}
                  <span class="item-type badge">{secret.category}</span>
                {/if}
              </div>
              <div class="item-actions">
                <button class="btn-small" onclick={() => requestSecret(secret.id, secret.name)}>
                  Retrieve
                </button>
              </div>
            </div>
          {/each}
        </div>
      {/if}

    {:else if activeTab === 'feed'}
      {#if feedLoading}
        <div class="loading">Loading feed...</div>
      {:else if feedItems.length === 0}
        <div class="empty">No feed items</div>
      {:else}
        <div class="list">
          {#each feedItems as item}
            <div class="list-item">
              <div class="item-main">
                <span class="item-name">{item.title || item.event_type}</span>
                <span class="item-time">{new Date(item.timestamp).toLocaleString()}</span>
              </div>
              {#if item.description}
                <div class="item-detail">{item.description}</div>
              {/if}
            </div>
          {/each}
        </div>
      {/if}

    {:else if activeTab === 'messages'}
      {#if messagesLoading}
        <div class="loading">Loading messages...</div>
      {:else if messages.length === 0}
        <div class="empty">No messages</div>
      {:else}
        <div class="list">
          {#each messages as msg}
            <div class="list-item" class:unread={!msg.read}>
              <div class="item-main">
                <span class="item-name">{msg.subject || msg.from}</span>
                <span class="item-time">{new Date(msg.timestamp).toLocaleString()}</span>
              </div>
              {#if msg.preview}
                <div class="item-detail">{msg.preview}</div>
              {/if}
            </div>
          {/each}
        </div>
      {/if}
    {/if}
  </div>
</div>

<style>
  .vault-view {
    padding: 24px;
  }

  h1 {
    font-size: 1.3rem;
    margin-bottom: 20px;
  }

  .tabs {
    display: flex;
    gap: 4px;
    margin-bottom: 20px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
  }

  .tab {
    background: none;
    border: none;
    color: var(--text-muted);
    padding: 10px 16px;
    cursor: pointer;
    font-size: 0.9rem;
    border-bottom: 2px solid transparent;
    transition: all 0.15s;
  }

  .tab:hover {
    color: var(--text);
  }

  .tab.active {
    color: var(--text);
    border-bottom-color: var(--accent);
  }

  .tab-content {
    min-height: 200px;
  }

  .loading, .empty {
    text-align: center;
    color: var(--text-muted);
    padding: 40px;
  }

  .list {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .list-item {
    background: var(--surface);
    padding: 14px 16px;
    border-radius: 6px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .list-item.unread {
    border-left: 3px solid var(--accent);
  }

  .item-main {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .item-name {
    font-weight: 500;
  }

  .item-type.badge {
    font-size: 0.7rem;
    padding: 2px 8px;
    border-radius: 4px;
    background: rgba(255, 255, 255, 0.08);
    color: var(--text-muted);
    text-transform: uppercase;
  }

  .item-meta {
    display: flex;
    gap: 12px;
  }

  .item-status.active {
    color: var(--success);
    font-size: 0.85rem;
  }

  .item-status.inactive {
    color: var(--text-muted);
    font-size: 0.85rem;
  }

  .item-time {
    font-size: 0.8rem;
    color: var(--text-muted);
  }

  .item-detail {
    font-size: 0.85rem;
    color: var(--text-muted);
  }

  .item-actions {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
  }

  .btn-small {
    background: var(--accent);
    color: white;
    border: none;
    padding: 6px 12px;
    border-radius: 4px;
    font-size: 0.8rem;
    cursor: pointer;
  }

  .btn-small:hover {
    opacity: 0.9;
  }

  .error-text {
    color: var(--error);
    font-size: 0.9rem;
    margin-bottom: 12px;
  }
</style>

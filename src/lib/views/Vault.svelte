<script lang="ts">
    import { sessionStore } from '../stores/session';
    import { initVaultListeners } from '../stores/vault';
    import { selectedConnectionStore } from '../stores/navigation';
    import PendingApproval from '../components/PendingApproval.svelte';

    // Feature views
    import ConnectionsList from './vault/ConnectionsList.svelte';
    import MessagingView from './vault/MessagingView.svelte';
    import SecretsView from './vault/SecretsView.svelte';
    import FeedView from './vault/FeedView.svelte';
    import VotingView from './vault/VotingView.svelte';
    import WalletView from './vault/WalletView.svelte';
    import DevicesView from './vault/DevicesView.svelte';
    import ConnectionDetail from './vault/ConnectionDetail.svelte';
    import Conversation from './vault/Conversation.svelte';

    type TabId = 'connections' | 'messages' | 'secrets' | 'feed' | 'voting' | 'wallets' | 'devices';

    const tabs: { id: TabId; label: string }[] = [
        { id: 'connections', label: 'Connections' },
        { id: 'messages', label: 'Messages' },
        { id: 'secrets', label: 'Secrets' },
        { id: 'feed', label: 'Feed' },
        { id: 'voting', label: 'Voting' },
        { id: 'wallets', label: 'Wallets' },
        { id: 'devices', label: 'Devices' },
    ];

    let session = $derived($sessionStore);
    let activeTab = $state<TabId>('feed');
    let selectedConnection = $derived($selectedConnectionStore);

    // When a connection is open, this toggles between the Conversation
    // (default) and the read-only ConnectionDetail (profile/manage).
    let detailMode = $state<'conversation' | 'profile'>('conversation');

    // Reset to conversation view whenever a different connection is opened.
    $effect(() => {
        if (selectedConnection) detailMode = 'conversation';
    });

    // Pending approval overlay
    let pendingApproval = $state<{ operation: string; requestId: string } | null>(null);

    // Initialize real-time event listeners
    $effect(() => { initVaultListeners(); });
</script>

<div class="vault-container">
    {#if session.state !== 'active'}
        <div class="inactive-overlay">
            <div class="inactive-message">
                <h3>Session {session.state}</h3>
                <p>
                    {#if session.state === 'inactive'}
                        Unlock your credentials to access the vault.
                    {:else if session.state === 'suspended'}
                        Session suspended — phone may be unreachable.
                    {:else if session.state === 'expired'}
                        Session expired. Re-authenticate from your phone.
                    {:else if session.state === 'revoked'}
                        Session revoked by vault owner.
                    {/if}
                </p>
            </div>
        </div>
    {:else}
        <!-- Tab bar -->
        <div class="tab-bar" role="tablist">
            {#each tabs as tab}
                <button
                    class="tab"
                    class:active={activeTab === tab.id}
                    onclick={() => activeTab = tab.id}
                    role="tab"
                    aria-selected={activeTab === tab.id}
                >
                    {tab.label}
                </button>
            {/each}
        </div>

        <!-- Tab content. When a connection is selected, ConnectionDetail
             takes over the panel regardless of which tab is active — the
             back arrow returns to the previous tab. -->
        <div class="tab-content" role="tabpanel">
            {#if selectedConnection && detailMode === 'profile'}
                <ConnectionDetail connection={selectedConnection} />
            {:else if selectedConnection}
                <Conversation
                    connection={selectedConnection}
                    onShowProfile={() => detailMode = 'profile'}
                />
            {:else if activeTab === 'connections'}
                <ConnectionsList />
            {:else if activeTab === 'messages'}
                <MessagingView />
            {:else if activeTab === 'secrets'}
                <SecretsView />
            {:else if activeTab === 'feed'}
                <FeedView />
            {:else if activeTab === 'voting'}
                <VotingView />
            {:else if activeTab === 'wallets'}
                <WalletView />
            {:else if activeTab === 'devices'}
                <DevicesView />
            {/if}
        </div>
    {/if}

    <!-- Pending phone approval overlay -->
    {#if pendingApproval}
        <PendingApproval
            operation={pendingApproval.operation}
            requestId={pendingApproval.requestId}
        />
    {/if}
</div>

<style>
    .vault-container {
        height: 100%;
        display: flex;
        flex-direction: column;
        position: relative;
    }

    .inactive-overlay {
        display: flex;
        align-items: center;
        justify-content: center;
        height: 100%;
    }

    .inactive-message {
        text-align: center;
        color: var(--text-secondary);
    }

    .inactive-message h3 {
        text-transform: capitalize;
        margin-bottom: 8px;
    }

    .tab-bar {
        display: flex;
        border-bottom: 1px solid var(--border);
        padding: 0 12px;
        gap: 4px;
        flex-shrink: 0;
        overflow-x: auto;
    }

    .tab {
        padding: 10px 16px;
        border: none;
        background: none;
        cursor: pointer;
        font-size: 0.9em;
        color: var(--text-secondary);
        border-bottom: 2px solid transparent;
        white-space: nowrap;
    }

    .tab:hover {
        color: var(--text-primary);
    }

    .tab.active {
        color: var(--accent);
        border-bottom-color: var(--accent);
        font-weight: 500;
    }

    .tab-content {
        flex: 1;
        overflow: hidden;
        padding: 16px;
    }
</style>

<script lang="ts">
    import { invoke } from '@tauri-apps/api/core';
    import type { Proposal, VaultOpResponse } from '../../types';

    let proposals: Proposal[] = $state([]);
    let loading = $state(true);
    let error = $state('');
    let voteError = $state('');

    async function loadProposals() {
        loading = true; error = '';
        try {
            const resp: VaultOpResponse = await invoke('list_proposals');
            if (resp.success && resp.data) {
                const data = resp.data as { proposals?: Proposal[] };
                proposals = data.proposals ?? [];
            } else { error = resp.error ?? 'Failed to load proposals'; }
        } catch (e) { error = String(e); }
        loading = false;
    }

    async function castVote(proposalId: string, choice: string) {
        voteError = '';
        try {
            const resp: VaultOpResponse = await invoke('cast_vote', { proposalId, choice });
            if (resp.pending_approval) {
                // Phone approval needed — will resolve via event
            } else if (resp.success) {
                await loadProposals();
            } else {
                voteError = resp.error ?? 'Vote failed';
            }
        } catch (e) {
            voteError = `Vote failed: ${e}`;
        }
    }

    $effect(() => { loadProposals(); });
</script>

<div class="voting-view">
    <div class="header"><h3>Voting</h3><button class="refresh" aria-label="Refresh" onclick={loadProposals}>↻</button></div>

    {#if loading}<div class="status">Loading proposals...</div>
    {:else if error}<div class="status error">{error}</div>
    {:else if proposals.length === 0}<div class="status">No proposals</div>
    {:else}
        <ul class="proposal-list">
            {#each proposals as p}
                <li class="proposal-item">
                    <div class="proposal-header">
                        <span class="proposal-title">{p.title}</span>
                        <span class="status-badge {p.status}">{p.status}</span>
                    </div>
                    <div class="proposal-desc">{p.description}</div>
                    {#if voteError}
                        <div class="vote-error">{voteError}</div>
                    {/if}
                    {#if p.status === 'open' && !p.my_vote}
                        <div class="vote-actions">
                            <button onclick={() => castVote(p.id, 'yes')}>Yes</button>
                            <button onclick={() => castVote(p.id, 'no')}>No</button>
                            <button onclick={() => castVote(p.id, 'abstain')}>Abstain</button>
                            <span class="phone-hint">Requires phone approval</span>
                        </div>
                    {:else if p.my_vote}
                        <div class="my-vote">Voted: {p.my_vote}</div>
                    {/if}
                </li>
            {/each}
        </ul>
    {/if}
</div>

<style>
    .voting-view { height: 100%; display: flex; flex-direction: column; }
    .header { display: flex; justify-content: space-between; align-items: center; padding: 0 0 12px; }
    .header h3 { margin: 0; }
    .refresh { background: none; border: 1px solid var(--border); border-radius: 4px; cursor: pointer; padding: 4px 8px; }
    .status { color: var(--text-secondary); padding: 24px; text-align: center; }
    .status.error { color: var(--danger); }
    .proposal-list { list-style: none; padding: 0; margin: 0; overflow-y: auto; flex: 1; }
    .proposal-item { padding: 16px; border-bottom: 1px solid var(--border); }
    .proposal-header { display: flex; justify-content: space-between; align-items: center; }
    .proposal-title { font-weight: 600; }
    .proposal-desc { color: var(--text-secondary); font-size: 0.9em; margin: 4px 0; }
    .status-badge { padding: 2px 6px; border-radius: 3px; font-size: 0.8em; }
    .status-badge.open { background: #e8f5e9; color: #2e7d32; }
    .status-badge.closed { background: #eeeeee; color: #616161; }
    .vote-actions { display: flex; gap: 8px; margin-top: 8px; align-items: center; }
    .vote-actions button { padding: 4px 12px; border: 1px solid var(--border); border-radius: 4px; background: none; cursor: pointer; }
    .vote-actions button:hover { background: var(--bg-hover); }
    .phone-hint { font-size: 0.75em; color: var(--text-secondary); }
    .my-vote { font-size: 0.85em; color: var(--accent); margin-top: 4px; }
    .vote-error { font-size: 0.8em; color: var(--danger); margin-top: 4px; }
</style>

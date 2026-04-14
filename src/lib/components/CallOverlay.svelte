<script lang="ts">
    import { onMount } from 'svelte';
    import {
        currentCallStore,
        acceptCall,
        declineCall,
        hangUp,
        type ActiveCall,
    } from '../stores/calls';

    let call = $derived($currentCallStore);

    // Live duration counter when active. We avoid an interval when not active
    // so an idle call screen doesn't burn render cycles.
    let now = $state(Date.now());
    let intervalId: ReturnType<typeof setInterval> | undefined;

    $effect(() => {
        if (call?.state === 'active') {
            now = Date.now();
            intervalId = setInterval(() => (now = Date.now()), 1000);
            return () => { if (intervalId) clearInterval(intervalId); };
        }
        return undefined;
    });

    function elapsedString(call: ActiveCall): string {
        if (!call.activeSince) return '';
        const seconds = Math.floor((now - call.activeSince) / 1000);
        const m = Math.floor(seconds / 60);
        const s = seconds % 60;
        return `${m}:${s.toString().padStart(2, '0')}`;
    }

    function stateLabel(c: ActiveCall): string {
        switch (c.state) {
            case 'ringing':    return 'Incoming call…';
            case 'dialing':    return 'Calling…';
            case 'connecting': return 'Connecting…';
            case 'active':     return elapsedString(c);
            case 'ended':      return c.error ?? 'Call ended';
        }
    }
</script>

{#if call}
    <div class="overlay">
        <div class="card">
            <div class="avatar" aria-hidden="true">
                <span class="initials">
                    {(call.peerDisplayName || '?').slice(0, 1).toUpperCase()}
                </span>
            </div>
            <div class="name">{call.peerDisplayName || 'Unknown'}</div>
            <div class="state">{stateLabel(call)}</div>
            <div class="type-badge">{call.callType}</div>

            <div class="media-warning">
                Media not yet implemented — signaling only.
            </div>

            <div class="actions">
                {#if call.state === 'ringing'}
                    <button class="decline" onclick={() => declineCall(call)}>Decline</button>
                    <button class="accept" onclick={() => acceptCall(call)}>Accept</button>
                {:else if call.state === 'dialing' || call.state === 'connecting' || call.state === 'active'}
                    <button class="end" onclick={() => hangUp(call)}>End call</button>
                {/if}
            </div>
        </div>
    </div>
{/if}

<style>
    .overlay {
        position: fixed;
        inset: 0;
        background: rgba(0, 0, 0, 0.7);
        backdrop-filter: blur(4px);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 1000;
    }

    .card {
        background: #1a1a1a;
        border: 1px solid var(--border, rgba(255,255,255,0.1));
        border-radius: 12px;
        padding: 32px 40px;
        max-width: 380px;
        text-align: center;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
    }

    .avatar {
        width: 96px;
        height: 96px;
        border-radius: 50%;
        background: rgba(255, 193, 37, 0.15);
        margin: 0 auto 16px;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .initials { font-size: 2.5em; font-weight: 600; color: #ffc125; }

    .name { font-size: 1.3em; font-weight: 500; margin-bottom: 4px; }
    .state { color: var(--text-secondary, #888); font-size: 0.95em; }

    .type-badge {
        display: inline-block;
        margin-top: 8px;
        padding: 2px 10px;
        background: rgba(255, 193, 37, 0.15);
        color: #ffc125;
        font-size: 0.75em;
        border-radius: 10px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    .media-warning {
        margin-top: 16px;
        padding: 8px 12px;
        background: rgba(255, 152, 0, 0.1);
        color: #ff9800;
        font-size: 0.8em;
        border-radius: 4px;
    }

    .actions {
        display: flex;
        gap: 12px;
        justify-content: center;
        margin-top: 24px;
    }

    .actions button {
        padding: 12px 28px;
        border: none;
        border-radius: 24px;
        font-size: 0.95em;
        font-weight: 500;
        cursor: pointer;
        font-family: inherit;
    }

    .accept { background: #4caf50; color: white; }
    .decline, .end {
        background: #f44336;
        color: white;
    }
</style>

<script lang="ts">
    import { invoke } from '@tauri-apps/api/core';
    import { listen } from '@tauri-apps/api/event';
    import type { Profile, PersonalDataItem, VaultOpResponse } from '../../types';

    interface ProfileFields {
        first_name?: string;
        last_name?: string;
        email?: string;
        phone?: string;
        photo?: string;
        public_key?: string;
        wallet_addresses?: string[];
        [key: string]: unknown;
    }

    let profile = $state<Profile | null>(null);
    let fields = $state<ProfileFields>({});
    let personalData = $state<Record<string, PersonalDataItem[]>>({});
    let loading = $state(true);
    let saving = $state(false);
    let error = $state('');
    let editing = $state(false);
    let pendingPhoneApproval = $state(false);

    // Editable copy — kept separate from the source-of-truth `fields` so
    // cancel discards user input cleanly.
    let editFields = $state<ProfileFields>({});

    async function loadProfile() {
        loading = true;
        error = '';
        try {
            const resp: VaultOpResponse = await invoke('get_profile');
            if (resp.success && resp.data) {
                const data = resp.data as { profile?: Profile; fields?: ProfileFields };
                profile = data.profile ?? null;
                fields = data.fields ?? {};
            } else if (resp.error) {
                error = resp.error;
            }

            const pdResp: VaultOpResponse = await invoke('list_personal_data');
            if (pdResp.success && pdResp.data) {
                const data = pdResp.data as { sections?: Record<string, PersonalDataItem[]> };
                personalData = data.sections ?? {};
            }
        } catch (e) {
            error = String(e);
        }
        loading = false;
    }

    function startEdit() {
        editFields = { ...fields };
        editing = true;
    }

    function cancelEdit() {
        editing = false;
        editFields = {};
    }

    async function saveProfile() {
        if (saving) return;
        saving = true;
        error = '';
        try {
            // Build the field-update payload — only include keys that
            // changed to keep the phone-approval prompt minimal.
            const changed: Record<string, { value: unknown }> = {};
            for (const [k, v] of Object.entries(editFields)) {
                if (fields[k] !== v) changed[k] = { value: v };
            }
            if (Object.keys(changed).length === 0) {
                editing = false;
                saving = false;
                return;
            }

            const resp: VaultOpResponse = await invoke('update_profile', {
                fields: changed,
            });
            if (resp.success) {
                fields = { ...fields, ...editFields };
                editing = false;
            } else if (resp.pending_approval) {
                pendingPhoneApproval = true;
            } else {
                error = resp.error ?? 'Update failed';
            }
        } catch (e) {
            error = String(e);
        }
        saving = false;
    }

    function fullName(): string {
        const f = `${fields.first_name ?? ''} ${fields.last_name ?? ''}`.trim();
        return f || profile?.display_name || 'You';
    }

    function avatarSrc(): string | null {
        const photo = fields.photo ?? profile?.photo_data;
        if (!photo) return null;
        return photo.startsWith('data:') ? photo : `data:image/png;base64,${photo}`;
    }

    $effect(() => { loadProfile(); });

    // Refresh on push — `vault:profile-update` fires both for own updates
    // (after phone approves) and for peer updates.
    $effect(() => {
        const unlisten = listen('vault:profile-update', () => {
            pendingPhoneApproval = false;
            loadProfile();
        });
        return () => { unlisten.then((fn) => fn()); };
    });
</script>

<div class="profile-view">
    <div class="header">
        <h3>Profile</h3>
        {#if !editing}
            <button class="edit-btn" onclick={startEdit} disabled={loading}>Edit</button>
        {/if}
    </div>

    {#if loading}
        <div class="status">Loading…</div>
    {:else if error}
        <div class="status error">{error}</div>
    {:else}
        <div class="scroll">
            {#if pendingPhoneApproval}
                <div class="phone-banner">
                    Waiting for phone approval to publish profile changes…
                </div>
            {/if}

            <!-- Identity card -->
            <section class="card">
                <div class="identity">
                    <div class="avatar">
                        {#if avatarSrc()}
                            <img src={avatarSrc()} alt="" />
                        {:else}
                            <span class="initials">{fullName().slice(0, 1).toUpperCase()}</span>
                        {/if}
                    </div>
                    <div class="identity-text">
                        {#if editing}
                            <div class="name-edit">
                                <input bind:value={editFields.first_name} placeholder="First name" />
                                <input bind:value={editFields.last_name} placeholder="Last name" />
                            </div>
                        {:else}
                            <div class="name">{fullName()}</div>
                            {#if profile?.guid}
                                <div class="guid mono">{profile.guid.slice(0, 12)}…</div>
                            {/if}
                        {/if}
                    </div>
                </div>
            </section>

            <!-- Contact -->
            <section class="card">
                <h4>Contact</h4>
                <div class="row">
                    <span class="label">Email</span>
                    {#if editing}
                        <input class="value-input" type="email" bind:value={editFields.email} placeholder="you@example.com" />
                    {:else}
                        <span class="value">{fields.email || '—'}</span>
                    {/if}
                </div>
                <div class="row">
                    <span class="label">Phone</span>
                    {#if editing}
                        <input class="value-input" type="tel" bind:value={editFields.phone} placeholder="+1…" />
                    {:else}
                        <span class="value">{fields.phone || '—'}</span>
                    {/if}
                </div>
            </section>

            <!-- Public keys & addresses -->
            {#if !editing}
                <section class="card">
                    <h4>Public identifiers</h4>
                    {#if fields.public_key}
                        <div class="row">
                            <span class="label">Public key</span>
                            <span class="value mono truncate">{fields.public_key}</span>
                        </div>
                    {/if}
                    {#if fields.wallet_addresses && fields.wallet_addresses.length > 0}
                        {#each fields.wallet_addresses as addr}
                            <div class="row">
                                <span class="label">BTC address</span>
                                <span class="value mono truncate">{addr}</span>
                            </div>
                        {/each}
                    {/if}
                </section>
            {/if}

            <!-- Personal data sections -->
            {#each Object.entries(personalData) as [section, items]}
                {#if items.length > 0}
                    <section class="card">
                        <h4>{section}</h4>
                        {#each items as item}
                            <div class="row">
                                <span class="label">{item.display_name}</span>
                                <span class="value">{item.value}</span>
                            </div>
                        {/each}
                    </section>
                {/if}
            {/each}

            {#if editing}
                <div class="actions">
                    <button class="cancel" onclick={cancelEdit} disabled={saving}>Cancel</button>
                    <button class="save" onclick={saveProfile} disabled={saving}>
                        {saving ? 'Saving…' : 'Save (requires phone)'}
                    </button>
                </div>
            {/if}
        </div>
    {/if}
</div>

<style>
    .profile-view { height: 100%; display: flex; flex-direction: column; }
    .header { display: flex; justify-content: space-between; align-items: center; padding: 0 0 12px; }
    .header h3 { margin: 0; }
    .edit-btn {
        background: var(--accent);
        color: #000;
        border: none;
        border-radius: 4px;
        padding: 6px 14px;
        cursor: pointer;
        font-weight: 500;
    }
    .edit-btn:disabled { opacity: 0.5; cursor: not-allowed; }

    .status { padding: 24px; text-align: center; color: var(--text-secondary); }
    .status.error { color: var(--danger); }

    .scroll { flex: 1; overflow-y: auto; }

    .phone-banner {
        background: rgba(255, 193, 37, 0.15);
        color: #ffc125;
        padding: 10px 14px;
        border-radius: 6px;
        margin-bottom: 12px;
        font-size: 0.9em;
    }

    .card {
        background: var(--surface, #1a1a1a);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
    }
    .card h4 {
        margin: 0 0 12px;
        font-size: 0.8em;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--text-secondary);
    }

    .identity { display: flex; gap: 14px; align-items: center; }
    .avatar {
        width: 64px; height: 64px;
        border-radius: 50%;
        background: var(--accent-muted, #333);
        display: flex; align-items: center; justify-content: center;
        overflow: hidden;
    }
    .avatar img { width: 100%; height: 100%; object-fit: cover; }
    .initials { font-size: 1.6em; font-weight: 600; color: var(--accent); }
    .identity-text { flex: 1; }
    .name { font-size: 1.15em; font-weight: 500; }
    .name-edit { display: flex; gap: 8px; }
    .name-edit input {
        flex: 1;
        padding: 6px 10px;
        background: #1c1c1c;
        color: inherit;
        border: 1px solid var(--border);
        border-radius: 4px;
    }
    .guid { color: var(--text-secondary); font-size: 0.8em; margin-top: 2px; }

    .row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 8px 0;
        border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        gap: 12px;
    }
    .row:last-child { border-bottom: none; }
    .label { color: var(--text-secondary); font-size: 0.85em; flex-shrink: 0; }
    .value { font-size: 0.9em; text-align: right; word-break: break-word; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.8em; }
    .truncate { max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .value-input {
        background: #1c1c1c;
        color: inherit;
        border: 1px solid var(--border);
        border-radius: 4px;
        padding: 4px 8px;
        font: inherit;
        text-align: right;
        max-width: 240px;
    }

    .actions {
        display: flex;
        gap: 8px;
        justify-content: flex-end;
        margin-top: 8px;
    }
    .cancel, .save {
        padding: 8px 14px;
        border-radius: 4px;
        border: 1px solid var(--border);
        cursor: pointer;
        font: inherit;
    }
    .cancel { background: transparent; color: inherit; }
    .save { background: var(--accent); color: #000; border-color: var(--accent); font-weight: 500; }
    .cancel:disabled, .save:disabled { opacity: 0.5; cursor: not-allowed; }
</style>

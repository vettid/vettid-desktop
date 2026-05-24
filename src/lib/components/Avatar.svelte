<script lang="ts">
  // Circular avatar with connection-type awareness. Mirrors the
  // Android ConnectionAvatar (see vettid-android FeedScreen.kt ~1660):
  //   - system  → VettID shield logo (no shape clipping; the asset is
  //                already a shield silhouette)
  //   - device  → desktop-window glyph on the brand gold
  //   - agent   → small computer glyph on a contrasting circle
  //   - peer    → photo if present, else deterministic-color initials
  import vettidLogo from '../../assets/vettid-logo.png';

  type ConnectionType = 'peer' | 'system' | 'device' | 'agent' | (string & {});

  interface Props {
    name: string;
    photo?: string;
    size?: number;
    connectionType?: ConnectionType;
  }
  let { name, photo, size = 40, connectionType = 'peer' }: Props = $props();

  function initials(s: string): string {
    const parts = s.trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) return '?';
    if (parts.length === 1) return parts[0]!.slice(0, 1).toUpperCase();
    return (parts[0]![0]! + parts[parts.length - 1]![0]!).toUpperCase();
  }

  function hue(s: string): number {
    // Cheap deterministic string→hue. Stable across launches without
    // needing a hash library.
    let h = 0;
    for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
    return Math.abs(h) % 360;
  }
</script>

{#if connectionType === 'system'}
  <img
    class="avatar logo"
    src={vettidLogo}
    alt="VettID"
    style="width:{size}px;height:{size}px;"
  />
{:else if connectionType === 'device'}
  <span
    class="avatar tile device"
    style="width:{size}px;height:{size}px;"
    aria-label="Desktop"
    title="Desktop"
  >
    <!-- DesktopWindows-equivalent glyph: monitor with a stand. -->
    <svg viewBox="0 0 24 24" width={Math.round(size * 0.55)} height={Math.round(size * 0.55)} aria-hidden="true">
      <path fill="currentColor" d="M21 3H3a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h7l-1 3H7v2h10v-2h-2l-1-3h7a2 2 0 0 0 2-2V5a2 2 0 0 0-2-2zm0 13H3V5h18z" />
    </svg>
  </span>
{:else if connectionType === 'agent'}
  <span
    class="avatar tile agent"
    style="width:{size}px;height:{size}px;"
    aria-label="Agent"
    title="Agent"
  >
    <svg viewBox="0 0 24 24" width={Math.round(size * 0.55)} height={Math.round(size * 0.55)} aria-hidden="true">
      <path fill="currentColor" d="M2 4h20v14H2zm2 2v10h16V6zM4 18h16v2H4z" />
    </svg>
  </span>
{:else}
  <div
    class="avatar"
    style="width:{size}px;height:{size}px;font-size:{Math.round(size * 0.4)}px;"
  >
    {#if photo}
      <img src={`data:image/png;base64,${photo}`} alt="" />
    {:else}
      <span
        class="initials"
        style="background:hsl({hue(name)},42%,28%);color:hsl({hue(name)},55%,85%);"
      >{initials(name)}</span>
    {/if}
  </div>
{/if}

<style>
  .avatar {
    border-radius: 50%;
    overflow: hidden;
    flex-shrink: 0;
    display: inline-block;
    line-height: 0;
  }
  .avatar.logo {
    /* Shield silhouette is already its own shape — drop the circular
       clip so the asset doesn't get cropped at the corners. */
    border-radius: 0;
    object-fit: contain;
  }
  .avatar.tile {
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }
  .avatar.tile.device {
    background: var(--accent);
    color: #1a1a1a;
  }
  .avatar.tile.agent {
    background: rgba(120, 160, 240, 0.18);
    color: #b9d0ff;
  }
  img {
    width: 100%;
    height: 100%;
    object-fit: cover;
    display: block;
  }
  .initials {
    width: 100%;
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 600;
    letter-spacing: 0.02em;
    line-height: 1;
  }
</style>

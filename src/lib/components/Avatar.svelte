<script lang="ts">
  // Circular avatar — peer's base64 photo if present, else colored
  // initials on a deterministic per-name background. The same name
  // gets the same color everywhere in the app.
  interface Props {
    name: string;
    photo?: string;
    size?: number;
  }
  let { name, photo, size = 40 }: Props = $props();

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

<style>
  .avatar {
    border-radius: 50%;
    overflow: hidden;
    flex-shrink: 0;
    display: inline-block;
    line-height: 0;
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

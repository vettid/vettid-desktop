<script lang="ts">
  // Phase 2 placeholder. The full Connections surface (list +
  // detail + conversation + invite) lands in Phase 5 of
  // DESKTOP-REWORK-PLAN.md. This stub exists so the new top-bar
  // chrome can ship without leaving the Connections rail entry
  // pointing at nothing.
</script>

<div class="wrap">
  <div class="placeholder">
    <h1>Connections</h1>
    <p>
      Your peer connections will live here — connection list, messaging,
      voice + video calls. Coming in Phase 5 of the desktop rework.
    </p>
    <p class="hint">
      For now, manage your connections from the VettID app on your phone.
    </p>
  </div>
</div>

<style>
  .wrap {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 40px;
  }
  .placeholder {
    text-align: center;
    max-width: 440px;
  }
  h1 {
    font-size: 1.4rem;
    margin-bottom: 12px;
  }
  p {
    color: var(--text-muted);
    line-height: 1.55;
    margin-bottom: 8px;
  }
  .hint {
    color: var(--text-subtle);
    font-size: 0.9rem;
  }
</style>

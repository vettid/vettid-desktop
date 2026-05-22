<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';
  import QRCode from 'qrcode';

  // --- Receive BTC sheet ----------------------------------------------
  //
  // Shows a wallet's receive address as text + a QR code. `wallet.get-
  // address` is an independent op (no phone approval) so this loads
  // immediately. The QR is rendered to a data-URL via the `qrcode`
  // package (already a project dependency) and shown in an <img>.

  interface WalletItem {
    wallet_id: string;
    label: string;
    address: string;
    network: string;
  }

  interface Props {
    wallet: WalletItem;
    onClose: () => void;
  }

  let { wallet, onClose }: Props = $props();

  // Start from the address already on the wallet card so the QR can
  // render instantly; refresh from the vault in case the wallet uses
  // rotating receive addresses. The parent re-mounts this component
  // per-open, so the initial prop capture is intentional.
  // svelte-ignore state_referenced_locally
  let address = $state(wallet.address ?? '');
  let loading = $state(true);
  let errorMessage = $state('');
  let qrDataUrl = $state('');
  let copied = $state(false);

  async function loadAddress() {
    loading = true;
    errorMessage = '';
    try {
      const resp: any = await invoke('get_wallet_address', { walletId: wallet.wallet_id });
      if (resp?.success && resp?.data) {
        const a = String(resp.data.address ?? resp.data.receive_address ?? '');
        if (a) address = a;
      } else if (!address) {
        errorMessage = resp?.error || 'Could not load the receive address.';
      }
    } catch (e) {
      if (!address) errorMessage = `Could not load the receive address: ${e}`;
    } finally {
      loading = false;
    }
  }

  // Re-render the QR whenever the address changes.
  $effect(() => {
    const a = address;
    if (!a) {
      qrDataUrl = '';
      return;
    }
    // The QR encodes a BIP-21 URI so wallet apps that scan it pre-fill
    // the address. Plain-address fallback would also work, but the URI
    // is the conventional, widely-supported form.
    QRCode.toDataURL(`bitcoin:${a}`, {
      errorCorrectionLevel: 'M',
      margin: 2,
      width: 220,
      color: { dark: '#1c1917', light: '#ffffff' },
    })
      .then((url) => { qrDataUrl = url; })
      .catch(() => { qrDataUrl = ''; });
  });

  onMount(() => { loadAddress(); });

  async function copyAddress() {
    if (!address) return;
    try {
      await navigator.clipboard.writeText(address);
      copied = true;
      setTimeout(() => { copied = false; }, 1800);
    } catch (e) {
      // Clipboard may be denied in some Tauri configs — fail quietly.
    }
  }
</script>

<div class="modal-backdrop" onclick={onClose} role="presentation"></div>
<div class="modal receive-modal" role="dialog" aria-modal="true" aria-label="Receive Bitcoin">
  <header class="modal-head">
    <h2>Receive Bitcoin</h2>
    <button class="x-btn" onclick={onClose} aria-label="Close">✕</button>
  </header>

  <div class="body">
    <p class="wallet-name">{wallet.label || 'Untitled wallet'}</p>

    {#if loading && !address}
      <div class="loading-wrap"><span class="spinner"></span></div>
    {:else if errorMessage && !address}
      <div class="error">{errorMessage}</div>
    {:else}
      <div class="qr-frame">
        {#if qrDataUrl}
          <img src={qrDataUrl} alt="Receive address QR code" width="220" height="220" />
        {:else}
          <div class="qr-placeholder"><span class="spinner"></span></div>
        {/if}
      </div>

      <div class="detail-label">Receive address</div>
      <div class="address-box">
        <span class="mono">{address}</span>
      </div>

      <button class="btn primary full" onclick={copyAddress}>
        {copied ? 'Copied ✓' : 'Copy address'}
      </button>

      <p class="hint">
        Share this address — or have the sender scan the QR — to receive Bitcoin into
        this wallet. Receiving never needs phone approval.
      </p>
    {/if}
  </div>
</div>

<style>
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
    z-index: 100;
    backdrop-filter: blur(2px);
  }
  .modal {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    z-index: 101;
    background: var(--surface);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 12px;
    width: 380px;
    max-width: calc(100vw - 48px);
    box-shadow: 0 18px 50px rgba(0, 0, 0, 0.5);
  }
  .modal-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 18px 22px 8px;
  }
  .modal-head h2 {
    font-size: 1.05rem;
    margin: 0;
    font-weight: 600;
  }
  .x-btn {
    background: transparent;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    font-size: 0.95rem;
    padding: 2px 6px;
    border-radius: 4px;
  }
  .x-btn:hover { background: rgba(255, 255, 255, 0.08); color: var(--text); }

  .body {
    padding: 6px 22px 22px;
    text-align: center;
  }
  .wallet-name {
    font-size: 0.85rem;
    color: var(--text-muted);
    margin: 0 0 14px;
  }

  .qr-frame {
    display: flex;
    align-items: center;
    justify-content: center;
    background: #ffffff;
    border-radius: 10px;
    padding: 14px;
    width: fit-content;
    margin: 0 auto 16px;
  }
  .qr-frame img { display: block; }
  .qr-placeholder {
    width: 220px;
    height: 220px;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .detail-label {
    font-size: 0.7rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 6px;
    text-align: left;
  }
  .address-box {
    background: var(--bg);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 6px;
    padding: 8px 10px;
    margin-bottom: 12px;
    text-align: left;
  }
  .mono {
    font-family: 'JetBrains Mono', 'Consolas', monospace;
    font-size: 0.82rem;
    color: var(--text);
    word-break: break-all;
  }

  .btn {
    padding: 9px 16px;
    border-radius: 6px;
    cursor: pointer;
    font: inherit;
    font-size: 0.9rem;
    border: 1px solid transparent;
  }
  .btn.full { width: 100%; }
  .btn.primary {
    background: var(--accent);
    color: #1a1a1a;
    font-weight: 600;
  }
  .btn.primary:hover { background: var(--accent-hover); }

  .hint {
    color: var(--text-subtle);
    font-size: 0.78rem;
    margin: 14px 0 0;
    line-height: 1.5;
  }
  .error {
    background: rgba(244, 67, 54, 0.1);
    border: 1px solid rgba(244, 67, 54, 0.25);
    color: var(--error);
    padding: 10px 14px;
    border-radius: 6px;
    font-size: 0.85rem;
  }
  .loading-wrap { display: flex; justify-content: center; padding: 40px 0; }
  .spinner {
    width: 26px;
    height: 26px;
    border: 3px solid rgba(255, 255, 255, 0.1);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: recv-spin 0.9s linear infinite;
  }
  @keyframes recv-spin { to { transform: rotate(360deg); } }
</style>

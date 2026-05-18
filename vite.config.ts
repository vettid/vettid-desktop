import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// Vite injects `crossorigin` on the module-script + stylesheet tags
// it generates. WebKit2GTK (Linux Tauri's webview) treats that as a
// CORS-mode fetch and refuses the response from the tauri:// asset
// protocol — the window paints the page background but the JS never
// executes, so the Svelte app never mounts. Stripping the attribute
// keeps the script as a plain same-origin module load. macOS/Windows
// WebViews accept either form so this is safe across platforms.
function stripCrossOriginAttribute() {
  return {
    name: "strip-crossorigin-for-tauri-webkit",
    enforce: "post" as const,
    transformIndexHtml(html: string) {
      return html.replace(/\s+crossorigin(?=[\s>])/g, "");
    },
  };
}

export default defineConfig({
  plugins: [svelte(), stripCrossOriginAttribute()],
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
  },
  envPrefix: ["VITE_", "TAURI_"],
  // @sveltejs/vite-plugin-svelte v4 (preview Svelte-5 support) doesn't
  // always pick the `browser` export condition for Svelte 5's
  // conditional exports — Vite ends up bundling Svelte's
  // index-server.js, whose `mount()` is a stub that throws
  // `lifecycle_function_unavailable: mount(...) is not available on
  // the server`. Pinning conditions explicitly forces the client entry.
  resolve: {
    conditions: ["browser", "module", "import", "default"],
  },
  build: {
    target: "esnext",
    minify: !process.env.TAURI_DEBUG ? "esbuild" : false,
    sourcemap: !!process.env.TAURI_DEBUG,
  },
});

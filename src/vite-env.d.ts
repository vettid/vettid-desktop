/// <reference types="vite/client" />

// Brings in Vite's ambient module declarations for asset imports —
// `*.png`, `*.svg`, `*.jpg`, `*.css?inline`, etc. — so `import logo
// from '../assets/vettid-logo.png'` type-checks. Without this file,
// svelte-check emits "Cannot find module" for every static asset
// import even though Vite happily resolves them at build time.

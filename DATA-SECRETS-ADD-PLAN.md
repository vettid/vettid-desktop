# Desktop Add-Data + Add-Secret Plan

Bring the vettid-desktop client to feature parity with the Android app's
add-data and add-secret flows. Created 2026-05-22 after a screen-by-screen
audit of the Android Personal Data and Secrets surfaces.

## Why this matters

The desktop is **read-only** for both Personal Data and Secrets today
(Secrets.svelte even says so: "Add secrets from the VettID app on your
phone — desktop secret management is read-only for now"). This blocks
the desktop from being a real first-class client. The Android add flows
are extensive — 23 secret templates, 19 multi-field + 60+ single-field
personal-data templates, alias grouping, per-field input hints, edit,
delete — so the work is real.

Crucially, this was **only fixable at all** after today's `params` →
`payload` device-op field-name fix (vettid-desktop `2523cf7`). Without
that, any `secret.add` / `personal-data.update` from the desktop would
silently reach the vault with an empty payload.

## Decisions

- **Phased.** MVP (Phase 1) ships the Custom-field add path for both
  surfaces — the user can add anything on desktop, just without the
  template scaffolding. Templates land in Phase 2.
- **Mirror Android, don't reinvent.** Field input types, alias model,
  vault payload shapes all match the Android client so the same record
  reads identically on either device.
- **Use existing vault ops.** No backend changes — `secret.add`,
  `personal-data.update`, `secret.delete`, `personal-data.delete`,
  `credential.secret.add` are all in the vault today; the Android app
  is the reference implementation.
- **Out of scope this plan:** critical-secret credential-bound add
  (Phase 4 — it needs the credential blob crypto path which is
  desktop-side new code); discoverability toggles at create time
  (Android defaults to "cataloged" — we'll do the same; post-create
  toggles are already in the read-only surfaces).

## Vault ops reference

| Op | Use | Payload shape (key fields) |
|----|-----|----------------------------|
| `secret.add` | Add a minor secret | `{name, value, category, alias?, description?, discoverability:"cataloged"}` |
| `secret.update` | Edit a minor secret | `{id, name?, value?, alias?, category?, description?, discoverability?}` |
| `secret.delete` | Delete a minor secret | `{id}` |
| `personal-data.update` | Add or update one or more data fields | `{fields:{namespace:value,…}, aliases?:{namespace:alias,…}}` (upsert) |
| `personal-data.delete` | Delete fields | `{namespaces:["…","…"]}` |
| `credential.secret.add` | Add a critical (credential-bound) secret | `{name, category, description?, alias?, value:base64, encrypted_credential, encrypted_password_hash, ephemeral_public_key, nonce, key_id}` |

Add-secret routes through `execute_phone_required` (write ops need
phone approval); add-data is independent once the session is unlocked.

## Architecture

Both add flows follow the same shape:

1. Trigger — an **Add** button on the screen (Secrets / Personal Data).
2. **Template chooser sheet** (Phase 2+) → either pick a template or
   tap "Custom Field" to fall through to the form.
3. **Form sheet** — a modal sheet with the fields the template needs
   (or just name+category+value for custom), an alias field, a save
   button. Uses the existing `modal` action for focus-trap.
4. On save → invoke the matching Tauri command → vault op → close sheet
   → store updates → list re-renders.

Phase 1 ships the custom-field branch only (no template chooser yet);
Phase 2 builds the chooser and the template-driven form on top.

---

## Phase 1 — Custom-field add (MVP, this plan ships this)

Lets the user add a single data field or a single minor secret with
arbitrary name / category / value. No templates, no multi-field
grouping. Matches Android's "Custom Field" path.

### P1 — Backend

- **New Tauri command** `add_secret(name, value, category, alias?,
  description?)` in `commands/vault.rs`, phone-required (`secret.add`).
  Default `discoverability: "cataloged"` to match Android.
- `update_personal_data` is already wired — reuse for add (it's an
  upsert by namespace).

### P1 — UI

- **`AddSecretSheet.svelte`** (new, in `views/vault/secrets/`):
  category dropdown (SecretCategory enum mirrored from
  `SecretsModels.kt`), alias text, name text, value text + reveal
  toggle, optional notes. Save button → invoke `add_secret`. Uses
  `modal` action.
- **`AddDataFieldSheet.svelte`** (new, in `views/vault/personaldata/`):
  category dropdown (DataCategory enum mirrored from
  `PersonalDataModels.kt`), alias text, field name text, field type
  dropdown (TEXT/PASSWORD/NUMBER/DATE/EMAIL/PHONE/URL/NOTE), value
  with appropriate input. Save builds a namespace (`category.snake-name`)
  and calls `update_personal_data`.
- **Secrets.svelte** — add a primary "Add secret" button in the
  header; remove the read-only hint.
- **PersonalData.svelte** — add a primary "Add field" button in the
  header; ditto.

### P1 — Models

- **`secretModels.ts`** (new): TypeScript mirror of `SecretCategory`
  enum (`IDENTITY | LOGIN | CERTIFICATE | CRYPTOCURRENCY | …`).
- **`personalDataModels.ts`** (new): TypeScript mirror of `DataCategory`
  enum.

### P1 — Verification

Add a secret + a data field on desktop; confirm both appear in the
catalog on Android (round-trips through the vault).

---

## Phase 2 — Template-driven add

Mirrors Android's template chooser + multi-field forms.

- **Template definitions** — port `SecretsModels.kt` and
  `PersonalDataModels.kt` to TypeScript (`secretTemplates.ts`,
  `personalDataTemplates.ts`). One entry per template with `category`,
  `fields[]` (each field: name + `FieldInputHint` + optional dropdown
  data), optional `groupNamePrompt`.
- **`TemplateChooserSheet.svelte`** — shows "Custom Field" pinned at
  top + categorised template cards. On pick → opens
  `TemplateFormSheet`.
- **`TemplateFormSheet.svelte`** — renders the picked template's
  fields in order with the right input widget per hint (text /
  password-reveal / date picker / country dropdown / state dropdown
  / numeric / phone / email). Alias field + optional group-name
  prompt. Save iterates the fields and calls `secret.add` /
  `personal-data.update` for each non-blank value, sharing one alias
  and (for secrets) one `group_id`.
- **Crypto-network picker** for cryptocurrency category (mirrors
  Android `CryptoNetworks.all`).

Both add screens swap their primary "Add" button to open the
TemplateChooserSheet; the Custom Field tile in the chooser falls
through to the Phase 1 sheets.

## Phase 3 — Edit + delete

- Per-row edit on Secrets + PersonalData → opens the matching add
  sheet in "edit" mode pre-populated.
- New Tauri commands `update_secret`, `delete_secret`,
  `delete_personal_data_fields`.
- Personal Data category change → delete-then-re-add at the new
  namespace (matches Android).

## Phase 4 — Critical (credential-bound) secrets — CUT 2026-05-22

**Decision:** critical secrets are phone-only. The desktop will not gain
add/reveal for credential-bound secrets at any phase.

**Rationale:** the desktop has no encrypted credential blob, no password
salt, and no UTK pool — by design. `credential.secret.add` requires all
of those fields as inputs (vault rejects without them — see
`credential_secret_handler.go` HandleAdd validation). The two paths to
fix that — (1) mirroring Android's credential store on desktop, or
(2) adding a new phone-delegated vault op — were both rejected:
(1) violates the project's "no user data on device" principle, and
(2) wasn't worth the cross-repo lift for an op the user wants kept
on the phone anyway.

**What still works on desktop:** critical-secret metadata is visible
(`credential.secret.list` is in `DeviceIndependentCapabilities`) so
alias cards still show a Critical Secret row with the right
subtitle/badge. Reveal is gated — `isCredentialBound` in
`Secrets.svelte` returns early and tells the user the value is managed
on their phone.

## Risks / notes

- **Field-name discipline:** the desktop Connection type drifted from
  the vault (`label` vs `peer_alias`) and the device-op envelope used
  `params` vs the vault's `payload` — both shipped silently until they
  bit. When porting Android models, type the requests precisely against
  the Go structs (`SecretAddRequest`, the `personal-data.update`
  payload) and test at least one round-trip end-to-end before declaring
  a template "done".
- Personal-data **namespaces** are dot-separated strings the Android
  app constructs from template metadata (e.g. `address.home.street`).
  Custom-field add needs a stable namespace scheme — propose
  `custom.{category}.{slugified-name}`.
- `secret.add` is phone-required — every add prompts the user's
  phone. UI should show a "waiting for phone approval" state via
  the existing `pending_approval` response.

# macOS release (Developer ID, notarized)

The Apple silicon (`aarch64-apple-darwin`) app is signed with VettID's own
Developer ID Application certificate and notarized by Apple. Apple
notarizes but does not re-sign: the signature a member installs is VettID's.

## One-time steps (the owner)

1. In the Apple developer portal, create a **Developer ID Application**
   certificate and install it in the login keychain of the build Mac.
2. In App Store Connect, create an **API key** with the **Developer** role.
   Keep the `.p8` file out of the repository.
3. Store the notarytool credentials once:

   ```bash
   xcrun notarytool store-credentials vettid-notary \
     --key <path to the .p8> --key-id <key id> --issuer <issuer id>
   ```

   A different profile name goes in `VETTID_NOTARY_PROFILE`.
4. Name the signing identity (it is never committed):

   ```bash
   export APPLE_SIGNING_IDENTITY="Developer ID Application: <name> (<team>)"
   ```

## Release

```bash
scripts/macos-release.sh            # signaling only
scripts/macos-release.sh --calls    # with WebRTC media (brew install opus pkg-config cmake)
```

It builds the app, signs it (hardened runtime, secure timestamp,
`src-tauri/entitlements.plist`), makes and signs the DMG, notarizes it with
`notarytool --wait`, staples the ticket and runs the verification. The DMG
is in `src-tauri/target/aarch64-apple-darwin/release/bundle/dmg/`.

`--sign-only` stops before notarization (no notary credentials needed);
`--dry-run` prints the steps. With `APPLE_SIGNING_IDENTITY=-` (ad-hoc) only
`--sign-only` or `--dry-run` is accepted.

## Verification

```bash
scripts/macos-verify.sh <app or dmg>           # the full release check
scripts/macos-verify.sh --adhoc <app or dmg>   # ad-hoc build: no Developer ID, Gatekeeper or staple check
```

It checks the signature, the hardened runtime flag, the Developer ID
authority, that the signed entitlements equal `src-tauri/entitlements.plist`
exactly, no `get-task-allow`, arm64 only, no dylib outside the system or the
bundle, Gatekeeper (`spctl`) and the stapled ticket.

## Entitlements

`src-tauri/entitlements.plist` is the one list: the signing uses it and the
verification compares against it. Each entry has its reason in the file.
Adding one is a one-line change there.

## Later: the Keychain protector (`keychain-access-groups`)

The macOS Keychain protector (issue #13) will need the
`keychain-access-groups` entitlement, which only works with a provisioning
profile for a Developer ID app. Then: create the Developer ID provisioning
profile for `com.vettid.desktop` in the portal, add the entitlement to
`entitlements.plist`, and release with

```bash
VETTID_PROVISION_PROFILE=<path to the .provisionprofile> scripts/macos-release.sh
```

The script embeds it as `Contents/embedded.provisionprofile` before
signing. Without the variable nothing is embedded.

## Local installs

`scripts/install-local.sh` is unchanged: an ad-hoc signed app for the
developer's own Mac, not for distribution.

## CI

CI builds the app ad-hoc and runs the verification in `--adhoc` mode (the
`macos` job). A signed CI release is not set up. It would need the
certificate (a base64 `.p12` and its password) and the API key, key id and
issuer as GitHub secrets, imported into a temporary keychain in the job.

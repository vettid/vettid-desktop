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

   When a renewed certificate sits beside the old one, the name is
   ambiguous: use the certificate's 40-hex SHA-1 instead
   (`security find-identity -v -p codesigning`).

The verification pins the signing team: the app's and the DMG's
`TeamIdentifier` must equal `VETTID_TEAM_ID` (never committed). The release
script derives it from the "(TEAMID)" in a name identity. With a SHA-1
identity, set it yourself: `export VETTID_TEAM_ID=<10 characters>`. The full
`macos-verify.sh` fails without it; `--adhoc` skips the check.

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

For a DMG the staple is checked on the DMG (`stapler staple` stamps only
the DMG); the app inside is not checked for its own staple, and
`spctl --type execute` on it finds its ticket online. A bare `.app` is
checked for its own staple.

It checks the signature, the hardened runtime flag, the Developer ID
authority, that the signed entitlements equal `src-tauri/entitlements.plist`
exactly, no `get-task-allow`, arm64 only, no library outside the system or
the bundle (every Mach-O; `@rpath` entries must resolve inside
`Contents/Frameworks`), Gatekeeper (`spctl`) and the stapled ticket.

With `--calls` the script sets `LIBOPUS_STATIC=1`, so libopus is linked
statically (no Homebrew dylib). The library check confirms that on the first
calls build; if it fails, do not disable library validation: link statically
or bundle and sign the library.

## Publishing (GitHub Releases)

Releases are published on GitHub. `macos-release.sh` records, beside the DMG (`<dmg>.commit`), the commit it built from, whether that tree was clean (untracked files included), whether it was the `--calls` build, and the DMG's sha256. It refuses if the checkout changed during the build. Publish from any checkout:

```sh
VETTID_TEAM_ID=<team> scripts/macos-publish.sh            # the DMG macos-release.sh made
VETTID_TEAM_ID=<team> scripts/macos-publish.sh <path.dmg> # or a given one
```

The script:
- runs the full check (`macos-verify.sh`, team included) and stops if anything fails;
- refuses a DMG built from a tree with local changes, from a commit that isn't on GitHub's `main`, or that isn't the file recorded at build time;
- verifies, hashes and uploads one copy of the DMG, and reads the version from the recorded commit;
- creates a **draft** release tagged `v<UTC yyyymmdd-HHMMSS>-macos`, as the earlier releases are, at the commit the DMG was built from;
- attaches the DMG as `VettID-Desktop-<version>-macos-arm64.dmg` and a `SHA256SUMS.txt`.

It never publishes. Read the draft on GitHub (Releases), then publish it there; mark it **Latest** if it replaces the one members should download.

## The Xcode 27 linker (string tables)

With a deployment target of macOS 12.0 or later, which Tauri takes from `bundle.macOS.minimumSystemVersion`, the linker of Xcode 27.0 (ld-27037.1, and the Command Line Tools' ld-27106.1) can write a dylib whose string table starts at an offset that isn't 8-byte aligned. Whether it happens depends on the lengths of the build paths, so it looks random. macOS refuses to load such a file ("mis-aligned LINKEDIT string pool"); for the proc-macros rustc has just built, that shows as `error[E0463]: can't find crate for 'zeroize_derive'` (or another `*_derive` or macro crate).

The repository links `aarch64-apple-darwin` through `scripts/macos-cc`, which is `cc -Wl,-no_fixup_chains` (`.cargo/config.toml`). Without chained fixups the linker writes the older, aligned layout, which macOS 12 and later load. It's a linker, not rustflags, because with `--target` the target's rustflags don't reach the proc-macros and build scripts.

`macos-verify.sh` checks that every library in the app has an aligned string table (macOS doesn't hold the main executable to it). If a build fails as above after a change of Xcode, remove the target directory's `release/` folder (it may hold a bad proc-macro) and build again. Drop the wrapper once an Xcode with the fix is the oldest one in use; check with a build without it and `macos-verify.sh`.

## Entitlements

`src-tauri/entitlements.plist` is the one list: the signing uses it and the
verification compares against it. Each entry has its reason in the file. The camera entitlement and
`NSCameraUsageDescription` are not there: they come back with camera capture.
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

# Vendored test vectors

Copied verbatim (LF line endings) from `github.com/vettid/vettid-vault`,
`testdata/vectors/`, at `origin/main` `5e1f888`. VAULT-MESSAGING §16 says
those files are authoritative: this crate must reproduce them byte for byte.
`.gitattributes` marks them `-text`, so Git never converts them.

| File | vettid-vault commit (last change to the file) | SHA-256 |
|---|---|---|
| `keys.json` | `7eb063767ad7dfd5dc4128ba1e90b3a71fc514b6` (2026-10-07) | `568c65595189051a6297653511acb27c88fed17257b985af070342d5bfc1660e` |
| `hpke.json` | `df79ca9fbc4b5cb8f3d08c17285c819e71b5fc07` (2026-10-02) | `08fa20d793577a27196f37e9fe5f5222bbcd90e5adabc015679be3d98b47b226` |
| `envelope_session.json` | `df79ca9fbc4b5cb8f3d08c17285c819e71b5fc07` (2026-10-02) | `8cbf6324c294e6c99011bd3bd5f875fcd329cbe7be1e354b7be06f3c03044827` |
| `handshake.json` | `19c03153e2ecda009f449cb26d13929f34085783` (2026-10-04) | `9b69503b507fd117ab3d6a66368cb60bb24e09286867921a6f473fb476fb0577` |
| `invite.json` | `df79ca9fbc4b5cb8f3d08c17285c819e71b5fc07` (2026-10-02) | `6d7be9ba65f8426070ee54f0ea6ed84fed1e49c54eb31e09a1e177d3d5286d2f` |
| `envelope_sealed.json` | `df79ca9fbc4b5cb8f3d08c17285c819e71b5fc07` (2026-10-02) | `3ab4f20eebb3ec621e97d3b03705c8b3851312e99e227d423e8f0e6066887360` |

Copied on 2026-11-02 with `git show origin/main:testdata/vectors/<file>`
(not from a working tree, whose line endings may differ). To update: copy
them the same way, update this table, and run `cargo test -p vettid-vms`;
the `vendored_vectors_match_source_md` test checks the hashes above and
that the files have no CR.

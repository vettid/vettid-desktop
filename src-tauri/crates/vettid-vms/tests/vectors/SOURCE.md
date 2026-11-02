# Vendored test vectors

Copied verbatim from `github.com/vettid/vettid-vault`, `testdata/vectors/`.
VAULT-MESSAGING §16 says those files are authoritative: this crate must
reproduce them byte for byte.

| File | vettid-vault commit (last change to the file) | SHA-256 |
|---|---|---|
| `keys.json` | `7eb063767ad7dfd5dc4128ba1e90b3a71fc514b6` (2026-10-07) | `9bd347c0a36225e1452e31f1f1f46f573cff2450a57ed0db869728903d032cb7` |
| `hpke.json` | `7eb063767ad7dfd5dc4128ba1e90b3a71fc514b6` (2026-10-07) | `f610a5160f85c83bb624f9652af0b89132af8139f039d7c787036985435a80ed` |

Copied on 2026-11-02 from vettid-vault `5e1f888`. To update: copy the
files again, update this table, and run `cargo test -p vettid-vms`; the
`vendored_vectors_match_source_md` test checks the hashes above.

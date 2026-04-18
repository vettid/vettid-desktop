fn main() {
    // Rebuild when guest creds env vars change — otherwise option_env!() gets
    // stale values. Values are fetched from SSM by scripts/fetch-guest-creds.sh
    // (or set by CI) and baked into the binary via option_env! in pairing.rs.
    println!("cargo:rerun-if-env-changed=VETTID_GUEST_JWT");
    println!("cargo:rerun-if-env-changed=VETTID_GUEST_SEED");
    println!("cargo:rerun-if-env-changed=VETTID_NATS_URL");

    tauri_build::build()
}

//! Refuse the dev-only plain-file key store and the dev-only relay trust
//! in any optimized or release build, whatever its debug-assertions
//! setting (lib.rs also refuses them without debug_assertions).

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_DEV_FILE_STORE");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_DEV_RELAY");
    let profile = std::env::var("PROFILE").unwrap_or_default();
    let opt = std::env::var("OPT_LEVEL").unwrap_or_default();
    let release = profile == "release" || opt != "0";
    if release && std::env::var_os("CARGO_FEATURE_DEV_FILE_STORE").is_some() {
        panic!("the dev-file-store feature writes keys to a plain file: it is for development builds only (profile {profile}, opt-level {opt})");
    }
    if release && std::env::var_os("CARGO_FEATURE_DEV_RELAY").is_some() {
        panic!("the dev-relay feature trusts the dev stack's TEST-ONLY TLS root: it is for development builds only (profile {profile}, opt-level {opt})");
    }
}

//! Refuse the dev-only relay trust (the dev stack's TEST-ONLY TLS root)
//! in any optimized or release build, whatever its debug-assertions
//! setting (lib.rs also refuses it without debug_assertions).

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_DEV_RELAY");
    if std::env::var_os("CARGO_FEATURE_DEV_RELAY").is_none() {
        return;
    }
    let profile = std::env::var("PROFILE").unwrap_or_default();
    let opt = std::env::var("OPT_LEVEL").unwrap_or_default();
    if profile == "release" || opt != "0" {
        panic!("the dev-relay feature trusts the dev stack's TEST-ONLY TLS root: it is for development builds only (profile {profile}, opt-level {opt})");
    }
}

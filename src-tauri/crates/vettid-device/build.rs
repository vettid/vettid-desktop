//! Refuse the dev-only plain-file key store in any optimized or release
//! build, whatever its debug-assertions setting (lib.rs also refuses it
//! without debug_assertions).

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_DEV_FILE_STORE");
    if std::env::var_os("CARGO_FEATURE_DEV_FILE_STORE").is_none() {
        return;
    }
    let profile = std::env::var("PROFILE").unwrap_or_default();
    let opt = std::env::var("OPT_LEVEL").unwrap_or_default();
    if profile == "release" || opt != "0" {
        panic!("the dev-file-store feature writes keys to a plain file: it is for development builds only (profile {profile}, opt-level {opt})");
    }
}

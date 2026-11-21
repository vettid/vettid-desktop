fn main() {
    // Link the Visual C++ runtime into the Windows program (#112): without
    // it the program doesn't start on a PC that lacks the runtime, and the
    // uninstaller's wipe can't run. tauri-build reads this in its "msvc"
    // arm only. .cargo/config.toml sets it too, but cargo finds that file
    // from the current directory, not from --manifest-path, so a build run
    // from outside the repo would miss it; setting it here can't be missed.
    // The static runtime isn't patched by Windows Update: release builds
    // need a current MSVC toolset (docs/WINDOWS-TESTING.md, "Build").
    std::env::set_var("STATIC_VCRUNTIME", "true");
    aws_lc_release_guard();
    tauri_build::build()
}

/// aws-lc-sys (the relay client's TLS, vettid-relay/src/tls.rs) must build
/// from its own source in a release: never a system-installed AWS-LC, and on
/// Windows x86_64 never the prebuilt assembly objects shipped in the crate
/// (NASM builds it). `.cargo/config.toml` sets `AWS_LC_SYS_USE_SYSTEM=0`,
/// but a build run from outside the repo misses that file, and nothing sets
/// `AWS_LC_SYS_PREBUILT_NASM=0` there (debug builds may use the prebuilt
/// objects). A build script can't set another crate's build environment, so
/// this only checks, and stops a release build that would get it wrong
/// (docs/WINDOWS-TESTING.md "Build", docs/MACOS-RELEASE.md).
fn aws_lc_release_guard() {
    for v in ["AWS_LC_SYS_USE_SYSTEM", "AWS_LC_SYS_PREBUILT_NASM", "PROFILE"] {
        println!("cargo:rerun-if-env-changed={v}");
    }
    if std::env::var("PROFILE").as_deref() != Ok("release") {
        return;
    }
    if std::env::var("AWS_LC_SYS_USE_SYSTEM").as_deref() != Ok("0") {
        panic!("a release build needs AWS_LC_SYS_USE_SYSTEM=0 (aws-lc-sys must not link a system AWS-LC); build from the repo, or export it");
    }
    let windows_x64 = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64");
    if windows_x64 && std::env::var("AWS_LC_SYS_PREBUILT_NASM").as_deref() != Ok("0") {
        panic!("a Windows release build needs AWS_LC_SYS_PREBUILT_NASM=0 and NASM on PATH (aws-lc's assembly is built from source, not taken prebuilt): docs/WINDOWS-TESTING.md, \"Build\"");
    }
}

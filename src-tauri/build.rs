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
/// objects). Each is read the way aws-lc-sys reads it (aws_lc_env). A build script can't set another crate's build environment, so
/// this only checks, and stops a release build that would get it wrong
/// (docs/WINDOWS-TESTING.md "Build", docs/MACOS-RELEASE.md).
fn aws_lc_release_guard() {
    let use_system = aws_lc_env("USE_SYSTEM");
    let prebuilt_nasm = aws_lc_env("PREBUILT_NASM");
    if std::env::var("PROFILE").as_deref() != Ok("release") {
        return;
    }
    if use_system.as_deref() != Some("0") {
        panic!("a release build needs AWS_LC_SYS_USE_SYSTEM=0 (aws-lc-sys must not link a system AWS-LC); build from the repo, or export it");
    }
    let windows_x64 = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64");
    if windows_x64 && prebuilt_nasm.as_deref() != Some("0") {
        panic!("a Windows release build needs AWS_LC_SYS_PREBUILT_NASM=0 and NASM on PATH (aws-lc's assembly is built from source, not taken prebuilt): docs/WINDOWS-TESTING.md, \"Build\"");
    }
}

/// The value aws-lc-sys itself reads for `AWS_LC_SYS_<var>`: the
/// target's own variable first (`AWS_LC_SYS_<var>_<target>`, the target
/// in lower case with `-` as `_`), then the plain one. Checking only the
/// plain one would let a target-suffixed variable override it unseen.
fn aws_lc_env(var: &str) -> Option<String> {
    let plain = format!("AWS_LC_SYS_{var}");
    let target = std::env::var("TARGET").unwrap_or_default().to_lowercase().replace('-', "_");
    let suffixed = format!("{plain}_{target}");
    println!("cargo:rerun-if-env-changed={plain}");
    println!("cargo:rerun-if-env-changed={suffixed}");
    std::env::var(&suffixed).ok().or_else(|| std::env::var(&plain).ok())
}

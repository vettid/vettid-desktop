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
    tauri_build::build()
}

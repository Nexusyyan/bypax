fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");

    #[cfg(windows)]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let version = env!("CARGO_PKG_VERSION");
        let mut res = tauri_winres::WindowsResource::new();
        res.set_language(0x0409)
            .set("ProductName", "Bypax")
            .set("FileDescription", "Bypax Privileged Network Helper")
            .set("InternalName", "bypax-service.exe")
            .set("OriginalFilename", "bypax-service.exe")
            .set("FileVersion", version)
            .set("ProductVersion", version);
        res.compile()
            .expect("failed to compile Windows PE version resources for bypax-service");
    }
}

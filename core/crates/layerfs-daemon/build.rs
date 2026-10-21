fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=HOME");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        if let Ok(home) = std::env::var("HOME") {
            let libdir = format!("{home}/.fuse-t/usr/local/lib");
            println!("cargo:rustc-link-search=native={libdir}");
            println!("cargo:rustc-link-arg=-Wl,-rpath,{libdir}");
        }
        println!("cargo:rustc-link-search=native=/usr/local/lib");
        println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/local/lib");
    }
}

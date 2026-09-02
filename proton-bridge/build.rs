use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let header_path = crate_dir.join("proton_bridge.h");
    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_language(cbindgen::Language::Cxx)
        .with_no_includes()
        .with_include("cstdint")
        .with_pragma_once(true)
        .generate()
        .expect("cbindgen failed")
        .write_to_file(&header_path);

    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=build.rs");
}

use bindgen;
use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=include/tipcc.h");
    println!("cargo:rerun-if-changed=include/libtipc.c");

    let bindings = bindgen::Builder::default()
        .header("include/tipcc.h")
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    // Compile the code
    cc::Build::new()
        .file("include/libtipc.c")
        .compile("libtipc");
}

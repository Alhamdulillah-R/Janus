use std::env;

/**
 * Link the compression libraries the static libcrypto was configured with (zlib, brotli, zstd).
 */
fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    println!("cargo:rerun-if-env-changed=JANUS_DEPS_MSVC");
    println!("cargo:rerun-if-env-changed=JANUS_DEPS_LINUX");

    if target_os == "windows" {
        let deps = env::var("JANUS_DEPS_MSVC").expect("JANUS_DEPS_MSVC points at build/deps-msvc/install/lib");

        println!("cargo:rustc-link-search=native={deps}");
        for lib in ["zlibstatic", "brotlienc", "brotlidec", "brotlicommon", "zstd_static"] {
            println!("cargo:rustc-link-lib=static={lib}");
        }
        return;
    }

    let deps = env::var("JANUS_DEPS_LINUX").expect("JANUS_DEPS_LINUX points at build/deps-linux/install/lib");

    println!("cargo:rustc-link-search=native={deps}");
    for lib in ["z", "brotlienc", "brotlidec", "brotlicommon", "zstd"] {
        println!("cargo:rustc-link-lib=static={lib}");
    }
}

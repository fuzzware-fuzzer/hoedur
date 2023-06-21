use std::{
    env,
    fs::{self, File},
    path::PathBuf,
    process::Command,
};

use qemu_build::{build, Arch};

const BINDINGS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../qemu-sys/src/bindings");
const PATCHES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../qemu-sys/patches");

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("failed to get $OUT_DIR"));
    let qemu_dir = out_dir.join("qemu-7.1.0");
    let build_dir = out_dir.join("build");
    let bindings_dir = PathBuf::from(BINDINGS_DIR);

    // get QEMU
    if !qemu_dir.is_dir() {
        let qemu_tar = out_dir.join("qemu-7.1.0.tar.xz");

        // download QEMU
        assert!(Command::new("wget")
            .arg("https://download.qemu.org/qemu-7.1.0.tar.xz")
            .arg("-O")
            .arg(&qemu_tar)
            .status()
            .expect("QEMU download failed")
            .success());

        // extract QEMU
        assert!(Command::new("tar")
            .current_dir(&out_dir)
            .arg("-xf")
            .arg(&qemu_tar)
            .status()
            .expect("QEMU extract failed")
            .success());

        // apply QEMU patches
        let patches_dir = PathBuf::from(PATCHES_DIR);
        let patches = [
            patches_dir.join("hoedur.patch"),
            patches_dir.join("5cb993ff131fca2abef3ce074a20258fd6fce557.patch"),
        ];
        for patch in patches {
            let file = File::open(patch).expect("Failed to open patch file");

            assert!(Command::new("patch")
                .current_dir(&qemu_dir)
                .stdin(file)
                .arg("-p1")
                .status()
                .expect("Apply QEMU patches failed")
                .success());
        }
    }

    // create build dir
    if !build_dir.is_dir() {
        fs::create_dir(&build_dir).expect("Failed to create build dir");
    }

    #[cfg(feature = "arm")]
    let arch = Arch::Arm;

    build(&qemu_dir, &build_dir, arch, &bindings_dir);
}

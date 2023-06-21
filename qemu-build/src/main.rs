use std::{convert::TryFrom, env, fs, path::PathBuf, process};

use qemu_build::{qemu_bindgen_clang_args, qemu_configure, Arch};

fn main() {
    let arg: Vec<_> = env::args().collect();
    if arg.len() != 4 {
        println!("usage: qemu-build <qemu-dir> <build-dir> <arch>");
        process::exit(1);
    }

    let qemu_dir = fs::canonicalize(PathBuf::from(arg[1].as_str())).expect("qemu-dir missing");
    let build_dir = fs::canonicalize(PathBuf::from(arg[2].as_str())).expect("build-dir missing");
    let arch = Arch::try_from(arg[3].as_str()).expect("Invalid Arch");

    println!(
        "configuring QEMU {:?} build in {} ...",
        arch,
        build_dir.display()
    );
    qemu_configure(&qemu_dir, &build_dir, arch);

    let clang_args = qemu_bindgen_clang_args(&qemu_dir, &build_dir, arch);
    println!("clang args: {clang_args:#?}");
}

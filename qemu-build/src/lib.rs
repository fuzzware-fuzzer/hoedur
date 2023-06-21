use std::convert::TryFrom;
use std::fmt;
use std::path::{Path, PathBuf};
use std::{env, fs, process::Command};

mod bindings;

#[cfg(debug_assertions)]
const BUILD_MODE: &str = "debug";
#[cfg(not(debug_assertions))]
const BUILD_MODE: &str = "release";

const ROOT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
const TARGET_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../target/$BUILD_MODE");
const ARCH_PLACEHOLDER: &str = "$ARCH";
const BUILD_MODE_PLACEHOLDER: &str = "$BUILD_MODE";
const BINDINGS_FILENAME: &str = "$BUILD_MODE/$ARCH.rs";
const BINDINGS_COMMIT_FILENAME: &str = "$BUILD_MODE/.commit-$ARCH";
const COMPILE_COMMANDS: &str = "compile_commands.json";
const QEMU_LIB: &str = "libqemu-system-$ARCH.so";
const QEMU_LIB_OUT: &str = "libqemu-system-$ARCH.$BUILD_MODE.so";
const QEMU_COMMIT_FILENAME: &str = ".commit-$ARCH-$BUILD_MODE";
const QEMU_MAIN_FILE: &str = "/softmmu/main.c";
const QEMU_MAIN_OBJECT: &str = "qemu-system-$ARCH.p/softmmu_main.c.o";

#[derive(Debug, Clone, Copy)]
pub enum Arch {
    Arm,
}

impl Arch {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Arm => "arm",
        }
    }

    pub fn target(&self) -> &'static str {
        match self {
            _ => self.as_str(),
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<&str> for Arch {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value {
            "arm" => Arch::Arm,
            _ => {
                return Err("Unknown Arch");
            }
        })
    }
}

pub fn build(qemu_dir: &Path, build_dir: &Path, arch: Arch, bindings_dir: &Path) {
    // paths
    let target_dir = TARGET_DIR.replace(BUILD_MODE_PLACEHOLDER, BUILD_MODE);
    let qemu_lib = QEMU_LIB.replace(ARCH_PLACEHOLDER, arch.as_str());
    let qemu_lib_out = QEMU_LIB_OUT
        .replace(ARCH_PLACEHOLDER, arch.as_str())
        .replace(BUILD_MODE_PLACEHOLDER, BUILD_MODE);
    let qemu_lib_target_path = Path::new(&target_dir).join(&qemu_lib_out);
    let bindings_path = bindings_dir.join(
        BINDINGS_FILENAME
            .replace(ARCH_PLACEHOLDER, arch.as_str())
            .replace(BUILD_MODE_PLACEHOLDER, BUILD_MODE),
    );
    let bindings_commit_file = bindings_dir.join(
        BINDINGS_COMMIT_FILENAME
            .replace(ARCH_PLACEHOLDER, arch.as_str())
            .replace(BUILD_MODE_PLACEHOLDER, BUILD_MODE),
    );
    let qemu_commit_file = qemu_dir.join(
        QEMU_COMMIT_FILENAME
            .replace(ARCH_PLACEHOLDER, arch.as_str())
            .replace(BUILD_MODE_PLACEHOLDER, BUILD_MODE),
    );
    let compile_commands = build_dir.join(COMPILE_COMMANDS);

    // get current build commit
    let (qemu_commit, bindings_commit) = (git_commit("qemu-sys/qemu/"), git_commit("qemu-build/"));

    // bindings need update?
    let update_bindings = {
        // check if bindings commit changed
        let commit_changed = commit_diff(&bindings_commit_file, &bindings_commit);

        // bindings missing
        !bindings_path.is_file() || commit_changed
    };

    // clean build when qemu lib is missing
    let clean_build = {
        // bindings and compile commands are missing => clean build
        let build_required = update_bindings && !compile_commands.is_file();

        // check if qemu commit changed
        let commit_changed = commit_diff(&qemu_commit_file, &qemu_commit);

        // qemu lib is missing
        let lib_missing = !qemu_lib_target_path.is_file();

        build_required || lib_missing || commit_changed
    };

    // configure & build qemu if lib is missing
    if clean_build {
        qemu_configure(qemu_dir, build_dir, arch);
        qemu_build(build_dir, &qemu_lib);

        // copy qemu lib into /target
        fs::copy(build_dir.join(qemu_lib), qemu_lib_target_path)
            .expect("Failed to copy qemu lib to target dir");

        // patch library filename (SONAME)
        let status = Command::new("patchelf")
            .args(["--set-soname", &qemu_lib_out, &qemu_lib_out])
            .current_dir(&target_dir)
            .status()
            .expect("failed to run patchelf");
        assert!(status.success());

        // update commit file
        fs::write(&qemu_commit_file, qemu_commit).expect("Failed to write qemu commit file");
    }

    // add qemu lib
    println!("cargo:rustc-link-lib=qemu-system-{arch}.{BUILD_MODE}");
    println!("cargo:rustc-link-search={target_dir}");

    // rerun when bindings are chagned/missing
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed={}", bindings_path.display());
    println!("cargo:rerun-if-changed={}", bindings_commit_file.display());

    // rerun when qemu is changed
    println!("cargo:rerun-if-changed={}", qemu_commit_file.display());

    // generate bindings if missing / clean build
    if clean_build || update_bindings {
        bindings::generate(qemu_dir, build_dir, arch)
            .expect("Unable to generate bindings")
            .write_to_file(bindings_path)
            .expect("Couldn't write bindings!");

        // update commit file
        fs::write(&bindings_commit_file, bindings_commit)
            .expect("Failed to write bindings commit file");
    }
}

fn git_commit(path: &str) -> String {
    let output = Command::new("git")
        .args(["log", "-n", "1", "--pretty=format:%H", "--", path])
        .current_dir(ROOT_DIR)
        .output()
        .expect("failed get current git commit");

    String::from_utf8_lossy(&output.stdout).to_string()
}

fn commit_diff(commit_file: &Path, commit: &str) -> bool {
    match fs::read_to_string(commit_file) {
        Ok(old_commit) => commit != old_commit,
        Err(err) if commit_file.is_file() => {
            println!("cargo:warning=Failed to read commit file {commit_file:?}: {err:?}");

            true
        }
        _ => true,
    }
}

pub fn qemu_configure(qemu_dir: &Path, build_dir: &Path, arch: Arch) {
    // configure minimal arm system qemu
    let status = Command::new(qemu_dir.join("configure"))
        .args([
            // compiler
            "--cc=clang",
            "--cxx=clang++",
            // "--static",
            // ---

            // target arch
            &format!("--target-list={arch}-softmmu"),
            // ---

            // debug:
            #[cfg(debug_assertions)]
            "--enable-debug", // includes debug_tcg + debug_mutex
            #[cfg(debug_assertions)]
            "--enable-debug-info",
            #[cfg(debug_assertions)]
            "--enable-stack-protector",
            #[cfg(not(debug_assertions))]
            "--disable-stack-protector",
            "--disable-safe-stack",
            // "--enable-sanitizers",
            // "--enable-tsan",
            // "--enable-profiler",
            // "--enable-tcg-interpreter",
            // "--enable-trace-backends=",
            #[cfg(not(debug_assertions))]
            "--disable-qom-cast-debug",
            "--disable-strip",
            "--disable-werror",
            // ---

            // minimal build
            "--without-default-devices",
            "--without-default-features",
            "--disable-containers",
            "--disable-capstone",
            "--disable-slirp",
            "--disable-blobs",
            "--audio-drv-list=",
            // ---

            // features:
            "--enable-system",
            "--enable-pie",
            "--enable-fdt", // required for arm-softmmu
            // "--enable-lto",
            #[cfg(all(
                any(target_arch = "x86", target_arch = "x86_64"),
                target_feature = "avx2"
            ))]
            "--enable-avx2",
            #[cfg(all(
                any(target_arch = "x86", target_arch = "x86_64"),
                target_feature = "avx512f"
            ))]
            "--enable-avx512f",
        ])
        .current_dir(build_dir)
        .status()
        .expect("failed to configure qemu");
    assert!(status.success());
}

fn qemu_build(build_dir: &Path, qemu_lib: &str) {
    // build qemu lib
    let status = Command::new("ninja")
        .args([qemu_lib])
        .current_dir(build_dir)
        .status()
        .expect("failed to build qemu libs");
    assert!(status.success());
}

pub fn qemu_bindgen_clang_args(qemu_dir: &Path, build_dir: &Path, arch: Arch) -> Vec<String> {
    // load compile commands
    let compile_commands_string = &fs::read_to_string(build_dir.join(COMPILE_COMMANDS))
        .expect("failed to read compile commands");

    let compile_commands =
        json::parse(compile_commands_string).expect("failed to parse compile commands");

    // find main object
    let entry = compile_commands
        .members()
        .find(|entry| {
            entry["output"] == QEMU_MAIN_OBJECT.replace(ARCH_PLACEHOLDER, arch.as_str())
                || entry["file"]
                    .as_str()
                    .map(|file| file.ends_with(QEMU_MAIN_FILE))
                    .unwrap_or(false)
        })
        .expect("didn't find compile command for qemu-system-arm");

    // get main object build command
    let command = entry["command"].as_str().expect("command is a string");

    // filter define and include args
    let mut clang_args = vec![];
    let mut include_arg = false;
    for arg in shell_words::split(command)
        .expect("failed to parse command")
        .into_iter()
        .skip(1)
    {
        if arg.starts_with("-D") {
            clang_args.push(arg)
        } else if let Some(incpath) = arg.strip_prefix("-I") {
            clang_args.push(format!("-I{}", include_path(build_dir, incpath)));
        } else if arg == "-iquote" || arg == "-isystem" {
            include_arg = true;
            clang_args.push(arg)
        } else if include_arg {
            include_arg = false;
            clang_args.push(include_path(build_dir, &arg))
        }
    }

    // add include dirs
    clang_args.push(format!("-I{}", include_path(qemu_dir, "include",)));
    clang_args.push("-iquote".to_owned());
    clang_args.push(include_path(qemu_dir, &format!("target/{}", arch.target())));

    clang_args
}

fn include_path(build_dir: &Path, path: &str) -> String {
    let include_path = PathBuf::from(path);

    if include_path.is_absolute() {
        path.to_string()
    } else {
        // make include path absolute
        build_dir.join(include_path).display().to_string()
    }
}

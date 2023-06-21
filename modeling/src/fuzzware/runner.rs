use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output},
    str::FromStr,
};

use anyhow::{bail, Context, Result};
use common::{
    config::fuzzware::{
        DEFAULT_DOCKER_BINARY, DEFAULT_DOCKER_IMAGE, DEFAULT_DOCKER_TAG, DEFAULT_LOCAL_BINARY,
    },
    fs::bufwriter,
};

use super::{docker::FuzzwareDocker, local::FuzzwareLocal};

#[derive(Debug)]
pub enum FuzzwareRunner {
    Local(FuzzwareLocal),
    Docker(FuzzwareDocker),
}

#[derive(Debug, Default, Clone, Copy)]
pub enum FuzzwareInstallation {
    #[default]
    Auto,
    Local,
    Docker,
}

impl FromStr for FuzzwareInstallation {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "auto" => Self::Auto,
            "local" => Self::Local,
            "docker" => Self::Docker,
            _ => return Err("Unknown Fuzzware Installation!"),
        })
    }
}

pub trait Runner {
    fn to_command(&self, workdir: &Path) -> Command;
    fn test(&self) -> Result<()>;
}

impl FuzzwareRunner {
    pub fn new(
        installation: FuzzwareInstallation,
        binary: PathBuf,
        docker: PathBuf,
        image: String,
        tag: String,
    ) -> Self {
        let local = || FuzzwareRunner::Local(FuzzwareLocal::new(binary));
        let docker = || FuzzwareRunner::Docker(FuzzwareDocker::new(docker, image, tag));

        match installation {
            FuzzwareInstallation::Auto => {
                log::info!("Auto detection of Fuzzware installation ...");

                let local = local();
                match local.test() {
                    Ok(_) => {
                        log::info!("Local Fuzzware installation is available.");
                        local
                    }
                    Err(_) => {
                        log::info!("Local Fuzzware installation is unavailable, fallback to Fuzzware Docker.");
                        docker()
                    }
                }
            }
            FuzzwareInstallation::Local => local(),
            FuzzwareInstallation::Docker => docker(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(
            FuzzwareInstallation::Auto,
            DEFAULT_LOCAL_BINARY.into(),
            DEFAULT_DOCKER_BINARY.into(),
            DEFAULT_DOCKER_IMAGE.into(),
            DEFAULT_DOCKER_TAG.into(),
        )
    }
}

impl Runner for FuzzwareRunner {
    fn to_command(&self, workdir: &Path) -> Command {
        match self {
            FuzzwareRunner::Local(runner) => runner.to_command(workdir),
            FuzzwareRunner::Docker(runner) => runner.to_command(workdir),
        }
    }

    fn test(&self) -> Result<()> {
        match self {
            FuzzwareRunner::Local(runner) => runner.test(),
            FuzzwareRunner::Docker(runner) => runner.test(),
        }
    }
}

pub(crate) fn test<T: Runner + ?Sized>(runner: &T) -> Result<()> {
    let tmpdir = tempfile::tempdir().context("get temp dir")?;
    let mut command = runner.to_command(tmpdir.path());
    command.arg("model").arg("-h");

    let output = run(&mut command, None)?;
    if output.status.success() && output.stderr.is_empty() {
        Ok(())
    } else {
        bail!(
            "Unexpected output on stderr for command {:?}\nstdout:\n{}\nstderr:\n{}",
            command,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }
}

pub(crate) fn run(command: &mut Command, logdir: Option<&Path>) -> Result<Output> {
    let output = command
        .output()
        .context("Failed to spawn Fuzzware docker")?;

    const TRACEBACK: &[u8] = b"Traceback (most recent call last):";

    // log level depending on output state
    let level = if !output.status.success() {
        log::Level::Error
    } else if output
        .stderr
        .windows(TRACEBACK.len())
        .any(|window| window == TRACEBACK)
    {
        log::Level::Warn
    } else {
        log::Level::Trace
    };

    // log stdout/-err
    if log::log_enabled!(level) {
        log::log!(
            level,
            "stdout:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
        log::log!(
            level,
            "stderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // log into tmp dir for fuzzware error archive
    if let Some(logdir) = logdir {
        bufwriter(&logdir.join("stdout.log"))?
            .write_all(&output.stdout)
            .context("Failed to write stdout logfile")?;
        bufwriter(&logdir.join("stderr.log"))?
            .write_all(&output.stderr)
            .context("Failed to write stderr logfile")?;
    }

    if !output.status.success() {
        bail!("Failed to run command: {:?}", command)
    }

    Ok(output)
}

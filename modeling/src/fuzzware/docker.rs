use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::Result;

use super::runner::{self, Runner};

const DOCKER_OPTIONS: &str = "-i";
const FUZZWARE_BINARY: &str = "fuzzware";
const MOUNT_TARGET: &str = "/home/user/fuzzware/targets";

#[derive(Debug)]
pub struct FuzzwareDocker {
    docker: PathBuf,
    image: String,
    tag: String,
}

impl Default for FuzzwareDocker {
    fn default() -> Self {
        use common::config::fuzzware::*;

        Self::new(
            DEFAULT_DOCKER_BINARY.into(),
            DEFAULT_DOCKER_IMAGE.into(),
            DEFAULT_DOCKER_TAG.into(),
        )
    }
}

impl FuzzwareDocker {
    pub fn new(docker: PathBuf, image: String, tag: String) -> Self {
        Self { docker, image, tag }
    }
}

impl Runner for FuzzwareDocker {
    fn to_command(&self, workdir: &Path) -> Command {
        let mut cmd = Command::new(&self.docker);

        cmd.arg("run")
            .arg(DOCKER_OPTIONS)
            .arg("--rm")
            .arg("--mount")
            .arg(format!(
                "type=bind,source={},target={}",
                workdir.display(),
                MOUNT_TARGET
            ))
            .arg(format!("{}:{}", self.image, self.tag))
            .arg(FUZZWARE_BINARY);

        cmd
    }

    fn test(&self) -> Result<()> {
        log::info!("Verifying Fuzzware Docker is available ...");
        runner::test(self)
    }
}

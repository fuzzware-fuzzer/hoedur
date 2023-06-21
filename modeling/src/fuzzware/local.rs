use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::Result;

use super::runner::{self, Runner};

#[derive(Debug)]
pub struct FuzzwareLocal {
    binary: PathBuf,
}

impl Default for FuzzwareLocal {
    fn default() -> Self {
        use common::config::fuzzware::*;

        Self::new(DEFAULT_LOCAL_BINARY.into())
    }
}

impl FuzzwareLocal {
    pub fn new(binary: PathBuf) -> Self {
        Self { binary }
    }
}

impl Runner for FuzzwareLocal {
    fn to_command(&self, workdir: &Path) -> Command {
        let mut cmd = Command::new(&self.binary);

        cmd.current_dir(workdir);

        cmd
    }

    fn test(&self) -> Result<()> {
        log::info!("Verifying Local Fuzzware is available ...");
        runner::test(self)
    }
}

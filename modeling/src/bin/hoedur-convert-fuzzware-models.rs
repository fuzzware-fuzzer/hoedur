use std::{path::PathBuf, process};

use anyhow::{Context, Result};
use common::fs::{bufreader, encoder};
use modeling::fuzzware::mmio_models::FuzzwareMmio;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        log::debug!("args = {:?}", args);
        eprintln!("usage: {} old-mmio.yml new-mmio.yml.zst", args[0]);
        process::exit(1);
    }

    let path_old = &args[1];
    let path_new = &args[2];

    let reader = bufreader(&PathBuf::from(path_old))?;
    let fuzzware: FuzzwareMmio =
        serde_yaml::from_reader(reader).context("Failed to deserialize Fuzzware MMIO models")?;

    let models: Vec<_> = fuzzware.convert().collect();

    let mut encoder =
        encoder(&PathBuf::from(path_new)).context("Failed to create new modeling file")?;
    serde_yaml::to_writer(&mut encoder, &models).context("Failed to serialize models")
}

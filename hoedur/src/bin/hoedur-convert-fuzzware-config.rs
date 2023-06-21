use std::{env, fs, io::Write, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use common::{
    fs::{bufreader, bufwriter},
    log::{init_log, LOG_INFO},
};
use emulator::EmulatorTargetConfig;
use modeling::fuzzware::config::{ConfigInclude, FuzzwareConfig};

#[derive(Parser, Debug)]
#[command(name = "hoedur-convert-fuzzware-config")]
pub struct Arguments {
    #[arg(long, default_value = LOG_INFO)]
    pub log_config: PathBuf,
    pub fuzzware: PathBuf,
    pub hoedur: PathBuf,
}

const FORCE_DECIMAL: [&str; 2] = [
    // interrupt interval
    "interval:",
    // interrupt allow-/blocklist
    "-",
];

fn main() -> Result<()> {
    let opt = Arguments::parse();

    // init log config
    init_log(&opt.log_config)?;
    log::trace!("Args: {:#?}", opt);

    #[cfg(not(feature = "arm"))]
    log::error!("hoedur-convert-fuzzware-config requires feature 'arm'.");

    let pwd = env::current_dir().context("Failed to get current dir")?;
    let config_raw = fs::read_to_string(&opt.fuzzware)
        .with_context(|| format!("Failed to read Fuzzware config file: {:?}", opt.fuzzware))?;
    let working_directory = opt
        .fuzzware
        .parent()
        .filter(|path| path.exists())
        .unwrap_or(&pwd);

    // merge config file
    let mut fuzzware_config = FuzzwareConfig::default();

    // config includes
    let include: ConfigInclude = serde_yaml::from_str(&config_raw).with_context(|| {
        format!(
            "Failed to deserialize Fuzzware config file: {:?}",
            opt.fuzzware
        )
    })?;
    for path in include.include.unwrap_or_default() {
        // get absolute path
        let abs_path = if path.is_relative() {
            working_directory.join(path)
        } else {
            path
        };

        // load included file
        fuzzware_config.merge(
            serde_yaml::from_reader(
                bufreader(&abs_path).with_context(|| {
                    format!("Failed to open included config file: {abs_path:?}")
                })?,
            )
            .with_context(|| format!("Failed to deserialize Fuzzware config file: {abs_path:?}"))?,
        );
    }

    // load main config
    fuzzware_config.merge(serde_yaml::from_str(&config_raw).with_context(|| {
        format!(
            "Failed to deserialize Fuzzware config file: {:?}",
            opt.fuzzware
        )
    })?);
    log::debug!("{:#x?}", fuzzware_config);

    // convert config
    let config = EmulatorTargetConfig::from_fuzzware(fuzzware_config, working_directory)
        .context("Failed to convert Fuzzware config to Hödur config")?;

    let script = config.script().map(|script| script.to_owned());

    // write config
    let config_str = serde_yaml::to_string(&config).context("Failed to serialize Hödur config")?;
    let mut writer = bufwriter(&opt.hoedur).context("Failed to create new Hödur config file")?;
    let mut first_block = true;

    // formater hacks
    for line in config_str.lines() {
        // skip yaml header
        if line == "---" {
            continue;
        }

        let parts: Vec<_> = line.split(' ').collect();

        // detect force decimal format
        let mut force_decimal = false;
        for part in &parts {
            if FORCE_DECIMAL.contains(&part.trim()) {
                force_decimal = true;
                break;
            }
        }

        // reformat as hex hack
        if parts.len() > 1 && !force_decimal {
            if let Some(number) = parts.last().and_then(|last| str::parse::<usize>(last).ok()) {
                for (idx, part) in parts.iter().enumerate() {
                    if idx + 1 < parts.len() {
                        write!(&mut writer, "{part} ")?;
                    } else {
                        writeln!(&mut writer, "{number:#x?}")?;
                    }
                }

                // skip default write
                continue;
            }
        }

        // pretty print script lines
        if let Some(script) = &script {
            if line.starts_with("script: \"") {
                writeln!(&mut writer, "script: |")?;

                for line in script.lines() {
                    writeln!(&mut writer, "  {line}")?;
                }

                continue;
            }
        }

        // skip None
        if line.ends_with(": ~") {
            continue;
        }

        // new block (no whitespace ident)
        if line == line.trim_start() && line.ends_with(':') {
            // add newline before blocks (except first block)
            if first_block {
                first_block = false;
            } else {
                writeln!(&mut writer)?;
            }
        }

        // write line as-is
        writeln!(&mut writer, "{line}")?;
    }

    Ok(())
}

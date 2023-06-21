use std::{
    convert::TryFrom,
    ffi::CString,
    fs,
    io::Write,
    ops::AddAssign,
    os::unix::prelude::OsStrExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use common::{
    config::fuzzware::MODEL_PER_PC_LIMIT,
    fs::{bufreader, bufwriter, encoder},
    FxHashMap,
};
use fslock::LockFile;
use ihex::Record;
use qemu_rs::{Address, QemuStateControl, Register};

use crate::{
    fuzzware::{
        mmio_models::FuzzwareMmio,
        runner::{FuzzwareRunner, Runner},
    },
    mmio::{AccessContext, ModelContext},
    mmio_model::MmioModel,
};

pub mod config;
pub mod docker;
pub mod local;
pub mod mmio_models;
pub mod runner;

const FUZZWARE_CONFIG_FILENAME: &str = "config.yml";
const FUZZWARE_STATE_FILENAME: &str = "statefile";

#[derive(Debug)]
pub struct Fuzzware {
    runner: FuzzwareRunner,
    model_share: Option<PathBuf>,
    model_count: FxHashMap<Address, usize>,
}

#[cfg(feature = "arm")]
fn registers() -> &'static [&'static str] {
    &[
        "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12", "LR",
        "PC", "SP", "XPSR",
    ]
}

#[cfg(not(feature = "arm"))]
fn registers() -> &'static [&'static str] {
    unimplemented!()
}

impl Fuzzware {
    pub fn new(runner: FuzzwareRunner, model_share: Option<PathBuf>) -> Result<Self> {
        runner.test().context("Fuzzware not available")?;

        Ok(Self {
            runner,
            model_share,
            model_count: FxHashMap::default(),
        })
    }

    pub fn limit_reached(&self, context: &AccessContext) -> bool {
        self.model_count
            .get(&context.pc())
            .map(|model_count| *model_count >= MODEL_PER_PC_LIMIT)
            .unwrap_or(false)
    }

    pub fn model(&mut self, context: &AccessContext) -> Result<Option<MmioModel>> {
        log::info!("Running Fuzzware modeling for {:x?} ...", context);

        // count models per pc for modeling limit (avoid modeling loop for arbitrary MMIO reads / DMA buffers)
        self.model_count
            .entry(context.pc())
            .or_default()
            .add_assign(1);

        //  model share
        if let Some(model_share) = &self.model_share {
            let context_str = context.to_string();

            let lockfile_path = model_share.join(format!("{context_str}.lock"));
            let mut lockfile = LockFile::open(&lockfile_path)
                .context(format!("open lockfile {lockfile_path:?}"))?;
            let model_file = model_share.join(format!("{context_str}.yml"));

            // lock exists => wait for other process
            if !lockfile.try_lock_with_pid()? {
                // TODO: early exit and try to find next missing model

                // wait for other process and reuse model
                log::info!(
                    "Waiting for Fuzzware model creation of shared instance for {:x?} ...",
                    context
                );
                lockfile.lock_with_pid()?;
                lockfile.unlock()?;

                return read_model(&model_file);
            } else if model_file.is_file() {
                lockfile.unlock()?;

                // reuse existing model
                log::info!("Loading shared Fuzzware model for {:x?}", context);

                return read_model(&model_file);
            }

            // create model
            let model = self
                .create_model(context)
                .context("create Fuzzware model")?;

            // write model
            serde_yaml::to_writer(
                bufwriter(&model_file).context("Failed to write model")?,
                &model,
            )?;

            lockfile.unlock()?;

            Ok(model)
        } else {
            // create model
            self.create_model(context).context("create Fuzzware model")
        }
        .context("Failed to create model")
    }

    fn create_model(&mut self, context: &AccessContext) -> Result<Option<MmioModel>> {
        // create temp dir for fuzzware modeling
        let tmpdir = tempfile::tempdir().context("get temp dir")?;
        let tmp = tmpdir.path();
        log::trace!("tmp dir = {:?}", tmp);

        // chmod 0o777 tmpdir
        let path = tmpdir.path();
        let s = CString::new(path.as_os_str().as_bytes()).expect("Path is valid CString");
        if unsafe { libc::chmod(s.as_ptr(), 0o777) } != 0 {
            Err(std::io::Error::last_os_error())
                .with_context(|| format!("Failed to set chmod 0777 for tmpdir {tmpdir:?}"))?;
        }

        // write state file: register + memory blocks
        write_statefile(&tmp.join(FUZZWARE_STATE_FILENAME))?;

        // TODO: write Fuzzware MMIO regions + chmod 0o777 config
        let config_file = tmp.join(FUZZWARE_CONFIG_FILENAME);

        // run fuzzware modelling
        let mut command = self.runner.to_command(tmpdir.path());
        runner::run(
            command.args([
                // fuzzware modeling
                "model",
                // ---

                // fuzzware config (MMIO regions + model output)
                "-c",
                FUZZWARE_CONFIG_FILENAME,
                // ---

                // debug mode
                #[cfg(debug_assertions)]
                "-d",
                // ---

                // state file
                FUZZWARE_STATE_FILENAME,
            ]),
            Some(tmp),
        )
        .context("Failed to run Fuzzware model docker")?;

        // verify Fuzzware config was created
        if !config_file.is_file() {
            log::warn!("Fuzzware did not create config file.");
            dump_fuzzware_error(tmp, context);
            return Ok(None);
        }

        // parse Fuzzware models
        let reader = bufreader(&config_file).context("Fuzzware config file")?;
        let fuzzware_models: FuzzwareMmio = serde_yaml::from_reader(reader).with_context(|| {
            format!(
                "Failed to deserialize Fuzzware MMIO models:\n{}",
                fs::read_to_string(&config_file).as_deref().unwrap_or("")
            )
        })?;
        log::trace!("parsed models: {:#x?}", fuzzware_models);

        // convert fuzzware models
        let models: Vec<_> = fuzzware_models.convert().collect();
        log::trace!("converted models: {:#x?}", models);

        // find matching model
        let model = models.into_iter().find_map(|mmio| match mmio.context {
            ModelContext::AccessContext(model_context) if model_context == *context => mmio.model,
            _ => {
                log::warn!(
                    "Fuzzware returned unexpected model {:#x?}, expected {:#x?}",
                    mmio,
                    context
                );
                dump_fuzzware_error(tmp, context);
                None
            }
        });
        log::debug!("model = {:x?}", model);

        // clean up tmpdir
        let _ = tmpdir.close().context("Failed to clean up tempdir");

        if let Some(model) = &model {
            log::info!("Fuzzware created model: {:x?}", model);
        } else {
            log::info!("Fuzzware did not create a model.");
        }

        Ok(model)
    }
}

fn read_model(model_file: &Path) -> Result<Option<MmioModel>> {
    let model: Option<MmioModel> = serde_yaml::from_reader(
        bufreader(model_file).context("Fuzzware MMIO model missing after lockfile vanished")?,
    )
    .context("Failed to deserialize Fuzzware MMIO models")?;

    if let Some(model) = &model {
        log::info!("Loaded shared model: {:x?}", model);
    } else {
        log::info!("Loaded shared model: (empty)");
    }

    Ok(model)
}

fn write_statefile(statefile: &Path) -> Result<()> {
    let qcontrol = qemu_rs::qcontrol();

    let mut statefile = bufwriter(statefile).context("Fuzzware statefile")?;

    write_registers(&mut statefile, qcontrol).context("Failed to write data into state file")?;
    write_memory_blocks_ihex(&mut statefile, qcontrol)
        .context("Failed to write data into state file")?;

    statefile.flush().context("Failed to flush state file")
}

fn write_registers<W: Write>(mut f: W, qcontrol: &QemuStateControl) -> Result<()> {
    for name in registers() {
        let register = Register::try_from(*name)
            .map_err(|err| anyhow::anyhow!("Failed to parse register name {:?}: {}", name, err))?;

        writeln!(f, "{}={:#x}", name, qcontrol.register(register))
            .context("Failed to write register content")?;
    }

    Ok(())
}

fn write_memory_blocks_ihex<W: Write>(mut f: W, qcontrol: &QemuStateControl) -> Result<()> {
    const IHEX_BLOCK_SIZE: usize = 0x80;

    let mut current_ela = None;
    for block in qcontrol.memory_blocks() {
        log::debug!(
            "block start = {:#x?}, len = {:#x?}",
            block.start,
            block.data.len()
        );

        for i in (0..block.data.len()).step_by(IHEX_BLOCK_SIZE) {
            // only add non-zero records
            let value = &block.data[i..i + IHEX_BLOCK_SIZE];
            if value.iter().any(|byte| *byte != 0) {
                let record_start = block.start + i as Address;

                // create ELA record if needed
                let ela = ((record_start >> 16) & 0xffff) as u16;
                if Some(ela) != current_ela {
                    current_ela = Some(ela);
                    writeln!(
                        f,
                        "{}",
                        Record::ExtendedLinearAddress(ela).to_record_string()?
                    )
                    .context("Failed to write ihex ELA record")?;
                }

                // write data block
                writeln!(
                    f,
                    "{}",
                    Record::Data {
                        offset: (record_start & 0xffff) as u16,
                        value: value.to_vec(),
                    }
                    .to_record_string()?
                )
                .context("Failed to write ihex data record")?;
            }
        }
    }

    // write end of file record
    writeln!(f, "{}", Record::EndOfFile.to_record_string()?)
        .context("Failed to write ihex EOF record")?;

    Ok(())
}

fn dump_fuzzware_error(tmp: &Path, context: &AccessContext) {
    if let Err(err) = dump_fuzzware_error_inner(tmp, context) {
        log::error!("Failed to dump fuzzware error archive: {:?}", err);
    }
}

fn dump_fuzzware_error_inner(tmp: &Path, context: &AccessContext) -> Result<()> {
    let path = PathBuf::from(format!("fuzzware-error-{context}.tar.zst"));
    let mut archive = tar::Builder::new(encoder(&path)?);

    archive.mode(tar::HeaderMode::Deterministic);
    archive.follow_symlinks(false);
    archive.append_dir_all("", tmp)?;

    let _ = archive
        .into_inner()
        .context("Failed to finish tar archive")?;

    Ok(())
}

use std::io::Read;
use std::path::Path;
use std::{io::Write, path::PathBuf};

use anyhow::{Context, Result};
use archive::tar::write_serialized_yml;
use archive::ArchiveBuilder;
use common::time::epoch;
use common::{fs::decoder, hashbrown::hash_map::RawEntryMut, FxHashMap, FxHashSet};
use qemu_rs::MmioAddress;

use crate::{
    fuzzware::{runner::FuzzwareRunner, Fuzzware},
    mmio::{aligned, AccessContext, Mmio, MmioContext, ModelContext},
    mmio_model::MmioModel,
};

#[derive(Debug, Default)]
pub struct Modeling {
    archive: Option<ArchiveBuilder>,
    fuzzware: Option<Fuzzware>,
    mmio_models: FxHashMap<MmioContext, MmioModel>,
    access_models: FxHashMap<AccessContext, MmioModel>,
    passthrough: FxHashSet<MmioAddress>,
    no_model: FxHashSet<AccessContext>,
}

impl Modeling {
    pub fn with_archive(archive: ArchiveBuilder) -> Self {
        Self {
            archive: Some(archive),
            ..Default::default()
        }
    }

    pub fn with_models(path: &Path) -> Result<Self> {
        let mut modeling = Self::default();
        decoder(path)
            .and_then(|reader| modeling.load_models(reader))
            .with_context(|| format!("Failed to load models from {path:?}"))?;
        Ok(modeling)
    }

    pub fn fuzzware(&self) -> bool {
        self.fuzzware.is_some()
    }

    pub fn set_fuzzware(
        &mut self,
        runner: FuzzwareRunner,
        model_share: Option<PathBuf>,
    ) -> Result<()> {
        self.fuzzware = Fuzzware::new(runner, model_share).map(Some)?;
        Ok(())
    }

    pub fn load_models<R: Read>(&mut self, reader: R) -> Result<()> {
        serde_yaml::from_reader(reader)
            .context("Failed to deserialize MMIO models")
            .and_then(|models| self.append_models(models))
    }

    pub fn append_models(&mut self, models: Vec<Mmio>) -> Result<()> {
        for model in models {
            // check if models are shadowed
            if let Some(old) = match model.context.clone() {
                ModelContext::AccessContext(context) => self.access_models.get(&context),
                ModelContext::MmioContext(context) => self.mmio_models.get(&context),
            } {
                if model.model.as_ref() == Some(old) {
                    continue;
                } else {
                    log::warn!(
                        "Loaded different model for {:x?}: replacing {:x?} with {:x?}",
                        model.context,
                        old,
                        model.model
                    );
                }
            }

            // add model to archive
            if let Some(archive) = &self.archive {
                write_to_archive(archive, &model)?;
            }

            // collect passtrough MMIO addresses (aligned)
            if let Some(MmioModel::Passthrough { .. }) = model.model {
                let mmio = match &model.context {
                    ModelContext::AccessContext(context) => context.mmio(),
                    ModelContext::MmioContext(context) => context,
                };
                self.passthrough.insert(mmio.addr_aligned());
            }

            // collect models
            match (model.context, model.model) {
                (ModelContext::AccessContext(context), Some(model)) => {
                    self.access_models.insert(context, model);
                }
                (ModelContext::AccessContext(context), None) => {
                    self.no_model.insert(context);
                }
                (ModelContext::MmioContext(context), Some(model)) => {
                    self.mmio_models.insert(context, model);
                }
                (ModelContext::MmioContext(context), _) => {
                    log::warn!("Empty model loaded for MMIO context: {:?}", context)
                }
            }
        }

        Ok(())
    }

    pub fn get(&self, context: &AccessContext) -> Option<&MmioModel> {
        // prefer concrete access model (with pc) over mmio model (without pc)
        self.access_models
            .get(context)
            .or_else(|| self.mmio_models.get(context.mmio()))
    }

    pub fn get_or_create(&mut self, context: &AccessContext) -> Result<Option<&MmioModel>> {
        // prefer concrete access model (with pc) over mmio model (without pc)
        Ok(match self.access_models.raw_entry_mut().from_key(context) {
            RawEntryMut::Occupied(entry) => Some(entry.into_mut()),
            RawEntryMut::Vacant(entry) => {
                // search for mmio model
                if let Some(model) = self.mmio_models.get(context.mmio()) {
                    return Ok(Some(model));
                }

                // fuzzware model creation
                if let Some(fuzzware) = &mut self.fuzzware {
                    // only try to create model once
                    if !self.no_model.contains(context) && !fuzzware.limit_reached(context) {
                        let new_model = fuzzware.model(context).context("Fuzzware modeling")?;
                        log::debug!("new_model = {:#x?}", new_model);

                        if let Some(model) = new_model {
                            // collect passtrough MMIO address (aligned)
                            if let MmioModel::Passthrough { .. } = model {
                                self.passthrough.insert(context.mmio().addr_aligned());
                            }

                            // add model to archive
                            if let Some(archive) = &self.archive {
                                write_to_archive(
                                    archive,
                                    &Mmio {
                                        context: ModelContext::AccessContext(context.clone()),
                                        model: Some(model.clone()),
                                    },
                                )?;
                            }

                            // save model
                            return Ok(Some(entry.insert(context.clone(), model).1));
                        } else {
                            // add model to archive
                            if let Some(archive) = &self.archive {
                                write_to_archive(
                                    archive,
                                    &Mmio {
                                        context: ModelContext::AccessContext(context.clone()),
                                        model: None,
                                    },
                                )?;
                            }

                            // save no-model
                            self.no_model.insert(context.clone());
                        }
                    }
                }

                // no model found
                None
            }
        })
    }

    pub fn is_passthrough(&self, mmio: MmioAddress) -> bool {
        self.passthrough.contains(&aligned(mmio))
    }

    fn models(&self) -> impl Iterator<Item = Mmio> + '_ {
        self.mmio_models
            .iter()
            .map(|(context, model)| Mmio {
                context: ModelContext::MmioContext(context.clone()),
                model: Some(model.clone()),
            })
            .chain(self.access_models.iter().map(|(context, model)| Mmio {
                context: ModelContext::AccessContext(context.clone()),
                model: Some(model.clone()),
            }))
    }

    pub fn write_to<W: Write>(&self, mut writer: W) -> Result<()> {
        let mmio: Vec<_> = self.models().collect();

        serde_yaml::to_writer(&mut writer, &mmio).context("Failed to serialize report")
    }
}

fn write_to_archive(archive: &ArchiveBuilder, model: &Mmio) -> Result<()> {
    write_serialized_yml(
        &mut archive.borrow_mut(),
        &format!("config/models/{}.yml", model.context),
        epoch()?,
        model,
    )
    .context("Failed to write model to archive")
}

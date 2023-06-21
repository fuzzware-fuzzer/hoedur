use std::cmp;
use std::ffi::CStr;
use std::path::PathBuf;
use std::{ffi::CString, fmt};

use anyhow::{bail, Context, Result};
use common::file_storage::FileStorage;
use serde::{Deserialize, Serialize};

pub use qemu_sys::PAGE_SIZE;

use crate::{Address, USize};

#[derive(Debug, Serialize, Deserialize)]
pub struct MemoryMap {
    name: Option<String>,
    #[serde(flatten)]
    region: MemoryRegion,
    alias: Option<Vec<MemoryMapAlias>>,
    permission: Option<MemoryPermission>,
    file: Option<FileData>,
    #[serde(rename = "type")]
    memory_type: MemoryType,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MemoryMapAlias {
    name: Option<String>,
    address: Address,
    offset: Option<USize>,
    size: Option<USize>,
    permission: Option<MemoryPermission>,
}

impl MemoryMap {
    pub fn prepare_file(&mut self, file_storage: &mut FileStorage) -> Result<()> {
        if let Some(file) = &mut self.file {
            file_storage.read(&file.path)?;
        }

        Ok(())
    }

    fn load_file(&self, file_storage: &FileStorage) -> Result<Option<Vec<u8>>> {
        Ok(if let Some(file_data) = &self.file {
            // get file content
            let path = &file_data.path;
            let content = file_storage.get(path)?;
            let content_len = content.len();
            let file_seek = file_data.seek.unwrap_or(0) as usize;
            let file_len = content_len.checked_sub(file_seek).with_context(||
                format!("Seek of {file_seek} bytes exceeds file length ({content_len} bytes) for file {path:?}")
            )?;

            // region
            let region_start = self.region.address as usize;
            let region_size = self.region.size;

            // data
            let offset = file_data.offset.unwrap_or(0);
            let data_length = file_data.length.unwrap_or(file_len as USize);
            let data_offset = cmp::min(offset, region_size) as usize;
            let data_end = cmp::min(offset.saturating_add(data_length), region_size) as usize;
            let data = data_offset..data_end;

            // file
            let file_start = file_seek as usize;
            let file_end = file_start + data.len();
            let file = file_start..file_end;

            log::info!(
                "Loading data into memory {:#x?}..{:#x?} ({:#x?} bytes) from file at {:#x?}..{:#x?} ({:#x?} bytes, remaining length {:#x?} bytes) {:?}",
                region_start + data.start,
                region_start + data.end,
                data.len(),
                file.start,
                file.end,
                file.len(),
                content_len - file.end,
                path
            );

            // fill region
            let mut buffer = vec![0u8; self.region.size as usize];
            buffer[data].copy_from_slice(&content[file]);

            Some(buffer)
        } else {
            None
        })
    }

    pub(crate) fn as_qemu_memory_map(&self, file_storage: &FileStorage) -> Result<QemuMemoryMap> {
        // get region name
        let mem_type = self.memory_type.as_str();
        let name = match &self.name {
            Some(name) => format!("{mem_type}.{name}"),
            None => format!("{}.{:x}", mem_type, self.region.address),
        };
        let name = CString::new(name).context("Failed to create CString")?;

        // verify page boundries: start + size
        // ignore DMA memory regions
        if self.memory_type != MemoryType::Dma {
            verify_page_boundry(
                "MemoryMap",
                [("start", self.region.address), ("size", self.region.size)],
            )?;
        }

        // qemu memory data
        let data = match self.memory_type {
            MemoryType::Ram | MemoryType::Rom => {
                let readonly = self.memory_type == MemoryType::Rom;

                match self.load_file(file_storage)? {
                    None => QemuMemoryData::Zero { readonly },
                    Some(data) => QemuMemoryData::File { data, readonly },
                }
            }
            MemoryType::Mmio | MemoryType::Dma => {
                if self.file.is_some() {
                    bail!("MMIO/DMA memory region with file content is currently not supported.");
                }

                QemuMemoryData::Mmio {
                    dma: self.memory_type == MemoryType::Dma,
                }
            }
        };

        // alias memory map
        let alias = match &self.alias {
            Some(alias) => alias
                .iter()
                .map(|alias| alias.as_qemu_memory_map(self).context("alias memory map"))
                .collect::<Result<Vec<_>>>()?,
            None => vec![],
        };

        // default permission
        let permission = self.permission.clone().unwrap_or_else(|| MemoryPermission {
            executable: self.memory_type.executable(),
            except: None,
        });

        Ok(QemuMemoryMap {
            name,
            start: self.region.address,
            size: self.region.size,
            alias,
            permission,
            data,
        })
    }
}

impl MemoryMapAlias {
    pub(crate) fn as_qemu_memory_map(&self, base: &MemoryMap) -> Result<QemuMemoryMapAlias> {
        // get region name
        let mem_type = base.memory_type.as_str();
        let name = match &self.name {
            Some(name) => format!("{mem_type}-alias.{name}"),
            None => format!("{}-alias.{:x}", mem_type, self.address),
        };
        let name = CString::new(name).context("Failed to create CString")?;

        let start = self.address as USize;
        let base_size = base.region.size;
        let base_offset = self.offset.unwrap_or(0) as USize;
        let size = self
            .size
            .unwrap_or_else(|| base_size.saturating_sub(base_offset)) as USize;

        verify_page_boundry("MemoryMapAlias", [("start", start), ("size", size)])?;
        if (size + base_offset) > base_size {
            bail!(
                "MemoryMapAlias has invalid size: {:#x?} + offset {:#x?} must be <= base MemoryMap size {:#x?}.",
                size,
                base_offset,
                base_size
            );
        }

        Ok(QemuMemoryMapAlias {
            name,
            start,
            size: size as USize,
            base_offset,
            permission: self.permission.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    address: Address,
    size: USize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileData {
    offset: Option<USize>,
    path: PathBuf,
    seek: Option<USize>,
    length: Option<USize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoryType {
    Ram,
    Rom,
    Mmio,
    Dma,
}

impl MemoryType {
    pub fn executable(&self) -> bool {
        match self {
            Self::Ram => false,
            Self::Rom => true,
            Self::Mmio => false,
            Self::Dma => false,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Ram => "ram",
            Self::Rom => "rom",
            Self::Mmio => "mmio",
            Self::Dma => "dma",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPermission {
    executable: bool,
    except: Option<Vec<MemoryPermissionException>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPermissionException {
    offset: USize,
    size: USize,
}

impl MemoryMap {
    pub fn new(
        name: Option<String>,
        region: MemoryRegion,
        alias: Option<Vec<MemoryMapAlias>>,
        permission: Option<MemoryPermission>,
        file: Option<FileData>,
        memory_type: MemoryType,
    ) -> Self {
        Self {
            name,
            region,
            alias,
            permission,
            file,
            memory_type,
        }
    }
}

impl MemoryRegion {
    pub fn new(address: Address, size: USize) -> Self {
        Self { address, size }
    }
}

impl FileData {
    pub fn new(
        offset: Option<USize>,
        path: PathBuf,
        seek: Option<USize>,
        length: Option<USize>,
    ) -> Self {
        Self {
            offset,
            path,
            seek,
            length,
        }
    }
}

impl MemoryPermission {
    pub fn new(executable: bool, except: Option<Vec<MemoryPermissionException>>) -> Self {
        Self { executable, except }
    }
}

impl MemoryPermissionException {
    pub fn new(offset: USize, size: USize) -> Self {
        Self { offset, size }
    }
}

#[derive(Debug)]
pub(crate) struct QemuMemoryMap {
    name: CString,
    pub(crate) start: Address,
    pub(crate) size: USize,
    alias: Vec<QemuMemoryMapAlias>,
    permission: MemoryPermission,
    pub(crate) data: QemuMemoryData,
}

#[derive(Debug, Deserialize)]
pub(crate) struct QemuMemoryMapAlias {
    name: CString,
    start: Address,
    size: USize,
    base_offset: USize,
    permission: Option<MemoryPermission>,
}

pub(crate) enum QemuMemoryData {
    Zero { readonly: bool },
    File { data: Vec<u8>, readonly: bool },
    Mmio { dma: bool },
}

impl QemuMemoryMap {
    pub fn name(&self) -> &CStr {
        self.name.as_c_str()
    }

    pub fn start(&self) -> u32 {
        self.start
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn alias(&self) -> &[QemuMemoryMapAlias] {
        self.alias.as_ref()
    }

    pub fn data(&self) -> &QemuMemoryData {
        &self.data
    }

    pub fn contains(&self, address: Address) -> bool {
        // memory map contains address
        contains(self.start, self.size, address)
            // or alias mapping contains address
            || self
                .alias
                .iter()
                .any(|alias| alias.contains(address))
    }

    pub fn offset(&self, address: Address) -> Option<USize> {
        // memory map offset
        offset(self.start, self.size, address)
            // alias memory map offset
            .or_else(|| self.alias.iter().find_map(|alias| alias.offset(address)))
    }

    pub fn contains_map(&self, other: &Self) -> bool {
        debug_assert!(other.size > 0);

        self.contains(other.start)
            || self.contains(other.start + (other.size - 1))
            || other.alias.iter().any(|alias| {
                debug_assert!(alias.size > 0);
                self.contains(alias.start) || self.contains(alias.start + (alias.size - 1))
            })
    }

    pub fn readonly(&self) -> bool {
        match &self.data {
            QemuMemoryData::Zero { readonly } | QemuMemoryData::File { readonly, .. } => *readonly,
            QemuMemoryData::Mmio { .. } => false,
        }
    }

    pub fn executable(&self, address: Address) -> Option<bool> {
        // this memory map contains address?
        offset(self.start, self.size, address)
            // then is address executable?
            .map(|offset| self.permission.executable(offset))
            // or delegate to alias map
            .or_else(|| {
                self.alias
                    .iter()
                    .find_map(|alias| alias.executable(address, &self.permission))
            })
    }

    pub fn dirty_map(&self) -> bool {
        match &self.data {
            QemuMemoryData::Zero { readonly } | QemuMemoryData::File { readonly, .. } => !*readonly,
            QemuMemoryData::Mmio { .. } => false,
        }
    }

    pub fn allow_overlap(&self) -> bool {
        match &self.data {
            QemuMemoryData::Zero { .. } | QemuMemoryData::File { .. } => false,
            QemuMemoryData::Mmio { dma } => *dma,
        }
    }
}

impl QemuMemoryMapAlias {
    pub fn name(&self) -> &CStr {
        self.name.as_c_str()
    }

    pub fn start(&self) -> u32 {
        self.start
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn base_offset(&self) -> u32 {
        self.base_offset
    }

    pub fn contains(&self, address: Address) -> bool {
        contains(self.start, self.size, address)
    }

    pub fn offset(&self, address: Address) -> Option<USize> {
        offset(self.start, self.size, address)
    }

    fn executable(&self, address: Address, parent_permission: &MemoryPermission) -> Option<bool> {
        // this alias map contains address?
        offset(self.start, self.size, address).map(|offset| {
            // custom alias permission or parent permission
            self.permission
                .as_ref()
                .unwrap_or(parent_permission)
                .executable(offset)
        })
    }
}

impl MemoryPermission {
    fn executable(&self, offset: USize) -> bool {
        if let Some(except) = &self.except {
            if except
                .iter()
                .any(|except| contains(except.offset, except.size, offset))
            {
                return !self.executable;
            }
        }

        self.executable
    }
}

impl fmt::Debug for QemuMemoryData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero { readonly } => f
                .debug_struct("QemuMemoryData::Zero")
                .field("readonly", readonly)
                .finish(),
            Self::File { data, readonly } => f
                .debug_struct("QemuMemoryData::File")
                .field("data", &data.len())
                .field("readonly", readonly)
                .finish(),
            Self::Mmio { dma } => f
                .debug_struct("QemuMemoryData::Mmio")
                .field("dma", dma)
                .finish(),
        }
    }
}

// memory map contains address
pub fn contains(start: Address, size: USize, address: Address) -> bool {
    address >= start && (address - start) < size
}

/// offset to start when within region
pub fn offset(start: Address, size: USize, address: Address) -> Option<USize> {
    // clippy issue ##9422
    #[allow(clippy::unnecessary_lazy_evaluations)]
    contains(start, size, address).then(|| address - start)
}

fn verify_page_boundry(struct_name: &'static str, boundries: [(&str, u32); 2]) -> Result<()> {
    for (name, value) in boundries {
        if (value as usize) % PAGE_SIZE != 0 {
            bail!(
                "{} has invalid {}: {:#x?} must be a multiple of the page size {:#x?}.",
                struct_name,
                name,
                value,
                PAGE_SIZE
            );
        }
    }

    Ok(())
}

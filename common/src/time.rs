use std::time::SystemTime;

use anyhow::{Context, Result};

pub type Epoch = u64;

pub fn epoch() -> Result<Epoch> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("invalid system time")?
        .as_secs())
}

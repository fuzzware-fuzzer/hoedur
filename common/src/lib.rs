pub mod config;
pub mod error;
pub mod exit;
pub mod file_storage;
pub mod fork;
pub mod fs;
pub mod log;
pub mod random;
pub mod time;

use std::hash::BuildHasherDefault;

pub use hashbrown;
pub use rustc_hash::FxHasher;
pub type FxHashMap<K, V> = hashbrown::HashMap<K, V, BuildHasherDefault<rustc_hash::FxHasher>>;
pub type FxHashSet<K> = hashbrown::HashSet<K, BuildHasherDefault<rustc_hash::FxHasher>>;

pub const GIT_VERSION: &str = git_version::git_version!();
pub const CONFIG: &str = include_str!("config.rs");

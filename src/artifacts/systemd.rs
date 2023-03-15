pub use crate::prelude::{UserInfo, known_hosts};
pub use crate::ChRootFileSystem;
pub use forensic_rs::{
    core::fs::StdVirtualFS, prelude::ForensicResult, traits::vfs::VirtualFileSystem,
};
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::{HashMap, BTreeSet};
pub use std::{
    fs,
    io::BufRead,
    path::{Path, PathBuf},
};

#[derive(Debug, Default, Clone)]
pub struct SystemdService {
    pub unit: HashMap<String, BTreeSet<String>>,
    pub service: HashMap<String, BTreeSet<String>>,
    pub install: HashMap<String, BTreeSet<String>>,
}

impl SystemdService {
    pub fn process_systemd_files() {

    }
}


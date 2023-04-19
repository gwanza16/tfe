pub use crate::prelude::{UserInfo, authorized_keys};
pub use crate::ChRootFileSystem;
pub use forensic_rs::{
    core::fs::StdVirtualFS, prelude::ForensicResult, traits::vfs::VirtualFileSystem,
};
use lazy_static::lazy_static;
use regex::Regex;
pub use std::{
    fs,
    io::BufRead,
    path::{Path, PathBuf},
};

#[derive(Debug, Default, Clone)]
pub struct AuthorizedKey {
    pub key_type: String,
    pub public_key: String,
    pub comment: String,
}

lazy_static! {
    pub static ref AUTHORIZED_KEYS_COMPONENTS: Regex =
        Regex::new(r#"^((?:[\w-]+(?:="[\w\s]*")?(?:,[\w-]+(?:="[\w\s]*")?)*)\s+)?(\S+)\s+(\S+)\s*(.*)$"#).unwrap();
}

pub fn get_authorized_keys(
    vfs: &mut impl VirtualFileSystem,
    user_home_path: PathBuf,
) -> ForensicResult<Vec<AuthorizedKey>> {
    let authorized_keys = vfs.read_to_string(
        user_home_path.join(".ssh/authorized_keys").as_path())?;

    let reader_groups = std::io::BufReader::new(authorized_keys.as_bytes());
    let mut system_authorized_keys: Vec<AuthorizedKey> = Vec::new();

    for authorized_key in reader_groups.lines() {
        let authorized_key = authorized_key?;
        let captures = AUTHORIZED_KEYS_COMPONENTS.captures(&authorized_key).unwrap();
        let authorized_key = AuthorizedKey {
            key_type: captures.get(1).unwrap().as_str().to_string(),
            public_key: captures.get(2).unwrap().as_str().to_string(),
            comment: captures.get(3).unwrap().as_str().to_string(),
        };
        system_authorized_keys.push(authorized_key);
    }

    Ok(system_authorized_keys)
}

#[test]
fn should_process_group_file() {
    let base_path = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let virtual_file_system = &Path::new(&base_path).join("artifacts");

    let mut _std_vfs = StdVirtualFS::new();
    let mut vfs = ChRootFileSystem::new(virtual_file_system, Box::new(_std_vfs));
    let user_info = UserInfo {
        name: "forensicrs".to_string(),
        id: 1,
        home: PathBuf::from("/home/forensicrs"),
        shell: "/bin/bash".to_string(),
        groups: Vec::new(),
    };
    let authorized_keys = get_authorized_keys(&mut vfs, user_info.home);

    print!("{:?}", authorized_keys);
}

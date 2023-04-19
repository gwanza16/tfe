pub use crate::prelude::{UserInfo, known_hosts};
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

#[derive(Debug, Default, Clone, PartialEq)]
pub struct KnownHost {
    pub hostname: String,
    pub key_type: String,
    pub public_key: String,
    pub comment: String,
}

lazy_static! {
    pub static ref KNOWN_HOSTS_COMPONENTS: Regex =
        Regex::new(r#"^([^\s]+)\s+([^\s]+)\s+([^\s]+)\s*(.*)$"#).unwrap();
}

impl KnownHost {
    pub fn get_known_hosts(
        vfs: &mut impl VirtualFileSystem,
        user_home_path: PathBuf,
    ) -> ForensicResult<Vec<Self>> {
        let known_hosts = vfs.read_to_string(
            user_home_path.join(".ssh/known_hosts").as_path())?;
    
        let reader_groups = std::io::BufReader::new(known_hosts.as_bytes());
        let mut system_known_hosts: Vec<Self> = Vec::new();
    
        for known_host in reader_groups.lines() {
            let known_host = known_host?;
            let captures = KNOWN_HOSTS_COMPONENTS.captures(&known_host).unwrap();
            let known_host = Self {
                hostname: captures.get(1).unwrap().as_str().trim().to_string(),
                key_type: captures.get(2).unwrap().as_str().trim().to_string(),
                public_key: captures.get(3).unwrap().as_str().trim().to_string(),
                comment: captures.get(4).unwrap().as_str().trim().to_string(),
            };
            system_known_hosts.push(known_host);
        }
    
        Ok(system_known_hosts)
    }
}

#[test]
fn should_process_known_hosts_file() {
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
    let authorized_keys = KnownHost::get_known_hosts(&mut vfs, user_info.home);

    match authorized_keys {
        Ok(keys) => {
            let authorized_key_test = KnownHost {
                hostname: "|1|TfKl866biYXUtnTkYkd0hRxU3qU=|8wzgJpCzm2GrhwDS507gudKHlO4=".to_string(),
                key_type: "ssh-ed25519".to_string(),
                public_key: String::from(r#"AAAAC3NzaC1lZDI1NTE5AAAAIDwrpaWIiSPnPg5HPKCVfYXzkTF6m3eTMSfnopZSiNE8"#),
                comment: "".to_string()
            };
            assert_eq!(authorized_key_test, keys[0]);
        },
        Err(e) => {
            panic!("Error getting known_hosts: {:?}", e);
        }
    }
}

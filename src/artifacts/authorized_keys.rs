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

#[derive(Debug, Default, Clone, PartialEq)]
pub struct AuthorizedKey {
    pub key_type: String,
    pub public_key: String,
    pub comment: String,
}

lazy_static! {
    pub static ref AUTHORIZED_KEYS_COMPONENTS: Regex =
        Regex::new(r#"^((?:[\w-]+(?:="[\w\s]*")?(?:,[\w-]+(?:="[\w\s]*")?)*)\s+)?(\S+)\s+(\S+)\s*(.*)$"#).unwrap();
}

impl AuthorizedKey {
    pub fn get_authorized_keys(
        vfs: &mut impl VirtualFileSystem,
        user_home_path: PathBuf,
    ) -> ForensicResult<Vec<Self>> {
        let authorized_keys = vfs.read_to_string(
            user_home_path.join(".ssh/authorized_keys").as_path())?;
    
        let reader_groups = std::io::BufReader::new(authorized_keys.as_bytes());
        let mut system_authorized_keys: Vec<Self> = Vec::new();
    
        for authorized_key in reader_groups.lines() {
            let authorized_key = authorized_key?;
            let captures = AUTHORIZED_KEYS_COMPONENTS.captures(&authorized_key).unwrap();
            let authorized_key = Self {
                key_type: captures.get(1).unwrap().as_str().trim().to_string(),
                public_key: captures.get(2).unwrap().as_str().trim().to_string(),
                comment: captures.get(3).unwrap().as_str().trim().to_string(),
            };
            system_authorized_keys.push(authorized_key);
        }
    
        Ok(system_authorized_keys)
    }
}


#[test]
fn should_process_authorized_keys_file() {
    let user_info = UserInfo {
        name: "forensicrs".to_string(),
        id: 1,
        home: PathBuf::from("/home/forensicrs"),
        shell: "/bin/bash".to_string(),
        groups: Vec::new(),
    };
    let base_path = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let virtual_file_system = &Path::new(&base_path).join("artifacts");

    let mut _std_vfs = StdVirtualFS::new();
    let mut vfs = ChRootFileSystem::new(virtual_file_system, Box::new(_std_vfs));

    let authorized_keys = AuthorizedKey::get_authorized_keys(&mut vfs, user_info.home);
    
    match authorized_keys {
        Ok(keys) => {
            let authorized_key_test = AuthorizedKey {
                key_type: "ssh-rsa".to_string(),
                public_key: String::from(r#"AAAAB3NzaC1yc2EAAAADAQABAAABAQDCHjg44Q5a5hAPGr5xvE+31tWcGtF5y9XJyLgCH1twBL2C/c5w5Z5xh+FbG+qo3qHmtyxCf9m1eB4j0fL8Lp0G/4+rPjvS+C96fc0lNlDrmXdh2NkwvCekWU6nK70wLxE/xZ2r55rJbDB6xtcqG6nXU6jfGp7V/R3d3wKkVabSKfZdR7gYlQeNhH7ivX9PhyPvmuw/6DJHioJ/BK0eFrRSfNlGd/zBbNzKpU6NR9U7Vp/gq3uTNlvVgG1ZuL1mTkH2eYTV7gMmbgLzRL9SS5kDdQKzy32wicBx5Z5iVrgvqKceYgGz+1lXt4j4vL8WAVw0M4UIx+ZSfjK8/oWz"#),
                comment: "user@host".to_string()
            };
            assert_eq!(authorized_key_test, keys[0]);
        },
        Err(e) => {
            panic!("Error getting authorized keys: {:?}", e);
        }
    }
}

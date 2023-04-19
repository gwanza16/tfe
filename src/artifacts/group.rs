pub use forensic_rs::{traits::vfs::VirtualFileSystem, prelude::ForensicResult, core::fs::StdVirtualFS};
pub use std::{
    io::BufRead, path::{Path, PathBuf},
};

pub use crate::ChRootFileSystem;
pub use crate::prelude::UserInfo;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Group {
    pub name: String,
    pub group_id: u32,
    pub users: Vec<String>
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct SystemGroups {
    pub groups: Vec<Group>,
}

impl SystemGroups {

    pub fn get_groups_for_user(&self, username: &str) -> ForensicResult<Vec<Group>> {
        let mut groups = Vec::new();
        for group in &self.groups {
            if group.users.contains(&username.to_string()) {
                groups.push(group.clone());
            }
        }
        Ok(groups)
    }

    pub fn process_group_file(vfs: &mut impl VirtualFileSystem) -> ForensicResult<Self> {

        let groups = vfs.read_to_string(std::path::PathBuf::from("/etc/group").as_path())?;
        let reader_groups = std::io::BufReader::new(groups.as_bytes());
    
        let mut system_groups: Vec<Group> = Default::default();
        
        for group_line in reader_groups.lines() {
            let group_line = group_line?;
            let group_columns: Vec<&str> = group_line.split(":").collect();
            if group_columns.len() < 2 {
                continue;
            }
    
            let mut users: Vec<String> = Vec::new();
            for member in group_columns[3].split(",") {
                users.push(member.trim().to_string());
            }
    
            let group = Group {
                name: group_columns[0].trim().to_string(),
                group_id: group_columns[2].trim().parse::<u32>().unwrap(),
                users
            };
    
            system_groups.push(group);
        }
    
        Ok(Self {
            groups: system_groups
        })
    
    }
}

#[test]
fn should_process_group_file() {
    let base_path = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let virtual_file_system = &Path::new(&base_path).join("artifacts");

    let mut _std_vfs = StdVirtualFS::new();
    let mut vfs = ChRootFileSystem::new(virtual_file_system, Box::new(_std_vfs));
    let system_groups = SystemGroups::process_group_file(&mut vfs);

    match system_groups {
        Ok(groups) => {
            let root_group = Group {
                name: "root".to_string(),
                group_id: 0,
                users: vec!["".to_string()],
            };
            let adm_group_users = vec!["syslog".to_string(), "forensicrs".to_string()];
            let adm_group = Group {
                name: "adm".to_string(),
                group_id: 4,
                users: adm_group_users,
            };
            assert_eq!(root_group, groups.groups[0]);
            assert_eq!(adm_group, groups.groups[4]);
        },
        Err(e) => {
            panic!("Error getting groups: {:?}", e);
        }
    }
}
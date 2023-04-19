pub use forensic_rs::{traits::vfs::VirtualFileSystem, prelude::ForensicResult, core::fs::StdVirtualFS};
use std::{
    io::BufRead,
};

pub use crate::ChRootFileSystem;

#[derive(Debug, Default, Clone)]
pub struct Group {
    pub name: String,
    pub group_id: u32,
    pub users: Vec<String>
}

#[derive(Debug, Default, Clone)]
pub struct SystemGroups {
    pub groups: Vec<Group>,
}

impl SystemGroups {

    pub fn get_groups_for_user(&self, username: &str) -> Vec<Group> {
        let mut groups = Vec::new();
        for group in &self.groups {
            if group.users.contains(&username.to_string()) {
                groups.push(group.clone());
            }
        }
        groups
    }
}

pub fn process_group_file(vfs: &mut impl VirtualFileSystem) -> ForensicResult<SystemGroups> {

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
            users.push(member.to_string());
        }

        let group = Group {
            name: group_columns[0].to_string(),
            group_id: group_columns[2].parse::<u32>().unwrap(),
            users
        };

        system_groups.push(group);
    }

    Ok(SystemGroups {
        groups: system_groups
    })

}

#[test]
fn should_process_group_file() {
    let mut _std_vfs = StdVirtualFS::new();
    let mut vfs = ChRootFileSystem::new("/", Box::new(_std_vfs));
    let system_groups = process_group_file(&mut vfs);

    print!("{:?}", system_groups);
}
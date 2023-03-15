use forensic_rs::prelude::ForensicError;
pub use forensic_rs::{
    core::fs::StdVirtualFS, prelude::ForensicResult, traits::vfs::VirtualFileSystem,
};
use lazy_static::lazy_static;
use regex::{Captures, Regex};
use std::{
    collections::{BTreeSet, HashMap},
    io::BufRead,
    path::PathBuf,
};

use crate::prelude::{
    bash::BashHistory,
    group::{process_group_file, Group},
};
pub use crate::{BashRcConfig, ChRootFileSystem};

lazy_static! {
    pub static ref VARIABLE_REGEX: Regex = Regex::new(
        r#"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(?:(?:'(.*)')|(?:"(.*)")|([^#\n]*))\s*(?:#.*)?"#
    )
    .unwrap();
    pub static ref ALIAS_REGEX: Regex =
        Regex::new(r#"^\s*alias\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:(?:'(.*)')|(?:"(.*)")|(.*))"#)
            .unwrap();
    pub static ref EXPORT_REGEX: Regex =
        Regex::new(r#"^\s*export\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:(?:'(.*)')|(?:"(.*)")|(.*))"#)
            .unwrap();
}

#[derive(Debug, Default, Clone)]
pub struct UserInfo {
    pub name: String,
    pub id: u32,
    pub home: PathBuf,
    pub shell: String,
    pub groups: Vec<Group>,
}

/*pub struct UserArtifact {
    bash_config: BashRcConfig,
    user_info: UserInfo,
}*/

impl UserInfo {
    pub fn load_bash_config(
        &self,
        fs: &mut impl VirtualFileSystem,
    ) -> ForensicResult<BashRcConfig> {
        let mut rc_config = BashRcConfig::default();
        rc_config.process_bashrcfile(self.home.as_path(), fs);

        Ok(rc_config)
    }

    pub fn load_bash_history(
        &self,
        fs: &mut impl VirtualFileSystem,
    ) -> ForensicResult<BashHistory> {
        let mut bash_history = BashHistory::default();

        let user_home = self.home.as_path().join(".bash_history");

        bash_history.read_history_timestamps(user_home, fs);

        Ok(bash_history)
    }
}

pub struct SystemInfo {
    pub users: Vec<UserInfo>,
}
impl SystemInfo {
    pub fn load(vfs: &mut impl VirtualFileSystem) -> ForensicResult<Self> {
        // Load user info from /etc/passwd ...
        let passwd = vfs.read_to_string(std::path::PathBuf::from("/etc/passwd").as_path())?;
        let reader_passwd = std::io::BufReader::new(passwd.as_bytes());
        let mut users = Vec::with_capacity(64);

        for passwd_line in reader_passwd.lines() {
            let passwd_line = passwd_line?;
            if passwd_line.is_empty() {
                continue;
            }
            let passwd_columns: Vec<&str> = passwd_line.split(":").collect();
            let new_user = UserInfo {
                name: passwd_columns
                    .get(0)
                    .ok_or_else(|| ForensicError::BadFormat)?
                    .to_string(),
                id: passwd_columns
                    .get(2)
                    .ok_or_else(|| ForensicError::BadFormat)?
                    .parse::<u32>()
                    .map_err(|_| ForensicError::BadFormat)?,
                home: PathBuf::from(
                    passwd_columns
                        .get(5)
                        .ok_or_else(|| ForensicError::BadFormat)?
                        .to_string(),
                ),
                shell: passwd_columns[6].to_owned(),
                groups: Self::get_user_groups(vfs, passwd_columns[1])?,
            };
            users.push(new_user)
        }
        //TODO: Rellenar con la info de usuarios sacada de /etc/passwd
        Ok(Self { users })
    }

    pub fn get_user_groups(
        vfs: &mut impl VirtualFileSystem,
        username: &str,
    ) -> ForensicResult<Vec<Group>> {
        // Load user info from /etc/groups ...
        let system_groups = process_group_file(vfs)?;
        Ok(system_groups.get_groups_for_user(username))
    }
}

pub fn insert_new_values_to_struct(
    captures: Captures,
    atributte: &mut HashMap<String, BTreeSet<String>>,
) {
    let mut captures_possible_values = BTreeSet::<String>::new();
    //gets the value of the key and the value from regex
    let key_pair = keys_and_values_from_regex(captures);

    //inserts the key_pair into aliases list
    match atributte.entry(key_pair.0.to_string()) {
        std::collections::hash_map::Entry::Occupied(entry) => {
            entry.into_mut().insert(key_pair.1.to_string());
        }
        std::collections::hash_map::Entry::Vacant(_) => {
            captures_possible_values.insert(key_pair.1.to_string());
            atributte.insert(key_pair.0.to_string(), captures_possible_values);
        }
    }
}

pub fn keys_and_values_from_regex(captures: Captures) -> (&str, &str) {
    let key = match captures.get(1) {
        Some(v) => v.as_str(),
        None => "no match",
    };

    let value = match (captures.get(2), captures.get(3), captures.get(4)) {
        (Some(v), None, None) => v.as_str(),
        (None, Some(v), None) => v.as_str(),
        (None, None, Some(v)) => v.as_str(),
        _ => "no match",
    };

    (key, value)
}

#[test]
fn should_execute_start_function() {
    let base_path = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let bashrc_path = std::path::Path::new(&base_path).join("artifacts");

    let mut _std_vfs = StdVirtualFS::new();
    let mut vfs = ChRootFileSystem::new(bashrc_path, Box::new(_std_vfs));
    let groups_result = SystemInfo::get_user_groups(&mut vfs, "forensicrs");
    let user_info = match groups_result {
        Ok(groups) => UserInfo {
            name: "forensicrs".to_string(),
            id: 1,
            home: PathBuf::from("/home/forensicrs"),
            shell: "/bin/bash".to_string(),
            groups,
        },
        Err(err) => {
            // handle the error case...
            // for example, you could return an error value or panic
            panic!("Failed to get user groups: {:?}", err);
        }
    };

    let result = UserInfo::load_bash_config(&user_info, &mut vfs).expect("Couldn't process bash");
    println!("{:?}", result);
}

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
    group::{ Group, SystemGroups}, bash::BashHistory, zsh::{ZshRcConfig, ZshHistory}, authorized_keys::AuthorizedKey, known_hosts::KnownHost, crontab::{CrontabTask, CrontabSchedule}, services::{InitdService, SystemdService},
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

#[derive(Debug, Default, Clone)]
pub struct SystemInfo {
    pub users: Vec<UserInfo>,
}

#[derive(Debug, Default, Clone)]
pub struct UserArtifact {
    pub user_info: UserInfo,
    pub bash_config: BashRcConfig,
    pub bash_history: BashHistory,
    pub zsh_config: ZshRcConfig,
    pub zsh_history: ZshHistory,
    pub authorized_keys: Vec<AuthorizedKey>,
    pub known_hosts: Vec<KnownHost>,
    pub programmed_tasks: Vec<CrontabTask>,
    pub groups: Vec<Group>,
    pub init_services: Vec<InitdService>,
    pub systemd_services: Vec<SystemdService>
}

impl UserArtifact {
    pub fn get_user_artifacts(username: String, vfs: &mut impl VirtualFileSystem) -> ForensicResult<Self> {
        let userinfo = UserInfo::get_user_info(username, vfs)?;
        let mut crontab_schedule = CrontabSchedule::default();
        let system_groups = SystemGroups::process_group_file(vfs)?;

        Ok(UserArtifact {
            user_info: userinfo.clone(),
            bash_config: BashRcConfig::load_bash_config(userinfo.clone(), vfs)?,
            bash_history: BashHistory::load_bash_history(userinfo.clone(), vfs)?,
            zsh_config: ZshRcConfig::load_zsh_config(userinfo.clone(), vfs)?,
            zsh_history: ZshHistory::load_zsh_history(userinfo.clone(), vfs)?,
            authorized_keys: AuthorizedKey::get_authorized_keys(vfs, 
                userinfo.home.clone())?,
            known_hosts: KnownHost::get_known_hosts(vfs, userinfo.home.clone())?,
            programmed_tasks: CrontabSchedule::process_crontab_files(&mut crontab_schedule, 
                vfs, userinfo.name.clone())?,
            groups: system_groups.get_groups_for_user(&userinfo.name.clone())?,
            init_services: InitdService::process_init_services_files(vfs)?,
            systemd_services: SystemdService::process_services_files(vfs)?
        })

    }

    pub fn get_system_artifacts(users: SystemInfo, vfs: &mut impl VirtualFileSystem) -> ForensicResult<Vec<Self>> {
        let mut system_artifacts: Vec<Self> = Vec::new();
        for user in users.users {
            let username = user.name;
            let user_artifact = Self::get_user_artifacts(username, vfs)?;
            system_artifacts.push(user_artifact);
        }
        Ok(system_artifacts)
    }
}

impl UserInfo {
    pub fn get_user_info(username: String, vfs: &mut impl VirtualFileSystem) -> ForensicResult<Self> {
        let passwd_file = vfs.read_to_string(std::path::PathBuf::from("/etc/passwd").as_path())?;
        let mut user_info = UserInfo::default();
    
        for line in passwd_file.lines() {
            let columns: Vec<&str> = line.split(':').collect();
    
            if columns.len() < 7 {
                continue;
            }
    
            if columns[0] == username {
                let id = columns[2].parse::<u32>().map_err(|_| ForensicError::BadFormat)?;
                let home = PathBuf::from(columns[5]);
                let shell = columns[6].to_string();
                let groups = SystemInfo::get_user_groups(vfs, &username)?;
                user_info = UserInfo {
                    name: username.clone(),
                    id,
                    home,
                    shell,
                    groups,
                };
            }
        }
        Ok(user_info)
    }
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
        let system_groups = SystemGroups::process_group_file(vfs)?;
        Ok(system_groups.get_groups_for_user(username)?)
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
            entry.into_mut().insert(key_pair.1.trim().to_string());
        }
        std::collections::hash_map::Entry::Vacant(_) => {
            captures_possible_values.insert(key_pair.1.trim().to_string());
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
fn should_create_user_info_struct() {
    let base_path = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let bashrc_path = std::path::Path::new(&base_path).join("artifacts");

    let mut _std_vfs = StdVirtualFS::new();
    let mut vfs = ChRootFileSystem::new(bashrc_path, Box::new(_std_vfs));
    //let groups_result = SystemInfo::get_user_groups(&mut vfs, "forensicrs");

    //let result = UserInfo::get_user_info("forensicrs".to_string(), &mut vfs).expect("Couldn't process bash");
    let result = UserArtifact::get_user_artifacts("forensicrs".to_string(), &mut vfs).expect("Couldn't process bash");

    println!("{:?}", result);
}

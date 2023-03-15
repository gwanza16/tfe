use chrono::NaiveDateTime;
use forensic_rs::traits::vfs::VirtualFileSystem;
use lazy_static::lazy_static;
use regex::Regex;
use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
};

use crate::prelude::*;
lazy_static! {
    pub static ref HISTORY_TIMESTAMP_REGEX: Regex = Regex::new(r#"^:\s*(\d+)"#).unwrap();
    pub static ref HISTORY_COMMAND_REGEX: Regex =
        Regex::new(r#"^:\s*\d+:(?:[^;]*;)(.*)$"#).unwrap();
}

#[derive(Debug, Default, Clone)]
pub struct ZshRcConfig {
    pub aliases: HashMap<String, BTreeSet<String>>,
    pub exports: HashMap<String, BTreeSet<String>>,
    pub variables: HashMap<String, BTreeSet<String>>,
}

#[derive(Debug, Default, Clone)]
pub struct ZshHistory {
    pub commands: Vec<(Option<NaiveDateTime>, String)>,
}

impl ZshHistory {
    //Creates a ZshHistory struct with commands assigned to the time of its execution
    pub fn read_history_timestamps<P>(
        &mut self,
        user_home_path: P,
        vfs: &mut impl VirtualFileSystem,
    ) where
        P: AsRef<std::path::Path>,
    {
        let path = PathBuf::from(user_home_path.as_ref());
        let history_contents = match vfs.read_to_string(path.join(".zsh_history").as_path()) {
            Ok(v) => v,
            Err(_e) => return,
        };

        for line in history_contents.lines() {
            let timestamp = HISTORY_TIMESTAMP_REGEX
                .captures(line)
                .and_then(|caps| caps.get(1))
                .and_then(|m| m.as_str().parse::<i64>().ok())
                .map(|ts| NaiveDateTime::from_timestamp_opt(ts, 0))
                .flatten();

            let command = HISTORY_COMMAND_REGEX
                .captures(line)
                .and_then(|caps| caps.get(1))
                .map(|match_obj| match_obj.as_str().to_string())
                .unwrap_or(String::new());

            self.commands.push((timestamp.clone(), command));
        }
    }
}

impl ZshRcConfig {
    pub fn generic_zsh_file_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/zshenv"),
            PathBuf::from("/etc/zprofile"),
            PathBuf::from("/etc/zshrc"),
            PathBuf::from("/etc/zlogin"),
            PathBuf::from("/etc/zlogout"),
            PathBuf::from("/etc/zsh/zlogin"),
            PathBuf::from("/etc/zsh/zlogin"),
            PathBuf::from("/etc/zsh/zprofile"),
            PathBuf::from("/etc/zsh/zshrc"),
            PathBuf::from("/etc/zsh/zshenv"),
        ]
    }
    pub fn get_user_zsh_files_path(user_home_path: &Path) -> Vec<PathBuf> {
        return vec![
            user_home_path.join(".zshenv"),
            user_home_path.join(".zprofile"),
            user_home_path.join(".zshrc"),
            user_home_path.join(".zlogin"),
            user_home_path.join(".zlogout"),
        ];
    }
    pub fn process_zshrcfile<P>(&mut self, user_home_path: P, vfs: &mut impl VirtualFileSystem)
    where
        P: AsRef<std::path::Path>,
    {
        let mut generic_bash_paths = Self::generic_zsh_file_paths();
        let mut user_bash_paths = Self::get_user_zsh_files_path(user_home_path.as_ref());
        generic_bash_paths.append(&mut user_bash_paths);

        for path in generic_bash_paths {
            let file_contents = match vfs.read_to_string(path.as_ref()) {
                Ok(v) => v,
                Err(_e) => continue,
            };
            for line in file_contents.lines() {
                if let Some(alias) = ALIAS_REGEX.captures(line) {
                    insert_new_values_to_struct(alias, &mut self.aliases);
                } else if let Some(export) = EXPORT_REGEX.captures(line) {
                    insert_new_values_to_struct(export, &mut self.exports);
                } else if let Some(variable) = VARIABLE_REGEX.captures(line) {
                    insert_new_values_to_struct(variable, &mut self.variables);
                }
            }
        }
    }
}

#[cfg(test)]
mod bash_tests {
    use std::{collections::BTreeSet, path::{PathBuf, Path}};

    use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
    use forensic_rs::core::fs::StdVirtualFS;

    use crate::{
        prelude::{
            zsh::{ZshHistory, ZshRcConfig},
            UserInfo,
        },
        ChRootFileSystem,
    };

    #[test]
    fn should_process_zsh_files() {
        let user_info = UserInfo {
            name: "forensicrs".to_string(),
            id: 1,
            home: PathBuf::from("/home/forensicrs"),
            shell: "/bin/zsh".to_string(),
            groups: Vec::new(),
        };

        let base_path = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let virtual_file_system = &Path::new(&base_path).join("artifacts");

        let mut _std_vfs = StdVirtualFS::new();
        let mut vfs = ChRootFileSystem::new(virtual_file_system, Box::new(_std_vfs));

        let mut rc_config = ZshRcConfig::default();

        ZshRcConfig::process_zshrcfile(&mut rc_config, user_info.home, &mut vfs);

        let widget_variable_value: BTreeSet<String> = BTreeSet::from([String::from(r#"$2"#)]);

        assert_eq!(
            &widget_variable_value,
            rc_config
                .variables
                .get("widget")
                .expect("Should exist widget variable")
        );

        let export_path_value: BTreeSet<String> =
            BTreeSet::from([String::from(r#"/usr/local/bin:/usr/bin:/bin:/usr/games"#)]);

        assert_eq!(
            &export_path_value,
            rc_config
                .exports
                .get("PATH")
                .expect("Should exist PATH export")
        );
    }

    #[test]
    fn should_read_history_timestamps() {
        let user_info = UserInfo {
            name: "gwanza".to_string(),
            id: 1,
            home: PathBuf::from("/home/gwanza"),
            shell: "/bin/zsh".to_string(),
            groups: Vec::new(),
        };
        let user_home = user_info.home;
        let mut rc_history = ZshHistory::default();
        let mut _std_vfs = StdVirtualFS::new();
        let mut vfs = ChRootFileSystem::new("/", Box::new(_std_vfs));
        ZshHistory::read_history_timestamps(&mut rc_history, user_home, &mut vfs);

        let mut test_command: Vec<(Option<NaiveDateTime>, String)> = Vec::with_capacity(1_000);

        let d = NaiveDate::from_ymd_opt(2023, 02, 17).unwrap();
        let t = NaiveTime::from_hms_milli_opt(11, 11, 25, 00).unwrap();
        test_command.push((Some(NaiveDateTime::new(d, t)), "ls".to_string()));

        assert_eq!(
            test_command.get(0).expect("Date time created"),
            rc_history.commands.get(0).expect("Date time to compare")
        );
    }
}

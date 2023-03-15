use chrono::NaiveDateTime;
use forensic_rs::traits::vfs::VirtualFileSystem;
use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
};

use crate::prelude::*;

#[derive(Debug, Default, Clone)]
pub struct BashRcConfig {
    pub aliases: HashMap<String, BTreeSet<String>>,
    pub exports: HashMap<String, BTreeSet<String>>,
    pub variables: HashMap<String, BTreeSet<String>>,
}

#[derive(Debug, Default, Clone)]
pub struct BashHistory {
    pub commands: Vec<(Option<NaiveDateTime>, String)>,
}

impl BashHistory {
    //Creates a BashHistory struct with commands assigned to the time of its execution
    pub fn read_history_timestamps<P>(
        &mut self,
        user_home_path: P,
        vfs: &mut impl VirtualFileSystem,
    ) where
        P: AsRef<std::path::Path>,
    {
        let path = PathBuf::from(user_home_path.as_ref());
        let history_contents = match vfs.read_to_string(path.join(".bash_history").as_path()) {
            Ok(v) => v,
            Err(_e) => return,
        };

        let mut last_timestamp: Option<NaiveDateTime> = None;

        for line in history_contents.lines() {
            if line.starts_with('#') {
                let timestamp = &line[1..];
                let timestamp = NaiveDateTime::from_timestamp_opt(
                    timestamp.parse::<i64>().unwrap_or_default(),
                    0,
                );
                last_timestamp = timestamp;
            } else {
                self.commands
                    .push((last_timestamp.clone(), line.to_string()));
            }
        }
    }
}

impl BashRcConfig {
    pub fn generic_bash_file_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/profile"),
            PathBuf::from("/etc/bash.bashrc"),
        ]
    }
    pub fn get_user_bash_files_path(user_home_path: &Path) -> Vec<PathBuf> {
        return vec![
            user_home_path.join(".bashrc"),
            user_home_path.join(".bash_profile"),
            user_home_path.join(".bash_login"),
            user_home_path.join(".profile"),
            user_home_path.join(".bash_logout"),
        ];
    }
    pub fn process_bashrcfile<P>(&mut self, user_home_path: P, vfs: &mut impl VirtualFileSystem)
    where
        P: AsRef<std::path::Path>,
    {
        let mut generic_bash_paths = Self::generic_bash_file_paths();
        let mut user_bash_paths = Self::get_user_bash_files_path(user_home_path.as_ref());
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
    use std::{
        collections::BTreeSet,
        path::{Path, PathBuf},
    };

    use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
    use forensic_rs::core::fs::StdVirtualFS;

    use crate::{prelude::UserInfo, BashRcConfig, ChRootFileSystem};

    use super::BashHistory;

    #[test]
    fn should_process_bash_files() {
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

        let mut rc_config = BashRcConfig::default();

        BashRcConfig::process_bashrcfile(&mut rc_config, user_info.home, &mut vfs);

        let alert_variable_value: BTreeSet<String> =
            BTreeSet::from([String::from(r#"${BWhite}${On_Red} "#)]);

        assert_eq!(
            &alert_variable_value,
            rc_config
                .variables
                .get("ALERT")
                .expect("Should exist ALERT variable")
        );

        let alias_rm_value: BTreeSet<String> = BTreeSet::from([String::from(r#"rm -i"#)]);

        assert_eq!(
            &alias_rm_value,
            rc_config.aliases.get("rm").expect("Should exist rm alias")
        );

        //println!("{:?}", rc_config);
        let export_histtimeformat_value: BTreeSet<String> = BTreeSet::from([
            String::from(r#"$(echo -e ${BCyan})[%d/%m %H:%M:%S]$(echo -e ${NC}) "#),
            String::from("%d/%m/%y %T "),
        ]);

        assert_eq!(
            &export_histtimeformat_value,
            rc_config
                .exports
                .get("HISTTIMEFORMAT")
                .expect("Should exist HISTTIMEFORMAT export")
        );
        println!("{:?}", rc_config);
    }

    #[test]
    fn should_read_history_timestamps() {
        let user_info = UserInfo {
            name: "gwanza".to_string(),
            id: 1,
            home: PathBuf::from("/home/gwanza"),
            shell: "/bin/bash".to_string(),
            groups: Vec::new(),
        };
        let user_home = user_info.home;
        let mut rc_history = BashHistory::default();
        let mut _std_vfs = StdVirtualFS::new();
        let mut vfs = ChRootFileSystem::new("/", Box::new(_std_vfs));
        BashHistory::read_history_timestamps(&mut rc_history, user_home, &mut vfs);

        let mut test_command: Vec<(Option<NaiveDateTime>, String)> = Vec::with_capacity(1_000);

        let d = NaiveDate::from_ymd_opt(2023, 01, 18).unwrap();
        let t = NaiveTime::from_hms_milli_opt(08, 17, 06, 00).unwrap();
        test_command.push((
            Some(NaiveDateTime::new(d, t)),
            "vim ~/.bash_history ".to_string(),
        ));

        assert_eq!(
            test_command.get(0).expect("Date time created"),
            rc_history.commands.get(0).expect("Date time to compare")
        );
    }
}

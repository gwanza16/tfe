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
        let path = Path::new(user_home_path.as_ref());
        let history_path = path.join(".zsh_history");
        //converts the content of the .zsh_history path to string
        let history_contents = match vfs.read_to_string(history_path.as_path()) {
            Ok(v) => v,
            Err(_e) => return,
        };

        let mut last_timestamp: Option<NaiveDateTime> = None;

        //reads each line of the .zsh_history
        for line in history_contents.lines() {
            //the timestamps start with #
            if line.starts_with('#') {
                let timestamp = &line[1..];
                let timestamp = NaiveDateTime::from_timestamp_opt(
                    timestamp.parse::<i64>().unwrap_or_default(),
                    0,
                );
                last_timestamp = timestamp;
            } else {
                self.commands
                    .push((last_timestamp.clone(), line.trim().to_string()));
            }
        }
    }

    //Creates a ZshHistory struct processing the .zsh_history file
    pub fn load_zsh_history(
        user_info: UserInfo,
        fs: &mut impl VirtualFileSystem,
    ) -> ForensicResult<Self> {
        let mut zsh_history = Self::default();

        let user_home = user_info.home.as_path().join(".zsh_history");

        zsh_history.read_history_timestamps(user_home, fs);

        Ok(zsh_history)
    }
    
}

impl ZshRcConfig {

    //returns the generic zsh config files
    pub fn generic_zsh_file_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/zshenv"),
            PathBuf::from("/etc/zprofile"),
            PathBuf::from("/etc/zshrc"),
            PathBuf::from("/etc/zlogin"),
            PathBuf::from("/etc/zlogout"),
            PathBuf::from("/etc/zsh/zlogin"),
            PathBuf::from("/etc/zsh/zlogout"),
            PathBuf::from("/etc/zsh/zprofile"),
            PathBuf::from("/etc/zsh/zshrc"),
            PathBuf::from("/etc/zsh/zshenv"),
        ]
    }

    //returns the user zsh config files
    pub fn get_user_zsh_files_path(user_home_path: &Path) -> Vec<PathBuf> {
        return vec![
            user_home_path.join(".zshenv"),
            user_home_path.join(".zprofile"),
            user_home_path.join(".zshrc"),
            user_home_path.join(".zlogin"),
            user_home_path.join(".zlogout"),
        ];
    }

    //Creates a ZshRcConfig struct processing all the zsh configuration files
    pub fn load_zsh_config(
        user_info: UserInfo,
        fs: &mut impl VirtualFileSystem,
    ) -> ForensicResult<Self> {
        let mut rc_config = Self::default();
        rc_config.process_zshrcfile(user_info.home.as_path(), fs);

        Ok(rc_config)
    }

    //Reads all the zsh configuration files and adds the new values to the struct
    pub fn process_zshrcfile<P>(&mut self, user_home_path: P, vfs: &mut impl VirtualFileSystem)
    where
        P: AsRef<std::path::Path>,
    {
        let mut generic_zsh_paths = Self::generic_zsh_file_paths();
        let mut user_zsh_paths = Self::get_user_zsh_files_path(user_home_path.as_ref());
        generic_zsh_paths.append(&mut user_zsh_paths);

        for path in generic_zsh_paths {
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
mod zsh_tests {
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

        let mut zsh_config = ZshRcConfig::default();

        ZshRcConfig::process_zshrcfile(&mut zsh_config, user_info.home, &mut vfs);

        let alias_ll_value: BTreeSet<String> = BTreeSet::from([String::from(r#"ls -la"#)]);

        assert_eq!(
            &alias_ll_value,
            zsh_config.aliases.get("ll").expect("Should exist ll alias")
        );

        let widget_variable_value: BTreeSet<String> = BTreeSet::from([String::from(r#"$2"#)]);

        assert_eq!(
            &widget_variable_value,
            zsh_config
                .variables
                .get("widget")
                .expect("Should exist widget variable")
        );

        let export_path_value: BTreeSet<String> =
            BTreeSet::from([
                String::from(r#"$HOME/.nodebrew/current/bin:$PATH"#),
                String::from(r#"$PATH:$HOME/.rvm/bin"#),
                String::from(r#"${PATH}:${ANDROID_SDK_ROOT}/tools:${ANDROID_SDK_ROOT}/platform-tools"#),
                String::from(r#"${PATH}:${HOME}/bin"#),
                String::from(r#"${PATH}:${JAVA_HOME}/bin"#),
                String::from(r#"/usr/local/bin:${PATH}"#),
                String::from(r#"/usr/local/bin:/usr/local/apache-maven-2.2.1/bin:/usr/local/maven-1.1/bin:/Developer/android/android-sdk-mac_x86/tools:/usr/local/mysql/bin:/usr/local/sbin:~/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/X11/bin:/Users/mark/.rvm/bin"#),
            ]);

        assert_eq!(
            &export_path_value,
            zsh_config
                .exports
                .get("PATH")
                .expect("Should exist PATH export")
        );

    }

    #[test]
    fn should_read_zsh_history_timestamps() {
        let user_info = UserInfo {
            name: "forensicrs".to_string(),
            id: 1,
            home: PathBuf::from("/home/forensicrs"),
            shell: "/bin/zsh".to_string(),
            groups: Vec::new(),
        };
        let user_home = user_info.home;
        let mut zsh_history = ZshHistory::default();
        let base_path = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let virtual_file_system = &Path::new(&base_path).join("artifacts");

        let mut _std_vfs = StdVirtualFS::new();
        let mut vfs = ChRootFileSystem::new(virtual_file_system, Box::new(_std_vfs));
        ZshHistory::read_history_timestamps(&mut zsh_history, user_home, &mut vfs);

        let mut test_command: Vec<(Option<NaiveDateTime>, String)> = Vec::with_capacity(1_000);

        let d = NaiveDate::from_ymd_opt(2023, 01, 19).unwrap();
        let t = NaiveTime::from_hms_milli_opt(06, 37, 06, 00).unwrap();
        test_command.push((
            Some(NaiveDateTime::new(d, t)),
            "vim ~/.zsh_history".to_string(),
        ));

        assert_eq!(
            test_command.get(0).expect("Date time created"),
            zsh_history.commands.get(0).expect("Date time to compare")
        );
    }
}

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
pub struct CrontabSchedule {
    pub minute: String,
    pub hour: String,
    pub day_of_month: String,
    pub month: String,
    pub day_of_week: String,
}

#[derive(Debug, Default, Clone)]
pub struct CrontabTask {
    pub username: String,
    pub command: String,
    pub schedule: CrontabSchedule,
}

lazy_static! {
    pub static ref START_WITH_NUMBER: Regex = Regex::new(r#"^\d"#).unwrap();
    pub static ref SYSTEM_CRONTAB_COMMAND: Regex =
        Regex::new(r#"^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s(.*)$"#).unwrap();
    pub static ref USER_CRONTAB_COMMAND: Regex =
        Regex::new(r#"^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s(.*)$"#).unwrap();
}

impl CrontabSchedule {
    pub fn process_crontab_files(
        &mut self,
        vfs: &mut impl VirtualFileSystem,
        username: String,
    ) -> ForensicResult<Vec<CrontabTask>> {
        let crontab_paths = Self::get_crontab_files(username);
        let mut crontab_tasks: Vec<CrontabTask> = Vec::new();

        for path in crontab_paths {
            let reader_crontab = match vfs.read_to_string(path.as_ref()) {
                Ok(v) => v,
                Err(_e) => continue,
            };

            for crontab_line in reader_crontab.lines() {
                let crontab_columns: Vec<&str> = crontab_line.split_whitespace().collect();

                if crontab_line.starts_with("*") || !START_WITH_NUMBER.is_match(&crontab_line) {
                    continue;
                }

                let crontab_schedule = CrontabSchedule {
                    minute: crontab_columns[0].to_string(),
                    hour: crontab_columns[1].to_string(),
                    day_of_month: crontab_columns[2].to_string(),
                    month: crontab_columns[3].to_string(),
                    day_of_week: crontab_columns[4].to_string(),
                };

                if path.starts_with("/var/spool") {
                    let crontab_command = match USER_CRONTAB_COMMAND.captures(&crontab_line) {
                        Some(captures) => captures.get(1).unwrap().as_str(),
                        None => "no command",
                    };

                    let crontab_task = CrontabTask {
                        username: "root".to_string(),
                        command: crontab_command.trim().to_string(),
                        schedule: crontab_schedule,
                    };

                    crontab_tasks.push(crontab_task);
                    continue;
                }

                let crontab_command = match SYSTEM_CRONTAB_COMMAND.captures(&crontab_line) {
                    Some(captures) => captures.get(1).unwrap().as_str(),
                    None => "no command",
                };

                let crontab_task = CrontabTask {
                    username: crontab_columns[5].to_string(),
                    command: crontab_command.trim().to_string(),
                    schedule: crontab_schedule,
                };

                crontab_tasks.push(crontab_task);
            }
        }

        Ok(crontab_tasks)
    }

    pub fn get_crontab_files(username: String) -> Vec<PathBuf> {
        let mut file_paths: Vec<PathBuf> = Vec::new();

        if let Ok(entries) = fs::read_dir(PathBuf::from("/etc/cron.d")) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if path.is_file() {
                        file_paths.push(path);
                    }
                }
            }
        }

        let cron_paths = vec![
            PathBuf::from("/etc/crontab"),
            PathBuf::from("/var/spool/cron/crontabs").join(username),
        ];

        file_paths.extend(cron_paths);
        file_paths
    }
}

#[test]
fn should_process_crontab_file() {
    let base_path = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let virtual_file_system = &Path::new(&base_path).join("artifacts");

    let mut _std_vfs = StdVirtualFS::new();
    let mut vfs = ChRootFileSystem::new(virtual_file_system, Box::new(_std_vfs));

    let mut crontab_schedule = CrontabSchedule::default();
    let system_groups = CrontabSchedule::process_crontab_files(
        &mut crontab_schedule,
        &mut vfs,
        "forensicrs".to_string(),
    );

    print!("{:?}", system_groups);
}

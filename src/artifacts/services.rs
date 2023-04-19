pub use crate::prelude::{known_hosts, UserInfo};
pub use crate::ChRootFileSystem;
use configparser::ini::Ini;
pub use forensic_rs::traits::vfs;
pub use forensic_rs::{
    core::fs::StdVirtualFS, prelude::ForensicResult, traits::vfs::VirtualFileSystem,
};

use std::collections::HashMap;

pub use std::{
    fs,
    io::BufRead,
    path::{Path, PathBuf},
};

#[derive(Debug, Default, Clone, PartialEq)]
pub struct InitdService {
    pub service_name: String,
    pub service_script: String,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct SystemdService {
    pub service_name: String,
    pub config: HashMap<String, HashMap<String, Option<String>>>,
}

impl InitdService {
    pub fn process_init_services_files(
        vfs: &mut impl VirtualFileSystem,
    ) -> ForensicResult<Vec<InitdService>> {
        let initd_path = PathBuf::from("/etc/init.d");
        let mut new_services: Vec<InitdService> = Vec::new();

        if let Ok(services) = vfs.read_dir(&initd_path) {
            for service in services {
                let file_name = match service {
                    forensic_rs::traits::vfs::VDirEntry::File(file_name) => file_name,
                    _ => continue,
                };
                let service_script = match vfs.read_to_string(&initd_path.join(&file_name)) {
                    Ok(script) => script,
                    Err(_) => "".to_string(),
                };

                let new_service = InitdService {
                    service_name: file_name,
                    service_script: service_script,
                };

                new_services.push(new_service);
            }
        }
        Ok(new_services)
    }
}

impl SystemdService {
    pub fn process_services_files(
        vfs: &mut impl VirtualFileSystem,
    ) -> ForensicResult<Vec<SystemdService>> {
        let mut config = Ini::new();
        let services_paths = Self::get_services_paths();
        let mut services_vec: Vec<SystemdService> = Vec::new();

        for path in services_paths {
            if let Ok(services) = vfs.read_dir(&path) {
                for service in services {
                    if let forensic_rs::traits::vfs::VDirEntry::File(mut file_name) = service {
                        services_vec.push(Self::insert_new_services(
                            vfs,
                            &path,
                            &mut file_name,
                            &mut config,
                        )?);
                    } else if let forensic_rs::traits::vfs::VDirEntry::Directory(dir_name) = service
                    {
                        //si se trata de un directorio se procesa los ficheros que tenga de servicios
                        if let Ok(files) = vfs.read_dir(&path.join(dir_name)) {
                            for file in files {
                                if let forensic_rs::traits::vfs::VDirEntry::File(
                                    mut dir_service_name,
                                ) = file
                                {
                                    services_vec.push(Self::insert_new_services(
                                        vfs,
                                        &path,
                                        &mut dir_service_name,
                                        &mut config,
                                    )?);
                                }
                            }
                        }
                    } else {
                        continue;
                    }
                }
            }
        }

        Ok(services_vec)
    }

    pub fn insert_new_services(
        vfs: &mut impl VirtualFileSystem,
        path: &Path,
        file_name: &mut String,
        config: &mut Ini,
    ) -> ForensicResult<SystemdService> {
        let mut new_service: SystemdService = Self::default();

        if Self::check_if_service_file(&file_name) {
            let service_script = match vfs.read_to_string(&path.join(&file_name)) {
                Ok(script) => script,
                Err(_) => "".to_string(),
            };

            let file = config.read(service_script);

            new_service = SystemdService {
                service_name: file_name.to_string(),
                config: match file {
                    Ok(config) => config,
                    Err(e) => return Err(forensic_rs::prelude::ForensicError::Other(e)),
                },
            };
        }

        Ok(new_service)
    }

    pub fn get_services_paths() -> Vec<PathBuf> {
        return vec![
            PathBuf::from("/usr/lib/systemd/system"),
            PathBuf::from("/usr/lib/systemd/user"),
            PathBuf::from("/lib/systemd/system"),
            PathBuf::from("/etc/systemd/system"),
        ];
    }

    pub fn check_if_service_file(file: &String) -> bool {
        let file_path = Path::new(&file);

        if file_path.extension().unwrap_or_default() == "service" {
            true
        } else {
            false
        }
    }
}

mod services_tests {
    pub use std::{collections::HashMap, path::Path};

    pub use forensic_rs::core::fs::StdVirtualFS;

    pub use crate::ChRootFileSystem;

    pub use super::{InitdService, SystemdService};

    #[test]
    fn should_process_initd_services() {
        let base_path = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let virtual_file_system = &Path::new(&base_path).join("artifacts");
        let mut _std_vfs = StdVirtualFS::new();
        let mut vfs = ChRootFileSystem::new(virtual_file_system, Box::new(_std_vfs));

        let initd_services = InitdService::process_init_services_files(&mut vfs);

        match initd_services {
            Ok(initd_service) => {
                let initd_service_test = InitdService {
                    service_name: "apache2".to_string(),
                    service_script: "hola".to_string(),
                };
                assert_eq!(initd_service_test, initd_service[0]);
            }
            Err(e) => {
                panic!("Error getting authorized keys: {:?}", e);
            }
        }
    }

    #[test]
    fn should_process_systemd_services() {
        let base_path = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let virtual_file_system = &Path::new(&base_path).join("artifacts");
        let mut _std_vfs = StdVirtualFS::new();
        let mut vfs = ChRootFileSystem::new(virtual_file_system, Box::new(_std_vfs));

        let systemd_services = SystemdService::process_services_files(&mut vfs);

        match systemd_services {
            Ok(systemd_service) => {
                let systemd_service_test = SystemdService {
                    service_name: "tortuga.service".to_string(),
                    config: HashMap::new(),
                };
                assert_eq!(systemd_service_test, systemd_service[2]);
            }
            Err(e) => {
                panic!("Error getting authorized keys: {:?}", e);
            }
        }
    }
}

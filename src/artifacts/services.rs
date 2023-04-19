pub use crate::prelude::{known_hosts, UserInfo};
pub use crate::ChRootFileSystem;
use configparser::ini::{Ini};
pub use forensic_rs::traits::vfs;
pub use forensic_rs::{
    core::fs::StdVirtualFS, prelude::ForensicResult, traits::vfs::VirtualFileSystem,
};

use std::collections::{HashMap};

pub use std::{
    fs,
    io::BufRead,
    path::{Path, PathBuf},
};

#[derive(Debug, Default, Clone)]
pub struct InitdService {
    pub service_name: String,
    pub service_script: String,
}

#[derive(Debug, Default, Clone)]
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
    pub fn process_services_files(vfs: &mut impl VirtualFileSystem) -> Vec<SystemdService> {
        let mut config = Ini::new();
        let services_paths = Self::get_services_paths();
        let mut services_vec: Vec<SystemdService> = Vec::new();

        for path in services_paths {
            if let Ok(services) = vfs.read_dir(&path) {
                for service in services {
                    if let forensic_rs::traits::vfs::VDirEntry::File(file_name) = service {
                        if Self::check_if_service_file(&file_name) {
                            let service_script = match vfs.read_to_string(&path.join(&file_name)) {
                                Ok(script) => script,
                                Err(_) => "".to_string(),
                            };

                            let file = config.read(service_script);

                            let new_service = SystemdService {
                                service_name: file_name,
                                config: match file {
                                    Ok(config) => config,
                                    _ => continue,
                                },
                            };

                            services_vec.push(new_service);

                        }
                    } else if let forensic_rs::traits::vfs::VDirEntry::Directory(dir_name) = service
                    {
                        //si se trata de un directorio se procesa los ficheros que tenga de servicios
                        if let Ok(files) = vfs.read_dir(&path.join(dir_name)) {
                            for file in files {
                                if let forensic_rs::traits::vfs::VDirEntry::File(dir_service_name) =
                                    file
                                {
                                    if Self::check_if_service_file(&dir_service_name) {
                                        let service_script = match vfs.read_to_string(&path.join(&dir_service_name)) {
                                            Ok(script) => script,
                                            Err(_) => "".to_string(),
                                        };
            
                                        let file = config.read(service_script);

                                        let new_service = SystemdService {
                                            service_name: dir_service_name,
                                            config: match file {
                                                Ok(config) => config,
                                                _ => continue,
                                            },
                                        };
            
                                        services_vec.push(new_service);
            
                                    }
                                }
                            }
                        }
                    } else {
                        continue;
                    }
                }
            }
        }

        services_vec
    }

    pub fn get_services_paths() -> Vec<PathBuf> {
        return vec![
            PathBuf::from("/usr/lib/systemd/system"),
            PathBuf::from("/usr/lib/sysstemd/user"),
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

#[test]
fn should_process_group_file() {
    let base_path = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let virtual_file_system = &Path::new(&base_path).join("artifacts");
    let mut _std_vfs = StdVirtualFS::new();
    let mut vfs = ChRootFileSystem::new(virtual_file_system, Box::new(_std_vfs));

    let initd_services = SystemdService::process_services_files(&mut vfs);

    println!("{:?}", initd_services);
}

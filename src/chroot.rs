use std::path::{PathBuf, Path};

use forensic_rs::{traits::vfs::VirtualFileSystem, prelude::ForensicResult};

pub struct ChRootFileSystem {
    path : PathBuf,
    fs : Box<dyn VirtualFileSystem>
}
impl ChRootFileSystem {
    pub fn new<P>(path : P, fs : Box<dyn VirtualFileSystem>) -> Self 
    where
        P : Into<std::path::PathBuf>
    {
        Self {
            path : path.into(),
            fs
        }
    }
}
fn strip_prefix(path : &Path) -> PathBuf {
    if path.starts_with("/") {
        match path.strip_prefix("/") {
            Ok(v) => v.to_path_buf(),
            Err(_) => path.to_path_buf()
        }
    }else{
        path.to_path_buf()
    }
}
impl VirtualFileSystem for ChRootFileSystem {
    fn read_to_string(&mut self, path: &Path) -> ForensicResult<String> {
        self.fs.read_to_string(self.path.join(strip_prefix(path)).as_path())
    }

    fn is_live(&self) -> bool {
        false
    }

    fn read_all(&mut self, path: &Path) -> ForensicResult<Vec<u8>> {
        self.fs.read_all(self.path.join(strip_prefix(path)).as_path())
    }

    fn read(& mut self, path: &Path, pos: u64, buf: & mut [u8]) -> ForensicResult<usize> {
        self.fs.read(self.path.join(strip_prefix(path)).as_path(), pos, buf)
    }

    fn metadata(&mut self, path: &Path) -> ForensicResult<forensic_rs::traits::vfs::VMetadata> {
        self.fs.metadata(self.path.join(strip_prefix(path)).as_path())
    }

    fn read_dir(&mut self, path: &Path) -> ForensicResult<Vec<forensic_rs::traits::vfs::VDirEntry>> {
        self.fs.read_dir(self.path.join(strip_prefix(path)).as_path())
    }
}

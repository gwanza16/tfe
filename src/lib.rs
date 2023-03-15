pub mod chroot;
pub mod artifacts;
pub mod shared;

//use crate::chroot::ChRootFileSystem;

pub use crate::{artifacts::bash::BashRcConfig, chroot::ChRootFileSystem};

pub mod prelude {
    pub use crate::artifacts::*;
    pub use crate::shared::*;
}
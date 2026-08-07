//! Isopod — compliance nervous system
//! Evidence over assertions. Continuous compliance as engineering property.

pub mod api;
pub mod config;
pub mod control;
pub mod daemon;
pub mod drift;
pub mod evidence;
pub mod observer;
pub mod remediation;
pub mod store;
pub mod style;

pub use config::Config;
pub use control::{Control, ControlResult, ControlSet, ControlStatus};
pub use evidence::{ArtifactType, Evidence, EvidenceStore};
pub use store::Store;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

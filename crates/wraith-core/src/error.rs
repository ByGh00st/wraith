//! Wraith Unified Error System
//! Industrial-grade hierarchical error types for zero-unhandled-panic execution.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, WraithError>;

#[derive(Error, Debug)]
pub enum WraithError {
    #[error("I/O Error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization Error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Privilege Violation: Root privileges required for kernel network manipulation")]
    PermissionDenied,

    #[error("Unsupported Operating System: Linux Kernel (Debian/Kali) is strictly required")]
    UnsupportedPlatform,

    #[error("Firewall Engine Failure: {0}")]
    Firewall(String),

    #[error("Tor Controller Failure: {0}")]
    Tor(String),

    #[error("Kernel Namespace Error: {0}")]
    Namespace(String),

    #[error("Hardware MAC/Link Error: {0}")]
    Hardware(String),

    #[error("Anti-Forensic Purge Error: {0}")]
    Forensic(String),

    #[error("Watchdog / KillSwitch Failure: {0}")]
    Guard(String),

    #[error("Network Command Error: {0}")]
    Command(String),

    #[error("General Failure: {0}")]
    Custom(String),
}

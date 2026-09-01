//! Wraith Unified Error System
//! Industrial-grade hierarchical error types for zero-unhandled-panic execution.

use rust_i18n::t;

pub type Result<T> = std::result::Result<T, WraithError>;

#[derive(Debug)]
pub enum WraithError {
    Io(std::io::Error),
    Json(serde_json::Error),
    PermissionDenied,
    UnsupportedPlatform,
    Firewall(String),
    Tor(String),
    Namespace(String),
    Hardware(String),
    Forensic(String),
    Guard(String),
    Command(String),
    Custom(String),
}

impl std::error::Error for WraithError {}

impl std::fmt::Display for WraithError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WraithError::Io(e) => write!(f, "{} {}", t!("err.io"), e),
            WraithError::Json(e) => write!(f, "{} {}", t!("err.json"), e),
            WraithError::PermissionDenied => write!(f, "{}", t!("err.permission_denied")),
            WraithError::UnsupportedPlatform => write!(f, "{}", t!("err.unsupported_platform")),
            WraithError::Firewall(msg) => write!(f, "{} {}", t!("err.firewall"), msg),
            WraithError::Tor(msg) => write!(f, "{} {}", t!("err.tor"), msg),
            WraithError::Namespace(msg) => write!(f, "{} {}", t!("err.namespace"), msg),
            WraithError::Hardware(msg) => write!(f, "{} {}", t!("err.hardware"), msg),
            WraithError::Forensic(msg) => write!(f, "{} {}", t!("err.forensic"), msg),
            WraithError::Guard(msg) => write!(f, "{} {}", t!("err.guard"), msg),
            WraithError::Command(msg) => write!(f, "{} {}", t!("err.command"), msg),
            WraithError::Custom(msg) => write!(f, "{} {}", t!("err.custom"), msg),
        }
    }
}

impl From<std::io::Error> for WraithError {
    fn from(e: std::io::Error) -> Self {
        WraithError::Io(e)
    }
}

impl From<serde_json::Error> for WraithError {
    fn from(e: serde_json::Error) -> Self {
        WraithError::Json(e)
    }
}

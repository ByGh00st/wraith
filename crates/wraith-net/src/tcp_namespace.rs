//! Pin the managed namespace for a transaction without moving the caller thread.

use crate::tcp_stack::TcpMorphError;
use serde::{Deserialize, Serialize};
use std::process::Output;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceIdentity {
    pub device: u64,
    pub inode: u64,
}

pub(crate) fn validate_name(name: &str) -> Result<(), TcpMorphError> {
    if name.is_empty() || name == "host" || name == "/" {
        return Err(TcpMorphError::HostMutationForbidden);
    }
    if name != crate::namespace::NAMESPACE_NAME {
        return Err(TcpMorphError::UnmanagedNamespace(name.into()));
    }
    Ok(())
}

pub(crate) struct Namespace {
    #[cfg(target_os = "linux")]
    file: std::fs::File,
    pub name: String,
    pub identity: NamespaceIdentity,
}

impl Namespace {
    pub fn open(name: &str) -> Result<Self, TcpMorphError> {
        validate_name(name)?;
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            let file = std::fs::File::open(format!("/run/netns/{name}"))
                .map_err(|error| match error.kind() {
                    std::io::ErrorKind::NotFound => TcpMorphError::NamespaceNotFound(name.into()),
                    _ => TcpMorphError::Io(error),
                })?;
            let metadata = file.metadata()?;
            let identity = NamespaceIdentity { device: metadata.dev(), inode: metadata.ino() };
            // A familiar name may be a bind mount of the host namespace.
            for path in ["/proc/1/ns/net", "/proc/self/ns/net"] {
                let host = std::fs::metadata(path)?;
                reject_host_identity(identity, NamespaceIdentity { device: host.dev(), inode: host.ino() })?;
            }
            Ok(Self { file, name: name.into(), identity })
        }
        #[cfg(not(target_os = "linux"))]
        { Err(TcpMorphError::UnsupportedPlatform) }
    }

    pub fn run(&self, program: &str, args: &[&str]) -> Result<Output, TcpMorphError> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            // Address the parent's live FD. Rust descriptors are close-on-exec;
            // /proc/self/fd in the child would therefore refer to the wrong table.
            let handle = format!("--net=/proc/{}/fd/{}", std::process::id(), self.file.as_raw_fd());
            Ok(std::process::Command::new("nsenter")
                .args([handle.as_str(), "--", program]).args(args)
                .env("LC_ALL", "C").output()?)
        }
        #[cfg(not(target_os = "linux"))]
        { let _ = (program, args); Err(TcpMorphError::UnsupportedPlatform) }
    }
}

#[cfg(any(target_os = "linux", test))]
fn reject_host_identity(target: NamespaceIdentity, host: NamespaceIdentity) -> Result<(), TcpMorphError> {
    if target == host { Err(TcpMorphError::HostMutationForbidden) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_managed_namespace_name_is_accepted() {
        for name in ["", "host", "/", "../1/ns/net", "/proc/1/ns/net", "--all", "other", " wraith_ns"] {
            assert!(validate_name(name).is_err(), "{name}");
        }
        assert!(validate_name(crate::namespace::NAMESPACE_NAME).is_ok());
    }

    #[test]
    fn host_aliases_are_rejected_by_identity() {
        let host = NamespaceIdentity { device: 4, inode: 42 };
        assert!(matches!(reject_host_identity(host, host), Err(TcpMorphError::HostMutationForbidden)));
        assert!(reject_host_identity(NamespaceIdentity { inode: 43, ..host }, host).is_ok());
    }
}

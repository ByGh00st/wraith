//! Ownership-checked orphan recovery. Never flush a host table or delete links
//! based on a name prefix alone. Call under the CLI lifecycle lock, after Tor stops.
use crate::namespace::{NAMESPACE_NAME, NS_SUBNET, VETH_HOST, VETH_NS};
use crate::tcp_namespace::{Namespace, NamespaceIdentity};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    process::Command,
};
use wraith_core::error::{Result, WraithError};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const NS_DIRECTORY: &str = "/etc/netns/wraith_ns";
const NS_LEASE: &str = "/var/lib/wraith/netns-owner.json";
const EGRESS_LEASE: &str = "/var/lib/wraith/egress-owner.json";

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct NamespaceLease {
    version: u8,
    boot_id: String,
    identity: NamespaceIdentity,
    pub(crate) tag: String,
    pub(crate) mac: String,
}

fn failure(message: impl Into<String>) -> WraithError {
    WraithError::Namespace(message.into())
}

fn private_metadata(metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(failure("Invalid recovery lease type/size"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
            return Err(failure("Unsafe recovery lease owner/mode"));
        }
    }
    Ok(())
}

fn read_lease<T: serde::de::DeserializeOwned>(path: &str) -> Result<Option<T>> {
    let parent = Path::new(path)
        .parent()
        .ok_or_else(|| failure("Missing lease parent"))?;
    match fs::symlink_metadata(parent) {
        Ok(metadata) if !metadata.is_dir() => {
            return Err(failure("Recovery directory must not be a symlink"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        _ => {}
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    private_metadata(&file.metadata()?)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(failure("Oversized recovery lease"));
    }
    Ok(Some(serde_json::from_slice(&bytes)?))
}

fn write_new_lease(path: &str, value: &impl Serialize) -> Result<()> {
    let parent = Path::new(path)
        .parent()
        .ok_or_else(|| failure("Missing lease directory"))?;
    fs::create_dir_all(parent)?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir() {
        return Err(failure("Recovery directory must not be a symlink"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != 0 {
            return Err(failure("Unsafe recovery directory owner/mode"));
        }
        // Older Wraith packages created this root-owned directory with group
        // write access. It is safe to narrow permissions after verifying that
        // root owns the real directory; never repair a foreign-owned path.
        if metadata.mode() & 0o022 != 0 {
            let mode = tighten_directory_mode(metadata.mode());
            fs::set_permissions(parent, fs::Permissions::from_mode(mode))?;
            let verified = fs::symlink_metadata(parent)?;
            if !verified.is_dir() || verified.uid() != 0 || verified.mode() & 0o022 != 0 {
                return Err(failure("Unsafe recovery directory owner/mode"));
            }
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *bytes, value)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path).map_err(|e| e.error)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn tighten_directory_mode(mode: u32) -> u32 {
    mode & !0o022
}

pub(crate) fn begin_namespace(identity: NamespaceIdentity, mac: String) -> Result<NamespaceLease> {
    use rand::RngCore;
    let mut random = [0u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut random)
        .map_err(|e| failure(format!("Ownership entropy unavailable: {e}")))?;
    let lease = NamespaceLease {
        version: 1,
        boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .into(),
        identity,
        tag: format!(
            "wraith-netns-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ),
        mac,
    };
    fs::create_dir_all("/etc/netns")?;
    fs::create_dir(NS_DIRECTORY)?;
    if let Err(error) = write_new_lease(NS_LEASE, &lease) {
        // Only the empty directory acquired above; never recursively remove it.
        let _ = fs::remove_dir(NS_DIRECTORY);
        return Err(error);
    }
    Ok(lease)
}

#[cfg(target_os = "linux")]
pub(crate) fn record_egress(snapshot: &crate::tcp_egress::TcpEgressSnapshot) -> Result<()> {
    write_new_lease(EGRESS_LEASE, snapshot)
}
pub(crate) fn forget_egress(snapshot: &crate::tcp_egress::TcpEgressSnapshot) -> Result<()> {
    if let Some(saved) = read_lease::<crate::tcp_egress::TcpEgressSnapshot>(EGRESS_LEASE)? {
        if saved != *snapshot {
            return Err(failure("Egress lease changed; refusing removal"));
        }
        fs::remove_file(EGRESS_LEASE)?;
    }
    Ok(())
}

pub fn has_orphan_leases() -> Result<bool> {
    Ok(read_lease::<NamespaceLease>(NS_LEASE)?.is_some()
        || read_lease::<crate::tcp_egress::TcpEgressSnapshot>(EGRESS_LEASE)?.is_some())
}

fn run(args: &[&str]) -> Result<String> {
    let output = Command::new("ip").args(args).env("LC_ALL", "C").output()?;
    if !output.status.success() {
        return Err(failure(format!(
            "Orphan inspection/cleanup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[derive(Debug, Deserialize)]
struct Link {
    ifname: String,
    #[serde(default)]
    ifalias: String,
    #[serde(default)]
    linkinfo: LinkInfo,
}
#[derive(Debug, Default, Deserialize)]
struct LinkInfo {
    #[serde(default)]
    info_kind: String,
}

fn candidate(name: &str) -> bool {
    [VETH_HOST, VETH_NS].contains(&name) || name.starts_with("veth_wraith")
}
fn owned_links(links: &[Link], tag: &str) -> Result<Vec<String>> {
    let mut owned = Vec::new();
    for link in links {
        if candidate(&link.ifname) || link.ifalias == tag {
            if link.ifalias != tag || link.linkinfo.info_kind != "veth" {
                return Err(failure(format!(
                    "Ambiguous link {}; ownership must be resolved before start",
                    link.ifname
                )));
            }
            owned.push(link.ifname.clone());
        }
    }
    Ok(owned)
}

fn validate_lease(lease: &NamespaceLease) -> Result<()> {
    let token = lease.tag.strip_prefix("wraith-netns-").unwrap_or("");
    if lease.version != 1 || token.len() != 32 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(failure("Invalid namespace ownership lease"));
    }
    Ok(())
}

/// Verify all evidence before mutation. Removing the owned namespace destroys
/// its TCPMSS/sysctl/FIB settings without writing global host TCP/routing state.
pub(crate) fn cleanup_owned_namespace() -> Result<bool> {
    let Some(lease) = read_lease::<NamespaceLease>(NS_LEASE)? else {
        return Ok(false);
    };
    validate_lease(&lease)?;
    let links: Vec<Link> = serde_json::from_str(&run(&["-j", "-d", "link", "show"])?)?;
    let owned = owned_links(&links, &lease.tag)?;
    let namespaces = run(&["netns", "list"])?;
    let exists = namespaces
        .lines()
        .any(|line| line.split_whitespace().next() == Some(NAMESPACE_NAME));
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    if boot.trim() != lease.boot_id && (exists || !owned.is_empty()) {
        return Err(failure(
            "Old-boot lease cannot authorize deletion of current network objects",
        ));
    }
    if exists {
        let namespace = Namespace::open(NAMESPACE_NAME)?;
        if namespace.identity != lease.identity {
            return Err(failure(
                "Namespace lifetime changed; refusing orphan cleanup",
            ));
        }
        if !run(&["netns", "pids", NAMESPACE_NAME])?.trim().is_empty() {
            return Err(failure(
                "Namespace still contains processes; close its applications before recovery",
            ));
        }
        let inside: Vec<Link> =
            serde_json::from_str(&run(&["-n", NAMESPACE_NAME, "-j", "-d", "link", "show"])?)?;
        if inside.iter().any(|link| {
            link.ifname != "lo" && (link.ifalias != lease.tag || link.linkinfo.info_kind != "veth")
        }) {
            return Err(failure(
                "Namespace contains an unowned interface; refusing teardown",
            ));
        }
    }
    // Persistent resolver data is checked too; never follow a replacement link.
    match fs::symlink_metadata(NS_DIRECTORY) {
        Ok(metadata) if !metadata.is_dir() => {
            return Err(failure("Namespace directory is not a real directory"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
        _ => {}
    }
    let entries = match fs::read_dir(NS_DIRECTORY) {
        Ok(entries) => Some(entries),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    for entry in entries.into_iter().flatten() {
        let entry = entry?;
        if entry.file_name() != "resolv.conf" || !entry.file_type()?.is_file() {
            return Err(failure("Unexpected namespace configuration entry"));
        }
        if entry.file_name() == "resolv.conf"
            && fs::read_to_string(entry.path())? != format!("nameserver {NS_SUBNET}.1\n")
        {
            return Err(failure(
                "Namespace resolver changed; refusing to discard it",
            ));
        }
    }
    if exists {
        if Namespace::open(NAMESPACE_NAME)?.identity != lease.identity {
            return Err(failure("Namespace replaced during cleanup"));
        }
        run(&["netns", "delete", NAMESPACE_NAME])?;
    }
    // Deleting a veth peer can already have removed the other endpoint.
    for name in owned {
        let current: Vec<Link> = serde_json::from_str(&run(&["-j", "-d", "link", "show"])?)?;
        if current.iter().any(|link| link.ifname == name) {
            let confirmed = owned_links(&current, &lease.tag)?;
            if !confirmed.contains(&name) {
                return Err(failure("Link ownership changed"));
            }
            run(&["link", "delete", "dev", &name])?;
        }
    }
    crate::namespace::remove_namespace_rules(Some(&lease.tag))?;
    match fs::remove_file(format!("{NS_DIRECTORY}/resolv.conf")) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    // Keep the lease if any prior operation failed; the next recovery retries.
    match fs::remove_dir(NS_DIRECTORY) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    fs::remove_file(NS_LEASE)?;
    tracing::info!("Recovered owned namespace, veth pair and scoped rules");
    Ok(true)
}

/// Idempotent preflight. Caller must own the lifecycle lock, exclude live Wraith
/// workers and stop managed Tor before invoking this for an orphaned egress lease.
pub fn recover_orphaned_state() -> Result<()> {
    if let Some(egress) = read_lease::<crate::tcp_egress::TcpEgressSnapshot>(EGRESS_LEASE)? {
        crate::tcp_egress::remove_tor_egress(&egress)?;
    }
    cleanup_owned_namespace()?;
    // Unmarked old resources are not sufficient proof to mutate host networking.
    crate::namespace::preflight_namespace()?;
    crate::tcp_egress::ensure_no_orphan_policy()?;
    let links: Vec<Link> = serde_json::from_str(&run(&["-j", "-d", "link", "show"])?)?;
    if links.iter().any(|link| candidate(&link.ifname)) {
        return Err(failure(
            "Unowned legacy veth remains; automatic prefix deletion refused",
        ));
    }
    Ok(())
}

pub fn inspect_namespace_mac() -> Result<(String, String, bool)> {
    let lease = read_lease::<NamespaceLease>(NS_LEASE)?
        .ok_or_else(|| failure("No namespace L2 lease (legacy session)"))?;
    validate_lease(&lease)?;
    let ns = Namespace::open(NAMESPACE_NAME)?;
    if ns.identity != lease.identity {
        return Err(failure("Namespace lifetime changed"));
    }
    let output = ns.run("ip", &["-j", "link", "show", "dev", VETH_NS])?;
    if !output.status.success() {
        return Err(failure("Namespace L2 readback failed"));
    }
    let links: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let actual = links[0]["address"]
        .as_str()
        .ok_or_else(|| failure("Missing L2 address"))?
        .to_string();
    let matches = actual == lease.mac && links[0]["ifalias"].as_str() == Some(lease.tag.as_str());
    Ok((lease.mac.clone(), actual, matches))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn root_owned_recovery_directory_repairs_only_writable_group_bits() {
        assert_eq!(tighten_directory_mode(0o777), 0o755);
        assert_eq!(tighten_directory_mode(0o775), 0o755);
        assert_eq!(tighten_directory_mode(0o700), 0o700);
    }

    #[test]
    fn prefixes_never_authorize_physical_or_unmarked_link_deletion() {
        for (kind, alias) in [("ether", "owner"), ("veth", ""), ("veth", "someone-else")] {
            let links = [Link {
                ifname: VETH_HOST.into(),
                ifalias: alias.into(),
                linkinfo: LinkInfo {
                    info_kind: kind.into(),
                },
            }];
            assert!(owned_links(&links, "owner").is_err());
        }
        let links = [Link {
            ifname: "veth_wraith_old".into(),
            ifalias: "owner".into(),
            linkinfo: LinkInfo {
                info_kind: "veth".into(),
            },
        }];
        assert_eq!(owned_links(&links, "owner").unwrap(), ["veth_wraith_old"]);
        assert!(owned_links(&[], "owner").unwrap().is_empty());
    }
    #[test]
    fn malformed_ownership_tokens_are_rejected() {
        let mut lease = NamespaceLease {
            version: 1,
            boot_id: "boot".into(),
            identity: NamespaceIdentity {
                device: 1,
                inode: 2,
            },
            tag: "wraith-netns-not-an-owner".into(),
            mac: String::new(),
        };
        assert!(validate_lease(&lease).is_err());
        lease.tag = format!("wraith-netns-{}", "a".repeat(32));
        assert!(validate_lease(&lease).is_ok());
        lease.version = 2;
        assert!(validate_lease(&lease).is_err());
    }
}

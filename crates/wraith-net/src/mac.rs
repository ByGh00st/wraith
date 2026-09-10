//! Wraith Hardware Identity Spoofing Engine
//! L2 MAC Randomization with realistic manufacturer OUIs and generic hostname generation.

use rand::seq::SliceRandom;
use rand::Rng;
use std::process::Command;
use tracing::info;
use wraith_core::error::{Result, WraithError};

pub const VENDOR_OUIS: &[&str] = &[
    "00:20:7A", // WiseComm
    "00:1B:44", // SanDisk
    "00:24:D6", // Intel
    "00:26:C6", // Intel
    "3C:D9:2B", // Hewlett-Packard
    "00:1E:68", // Quanta
    "00:25:00", // Apple
    "F0:DB:E2", // Apple
    "00:50:56", // VMware
    "00:0C:29", // VMware
    "08:00:27", // VirtualBox
    "52:54:00", // QEMU
];

fn run_cmd(cmd: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| WraithError::Hardware(format!("Command {cmd} failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(WraithError::Hardware(format!("{cmd} {:?} failed: {stderr}", args)));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn get_default_interface() -> Result<String> {
    let output = run_cmd("ip", &["route", "show", "default"])?;
    for part in output.split_whitespace().collect::<Vec<_>>().windows(2) {
        if part[0] == "dev" {
            return Ok(part[1].to_string());
        }
    }

    // Fallback: search for active non-lo link
    let links = run_cmd("ip", &["-o", "link", "show", "up"])?;
    for line in links.lines() {
        if let Some(iface) = line.split(':').nth(1) {
            let clean = iface.trim();
            if clean != "lo" {
                return Ok(clean.to_string());
            }
        }
    }

    Err(WraithError::Hardware("No suitable network interface discovered".into()))
}

pub fn get_current_mac(interface: &str) -> Result<String> {
    let output = run_cmd("ip", &["link", "show", interface])?;
    for line in output.lines() {
        if let Some(pos) = line.find("link/ether ") {
            if let Some(rest) = line.get(pos + 11..) {
                if let Some(mac) = rest.split_whitespace().next() {
                    if mac.len() == 17 {
                        return Ok(mac.to_string());
                    }
                }
            }
        }
    }
    Err(WraithError::Hardware(format!("Could not extract MAC from {interface}")))
}

pub fn generate_random_mac(vendor_prefix: bool) -> String {
    let mut rng = rand::thread_rng();
    if vendor_prefix {
        let oui = VENDOR_OUIS.choose(&mut rng).unwrap_or(&"00:24:D6");
        let suffix = format!(
            "{:02x}:{:02x}:{:02x}",
            rng.gen::<u8>(),
            rng.gen::<u8>(),
            rng.gen::<u8>()
        );
        format!("{oui}:{suffix}")
    } else {
        let first_byte = (rng.gen::<u8>() & 0xFE) | 0x02; // unicast + locally administered
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            first_byte,
            rng.gen::<u8>(),
            rng.gen::<u8>(),
            rng.gen::<u8>(),
            rng.gen::<u8>(),
            rng.gen::<u8>()
        )
    }
}

pub fn change_mac(interface: Option<&str>, target_mac: Option<&str>) -> Result<(String, String, String)> {
    change_mac_with_journal(interface, target_mac, |_, _, _| Ok(()))
}

pub fn change_mac_with_journal(interface: Option<&str>, target_mac: Option<&str>, journal: impl FnOnce(&str, &str, &str) -> Result<()>) -> Result<(String, String, String)> {
    let iface = match interface {
        Some(i) => i.to_string(),
        None => get_default_interface()?,
    };

    let old_mac = get_current_mac(&iface)?;
    let new_mac = match target_mac {
        Some(m) => m.to_string(),
        None => generate_random_mac(true),
    };

    journal(&iface, &old_mac, &new_mac)?;
    info!("Spoofing MAC on {iface}: {old_mac} -> {new_mac}");

    run_cmd("ip", &["link", "set", &iface, "down"])?;
    let changed = (|| {
        run_cmd("ip", &["link", "set", &iface, "address", &new_mac])?;
        run_cmd("ip", &["link", "set", &iface, "up"])?;
        let verified = get_current_mac(&iface)?;
        if !verified.eq_ignore_ascii_case(&new_mac) {
            return Err(WraithError::Hardware("MAC verification failed".into()));
        }
        Ok(verified)
    })();
    let verified_mac = match changed {
        Ok(mac) => mac,
        Err(error) => {
            let restored = restore_mac(&iface, &old_mac);
            if let Err(rollback) = restored {
                return Err(WraithError::Hardware(format!("{error}; MAC rollback failed: {rollback}")));
            }
            return Err(error);
        }
    };
    // Do not flush static addresses or kill DHCP clients on unrelated adapters.

    Ok((iface, old_mac, verified_mac))
}

pub fn restore_mac(interface: &str, original_mac: &str) -> Result<()> {
    info!("Restoring hardware MAC on {interface} to {original_mac}");
    run_cmd("ip", &["link", "set", interface, "down"])?;
    let address_result = run_cmd("ip", &["link", "set", interface, "address", original_mac]);
    let up_result = run_cmd("ip", &["link", "set", interface, "up"]);
    address_result?;
    up_result?;
    if !get_current_mac(interface)?.eq_ignore_ascii_case(original_mac) {
        return Err(WraithError::Hardware("MAC restoration verification failed".into()));
    }
    Ok(())
}

pub fn randomize_hostname() -> Result<(String, String)> {
    randomize_hostname_with_journal(|_| Ok(()))
}

pub fn randomize_hostname_with_journal(journal: impl FnOnce(&str) -> Result<()>) -> Result<(String, String)> {
    let old_host = run_cmd("hostname", &[])?;
    journal(&old_host)?;

    let adjectives = ["quiet", "swift", "dark", "silent", "deep", "cold", "thin", "pale", "shadow"];
    let nouns = ["node", "host", "desk", "core", "unit", "base", "link", "port", "gate"];
    let mut rng = rand::thread_rng();
    let num: u16 = rng.gen_range(10..99);
    let adj = adjectives.choose(&mut rng).copied().unwrap_or("shadow");
    let noun = nouns.choose(&mut rng).copied().unwrap_or("node");
    let new_host = format!("{adj}-{noun}-{num}");

    run_cmd("hostname", &[&new_host])?;
    info!("Hostname randomized: {old_host} -> {new_host}");
    Ok((old_host, new_host))
}

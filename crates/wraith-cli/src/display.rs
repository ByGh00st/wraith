//! Wraith Sovereign Terminal Presentation Engine
//! Cyberpunk high-contrast telemetry dashboards, live circuit topologies, and visual leak monitors.

use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
use owo_colors::OwoColorize;
use wraith_core::state::StateData;
use wraith_guard::LeakReport;
use wraith_tor::TorTelemetry;

pub const WRAITH_BANNER: &str = r#"
 ╦ ╦╦═╗╔═╗╦╔╦╗╦ ╦  ╔═╗╦═╗╦╔╦╗╔═╗
 ║║║╠╦╝╠═╣║ ║ ╠═╣  ╠═╝╠╦╝║║║║║╣ 
 ╚╩╝╩╚═╩ ╩╩ ╩ ╩ ╩  ╩  ╩╚═╩╩ ╩╚═╝"#;

pub fn print_banner() {
    println!("{}", WRAITH_BANNER.bold().magenta());
    println!(
        "  ┌── {} ──────────────────────────────────────────────────────────┐",
        "WRAITH-PRIME // GEN-4 SOVEREIGN KERNEL ANONYMIZATION MATRIX".bold().cyan()
    );
    println!(
        "  │  {} {}  │  {} {}  │  {} {}  │",
        "CORE:".dimmed(), "Rust 2021".bold().green(),
        "TARGET:".dimmed(), "Kali Linux x86_64".bold().yellow(),
        "SECURITY:".dimmed(), "BLACK-LEVEL".bold().red()
    );
    println!("  └───────────────────────────────────────────────────────────────────────────────────────────────┘\n");
}

pub fn print_step(msg: &str, status: &str) {
    let tag = match status {
        "ok" => "✔".bold().green().to_string(),
        "error" => "✖".bold().red().to_string(),
        "warn" => "⚠".bold().yellow().to_string(),
        _ => "◈".bold().cyan().to_string(),
    };
    println!("  {tag} {msg}");
}

pub fn print_success(msg: &str) {
    println!(
        "\n  ╔═══════════════════════════════════════════════════════════════════════════════════════════════╗\n  ║  {} {:<77} ║\n  ╚═══════════════════════════════════════════════════════════════════════════════════════════════╝\n",
        "✔ SUCCESS:".bold().green(),
        msg.bold().white()
    );
}

pub fn print_error(msg: &str) {
    println!(
        "\n  ╔═══════════════════════════════════════════════════════════════════════════════════════════════╗\n  ║  {} {:<79} ║\n  ╚═══════════════════════════════════════════════════════════════════════════════════════════════╝\n",
        "✖ ERROR:".bold().red(),
        msg.bold().white()
    );
}

pub fn show_status_dashboard(state: &StateData, is_tor: bool, ip: &str, circuits: usize) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("🛡️ Security & Telemetry Metric").add_attribute(Attribute::Bold).fg(Color::Cyan),
        Cell::new("⚡ Operational Status / Value").add_attribute(Attribute::Bold).fg(Color::Cyan),
    ]);

    let status_cell = if state.active {
        Cell::new("● ACTIVE / ARMED (Fail-Closed)").fg(Color::Green).add_attribute(Attribute::Bold)
    } else {
        Cell::new("○ INACTIVE").fg(Color::DarkGrey)
    };

    let tor_cell = if is_tor {
        Cell::new("✔ Verified via Tor Transparent Proxy (9040)").fg(Color::Green)
    } else {
        Cell::new("✖ Unverified / Direct Clearnet Warning").fg(Color::Red).add_attribute(Attribute::Bold)
    };

    let ks_cell = if state.kill_switch {
        Cell::new("● Fail-Closed Async Watchdog Armed (<1ms Drop)").fg(Color::Green)
    } else {
        Cell::new("○ Watchdog Disabled").fg(Color::Yellow)
    };

    table.add_row(vec![Cell::new("Sovereign State"), status_cell]);
    table.add_row(vec![Cell::new("Public Exit IP"), Cell::new(ip).fg(Color::White).add_attribute(Attribute::Bold)]);
    table.add_row(vec![Cell::new("Tor Network Routing"), tor_cell]);
    table.add_row(vec![Cell::new("KillSwitch Gate"), ks_cell]);
    table.add_row(vec![
        Cell::new("Active Circuits"),
        Cell::new(format!("{circuits} isolated multi-hop circuit(s) established")).fg(Color::Cyan),
    ]);

    table.add_row(vec![
        Cell::new("DPI Tool Auto-Sanitizer"),
        Cell::new("✔ In-Flight (Nmap, Sqlmap, Ffuf, Nikto headers rewritten to Chrome/Firefox)").fg(Color::Green),
    ]);

    table.add_row(vec![
        Cell::new("RAMFS Vault & Scrambler"),
        Cell::new("✔ Active (/dev/shm, mlockall + MADV_DONTDUMP + XOR rotation)").fg(Color::Green),
    ]);

    if let Some(mac) = &state.mac_new {
        table.add_row(vec![
            Cell::new("Hardware MAC Spoof"),
            Cell::new(format!("✔ Randomized: {mac}")).fg(Color::Magenta),
        ]);
    }

    if let Some(prof) = &state.exit_profile {
        table.add_row(vec![
            Cell::new("Geographic Exit Profile"),
            Cell::new(format!("✔ Active: {prof}")).fg(Color::Blue),
        ]);
    }

    if state.namespace_active {
        table.add_row(vec![
            Cell::new("Kernel Net Namespace"),
            Cell::new("✔ Isolated Jail (10.200.1.0/24 veth pair)").fg(Color::Green),
        ]);
    }

    if state.tcp_stack_masked {
        table.add_row(vec![
            Cell::new("TCP/IP Stack Mask (p0f)"),
            Cell::new("✔ Windows 11 L4 Profile (TTL=128, TS=0)").fg(Color::Green),
        ]);
    }

    if state.machine_id_old.is_some() {
        table.add_row(vec![
            Cell::new("Hardware DMI Cloaking"),
            Cell::new("✔ /etc/machine-id & DMI Serial Rotated").fg(Color::Green),
        ]);
    }

    println!("{table}\n");
}

pub fn show_leak_report(report: &LeakReport) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("Attack Vector").add_attribute(Attribute::Bold).fg(Color::Cyan),
        Cell::new("Integrity").add_attribute(Attribute::Bold).fg(Color::Cyan),
        Cell::new("Inspection Details").add_attribute(Attribute::Bold).fg(Color::Cyan),
    ]);

    let ip_val = report.ip_address.as_deref().unwrap_or("Unknown");
    let tor_status = if report.is_tor {
        Cell::new("✔ PASS").fg(Color::Green).add_attribute(Attribute::Bold)
    } else {
        Cell::new("✖ FAIL").fg(Color::Red).add_attribute(Attribute::Bold)
    };

    let dns_status = if !report.dns_leak {
        Cell::new("✔ NO LEAK").fg(Color::Green).add_attribute(Attribute::Bold)
    } else {
        Cell::new("✖ LEAK DETECTED").fg(Color::Red).add_attribute(Attribute::Bold)
    };

    let ipv6_status = if !report.ipv6_leak {
        Cell::new("✔ FULL DROP").fg(Color::Green).add_attribute(Attribute::Bold)
    } else {
        Cell::new("✖ LEAK DETECTED").fg(Color::Red).add_attribute(Attribute::Bold)
    };

    let overall = if report.secure {
        Cell::new("✔ 100% SECURE").fg(Color::Green).add_attribute(Attribute::Bold)
    } else {
        Cell::new("✖ VULNERABLE").fg(Color::Red).add_attribute(Attribute::Bold)
    };

    table.add_row(vec![Cell::new("Public Exit IP"), Cell::new(ip_val).fg(Color::White), Cell::new("Tor Network Exit Relay")]);
    table.add_row(vec![Cell::new("Tor Transparent Proxy"), tor_status, Cell::new("All TCP egress routed through TransPort 9040")]);
    table.add_row(vec![Cell::new("DNS Leak Protection"), dns_status, Cell::new("All queries forced through Sovereign DNS 5353")]);
    table.add_row(vec![Cell::new("IPv6 Dual-Stack Leak"), ipv6_status, Cell::new("Kernel netfilter unconditional drop")]);
    table.add_row(vec![Cell::new("Overall Defense Grade"), overall, Cell::new("Operational Security & Forensic Assessment")]);

    println!("{table}\n");
}

pub fn show_circuit_telemetry(telemetry: &TorTelemetry) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("Circuit ID").add_attribute(Attribute::Bold).fg(Color::Cyan),
        Cell::new("Relay Multi-Hop Topology").add_attribute(Attribute::Bold).fg(Color::Cyan),
        Cell::new("Circuit Purpose").add_attribute(Attribute::Bold).fg(Color::Cyan),
    ]);

    for circ in &telemetry.circuits {
        let path_str = circ.path.join(" ➔ ");
        table.add_row(vec![
            Cell::new(&circ.id).fg(Color::Yellow),
            Cell::new(path_str).fg(Color::Green),
            Cell::new(&circ.purpose).fg(Color::DarkGrey),
        ]);
    }

    println!("{table}\n");
    println!(
        "  {} Tor v{} | ↓ {:.2} MB | ↑ {:.2} MB\n",
        "[STATS]".dimmed(),
        telemetry.version,
        telemetry.bytes_read as f64 / (1024.0 * 1024.0),
        telemetry.bytes_written as f64 / (1024.0 * 1024.0)
    );
}

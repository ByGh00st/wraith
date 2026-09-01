//! Wraith Terminal Presentation Engine
//! Cyberpunk high-contrast telemetry dashboards, live circuit topologies, and visual leak monitors.

use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
use owo_colors::OwoColorize;
use wraith_core::state::StateData;
use wraith_guard::LeakReport;
use wraith_tor::TorTelemetry;
use rust_i18n::t;

pub const WRAITH_BANNER: &str = r#"
   ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗
   ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║
   ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║
   ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║
   ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║
    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝"#;

pub fn detect_target_os() -> String {
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("PRETTY_NAME=") {
                let clean = val.trim_matches('"').trim_matches('\'').trim();
                if !clean.is_empty() {
                    return format!("{clean} ({})", std::env::consts::ARCH);
                }
            }
        }
    }
    format!("Linux ({})", std::env::consts::ARCH)
}

pub fn visible_width(s: &str) -> usize {
    let mut width = 0;
    let mut in_escape = false;

    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
            continue;
        }
        if in_escape {
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
            continue;
        }
        if c == '\u{fe0f}' || c == '\u{fe0e}' || ('\u{200b}'..='\u{200d}').contains(&c) {
            continue;
        }
        let u = c as u32;
        if (0x1F300..=0x1FAFF).contains(&u)
            || (0x2600..=0x27BF).contains(&u)
            || (0x2E80..=0x9FFF).contains(&u)
            || (0xAC00..=0xD7AF).contains(&u)
            || (0xF900..=0xFAFF).contains(&u)
            || (0xFF01..=0xFF60).contains(&u)
        {
            width += 2;
        } else {
            width += 1;
        }
    }
    width
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BoxCorner {
    Rounded, // ╭ ╮ ╰ ╯
    Square,  // ┌ ┐ └ ┘
}

pub fn render_box_top(title: &str, total_width: usize, corner: BoxCorner) -> String {
    let (top_left, top_right) = match corner {
        BoxCorner::Rounded => ("╭", "╮"),
        BoxCorner::Square => ("┌", "┐"),
    };

    let clean_title = if let (Some(start), Some(end)) = (title.find('['), title.rfind(']')) {
        title[start + 1..end].trim()
    } else {
        title.trim()
    };

    let title_w = visible_width(clean_title);
    let fixed_w = 2 /* spaces */ + 1 /* corner */ + 2 /* ── */ + 3 /* " [ " */ + title_w + 3 /* " ] " */ + 1 /* corner */;
    let dash_count = if total_width > fixed_w { total_width - fixed_w } else { 2 };
    let dashes = "─".repeat(dash_count);
    format!("  {top_left}── [ {clean_title} ] {dashes}{top_right}")
}

pub fn render_box_bottom(total_width: usize, corner: BoxCorner) -> String {
    let (bottom_left, bottom_right) = match corner {
        BoxCorner::Rounded => ("╰", "╯"),
        BoxCorner::Square => ("└", "┘"),
    };
    let dash_count = if total_width > 4 { total_width - 4 } else { 2 };
    let dashes = "─".repeat(dash_count);
    format!("  {bottom_left}{dashes}{bottom_right}")
}

pub fn render_box_row(content: &str, total_width: usize) -> String {
    let inner_w = if total_width > 7 { total_width - 7 } else { 1 };
    let v_w = visible_width(content);
    let padding_count = if inner_w > v_w { inner_w - v_w } else { 0 };
    let padding = " ".repeat(padding_count);
    format!("  │  {content}{padding} │")
}

pub fn print_banner(is_strict: bool) {
    let target = detect_target_os();
    if is_strict {
        println!("{}", WRAITH_BANNER.bold().bright_red());
        println!("{}", render_box_top(&t!("banner.max_defense"), 78, BoxCorner::Rounded).bright_red());
        println!("{}", render_box_row(&format!("{} {}", t!("banner.engine_spec").dimmed(), t!("banner.engine_val_strict").bold().bright_red()), 78));
        println!("{}", render_box_row(&format!("{} {}", t!("banner.target_host").dimmed(), target.bold().bright_yellow()), 78));
        println!("{}", render_box_row(&format!("{} {}", t!("banner.gate_status").dimmed(), t!("banner.gate_val_strict").bold().bright_red()), 78));
        println!("{}\n", render_box_bottom(78, BoxCorner::Rounded).bright_red());
    } else {
        println!("{}", WRAITH_BANNER.bold().bright_purple());
        println!("{}", render_box_top(&t!("banner.telemetry"), 78, BoxCorner::Rounded).bright_cyan());
        println!("{}", render_box_row(&format!("{} {}", t!("banner.engine_spec").dimmed(), t!("banner.engine_val_normal").bold().bright_cyan()), 78));
        println!("{}", render_box_row(&format!("{} {}", t!("banner.target_host").dimmed(), target.bold().bright_yellow()), 78));
        println!("{}", render_box_row(&format!("{} {}", t!("banner.gate_status").dimmed(), t!("banner.gate_val_normal").bold().bright_green()), 78));
        println!("{}\n", render_box_bottom(78, BoxCorner::Rounded).bright_cyan());
    }
}

pub fn print_step(msg: &str, status: &str) {
    let (badge, colored_msg) = match status {
        "ok" => ("  ◈ [ARMED]   ".bold().bright_green().to_string(), msg.bold().white().to_string()),
        "error" => ("  ✖ [BLOCKED] ".bold().bright_red().to_string(), msg.bold().bright_red().to_string()),
        "warn" => ("  ▲ [AUDIT]   ".bold().bright_yellow().to_string(), msg.bright_yellow().to_string()),
        _ => ("  ❯ [STAGE]   ".bold().bright_cyan().to_string(), msg.dimmed().to_string()),
    };
    println!("{badge}{colored_msg}");
}

pub fn print_session_hud(geo: &wraith_guard::IpGeoInfo, is_strict: bool, interval: Option<u64>) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);

    if is_strict {
        table.set_header(vec![
            Cell::new(t!("hud.active_hud_strict")).fg(Color::Red).add_attribute(Attribute::Bold),
            Cell::new(t!("hud.op_status")).fg(Color::Red).add_attribute(Attribute::Bold),
        ]);
    } else {
        table.set_header(vec![
            Cell::new(t!("hud.active_hud_normal")).fg(Color::Cyan).add_attribute(Attribute::Bold),
            Cell::new(t!("hud.op_status")).fg(Color::Cyan).add_attribute(Attribute::Bold),
        ]);
    }

    let cc = geo.country_code.as_deref().unwrap_or("??");
    let cname = geo.country_name.as_deref().unwrap_or("Unknown");
    let loc_details = if let Some(city) = &geo.city {
        format!("{} ➔ {} [📍 {}], {}", geo.ip, cname, cc, city)
    } else {
        format!("{} ➔ {} [📍 {}]", geo.ip, cname, cc)
    };

    table.add_row(vec![
        Cell::new(t!("hud.tor_exit")).fg(Color::Yellow).add_attribute(Attribute::Bold),
        Cell::new(loc_details).fg(Color::Green).add_attribute(Attribute::Bold),
    ]);

    let mode_str = if is_strict {
        t!("hud.max_defense_val")
    } else {
        t!("hud.std_defense_val")
    };
    table.add_row(vec![
        Cell::new(t!("hud.sec_matrix")),
        Cell::new(mode_str).fg(Color::Green).add_attribute(Attribute::Bold),
    ]);

    table.add_row(vec![
        Cell::new(t!("hud.killswitch")),
        Cell::new(t!("hud.watchdog")).fg(Color::Green),
    ]);

    let rotate_str = if let Some(sec) = interval {
        t!("hud.auto_rotate").replace("{}", &sec.to_string())
    } else {
        t!("hud.manual_rotate").into_owned()
    };
    table.add_row(vec![
        Cell::new(t!("hud.rotate_policy")),
        Cell::new(rotate_str).fg(Color::Magenta),
    ]);

    table.add_row(vec![
        Cell::new(t!("hud.dpi_sanitizer")),
        Cell::new(t!("hud.dpi_active")).fg(Color::Cyan),
    ]);

    let state_data = wraith_core::state::StateManager::default().read();
    if state_data.multihop_enabled {
        table.add_row(vec![
            Cell::new("Multi-Hop Overlay").fg(Color::Cyan).add_attribute(Attribute::Bold),
            Cell::new("ACTIVE (WireGuard [ChaCha20] ➔ Tor [3 Hops] ➔ Exit Node)").fg(Color::Green).add_attribute(Attribute::Bold),
        ]);
    }

    println!("\n{table}");

    println!("{}", render_box_top(&t!("hud.keys"), 96, BoxCorner::Square).bright_cyan());
    let keys_content = format!("{} │ {} │ {} │ {} │ {}", 
        t!("hud.k_rotate").bold().bright_cyan(),
        t!("hud.k_audit").bold().bright_green(),
        t!("hud.k_monitor").bold().bright_purple(),
        t!("hud.k_purge").bold().bright_yellow(),
        t!("hud.k_quit").bold().bright_red()
    );
    println!("{}", render_box_row(&keys_content, 96));
    println!("{}\n", render_box_bottom(96, BoxCorner::Square).bright_cyan());
}

pub fn print_success(msg: &str) {
    println!("\n{}", render_box_top("✔ WRAITH SYSTEM RESTORED", 78, BoxCorner::Rounded).bold().bright_green());
    println!("{}", render_box_row(&msg.bold().bright_green().to_string(), 78));
    println!("{}\n", render_box_bottom(78, BoxCorner::Rounded).bold().bright_green());
}

pub fn print_error(msg: &str) {
    println!("\n{}", render_box_top("✖ CRITICAL SECURITY FAULT", 78, BoxCorner::Rounded).bold().bright_red());
    println!("{}", render_box_row(&msg.bold().bright_red().to_string(), 78));
    println!("{}\n", render_box_bottom(78, BoxCorner::Rounded).bold().bright_red());
}

pub fn show_status_dashboard(state: &StateData, is_tor: bool, ip: &str, circuits: usize) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("🛡️ Security & Telemetry Vector").add_attribute(Attribute::Bold).fg(Color::Cyan),
        Cell::new("⚡ Operational Status & Forensic State").add_attribute(Attribute::Bold).fg(Color::Cyan),
    ]);

    let status_cell = if state.active {
        Cell::new("● ACTIVE / ARMED (Fail-Closed Gate)").fg(Color::Green).add_attribute(Attribute::Bold)
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

    table.add_row(vec![Cell::new("Anonymization State"), status_cell]);
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
        Cell::new("✔ NO LEAKS DETECTED (this test)").fg(Color::Green).add_attribute(Attribute::Bold)
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

pub fn print_localized_help() {
    print_banner(false);
    println!("  {}\n", t!("help.desc").dimmed());
    println!("  {}\n", t!("help.usage").bold().bright_cyan());

    println!("  {}", t!("help.commands_header").bold().bright_yellow());
    let commands = [
        ("start", t!("help.cmd_start")),
        ("stop", t!("help.cmd_stop")),
        ("switch", t!("help.cmd_switch")),
        ("test", t!("help.cmd_test")),
        ("info", t!("help.cmd_info")),
        ("dashboard", t!("help.cmd_dashboard")),
        ("doctor", t!("help.cmd_doctor")),
        ("benchmark", t!("help.cmd_benchmark")),
        ("cleanup", t!("help.cmd_cleanup")),
        ("mac", t!("help.cmd_mac")),
        ("profile", t!("help.cmd_profile")),
        ("pentest", t!("help.cmd_pentest")),
        ("update", t!("help.cmd_update")),
        ("shred", t!("help.cmd_shred")),
        ("monitor", t!("help.cmd_monitor")),
    ];
    for (cmd, desc) in commands {
        println!("    {:<12} {}", cmd.bold().bright_green(), desc);
    }

    println!("\n  {}", t!("help.sec_net_header").bold().bright_yellow());
    let net_opts = [
        ("-m, --mac", t!("help.opt_mac")),
        ("-b, --bridge", t!("help.opt_bridge")),
        ("-n, --namespace", t!("help.opt_namespace")),
        ("-p, --profile <PROFILE>", t!("help.opt_profile")),
        ("--jitter", t!("help.opt_jitter")),
        ("--rotate-interval <SEC>", t!("help.opt_rotate")),
        ("--no-killswitch", t!("help.opt_no_ks")),
        ("-W, --wireguard <CONF>", t!("help.opt_wg")),
        ("--spawn-monitor", t!("help.opt_spawn_monitor")),
    ];
    for (opt, desc) in net_opts {
        println!("    {:<26} {}", opt.bold().bright_cyan(), desc);
    }

    println!("\n  {}", t!("help.sec_harden_header").bold().bright_yellow());
    let harden_opts = [
        ("--browser-shield", t!("help.opt_browser_shield")),
        ("--font-sandbox", t!("help.opt_font_sandbox")),
        ("--tcp-mask", t!("help.opt_tcp_mask")),
        ("--machine-id", t!("help.opt_machine_id")),
        ("-F, --full-security", t!("help.opt_full_security")),
    ];
    for (opt, desc) in harden_opts {
        println!("    {:<26} {}", opt.bold().bright_cyan(), desc);
    }

    println!("\n  {}", t!("help.sec_forensic_header").bold().bright_red());
    let forensic_opts = [
        ("--forensic-wipe-logs", t!("help.opt_wipe_logs")),
        ("-d, --forensic-self-destruct", t!("help.opt_self_destruct")),
        ("--aggressive-masquerade", t!("help.opt_masquerade")),
        ("--aggressive-anti-debug", t!("help.opt_anti_debug")),
    ];
    for (opt, desc) in forensic_opts {
        println!("    {:<26} {}", opt.bold().bright_red(), desc);
    }

    println!("\n  {}", "Genel Seçenekler / General Options:".bold().bright_yellow());
    println!("    {:<26} {}", "-v, --verbose", t!("help.opt_verbose"));
    println!("    {:<26} {}", "--lang <LANG>", t!("help.opt_lang"));
    println!("    {:<26} {}", "-h, --help", "Print this help message");
    println!("    {:<26} {}\n", "-V, --version", "Print version");
}


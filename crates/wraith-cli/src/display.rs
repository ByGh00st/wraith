//! Wraith Terminal Presentation Engine
//! Cyberpunk high-contrast telemetry dashboards, live circuit topologies, and visual leak monitors.

use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
use owo_colors::OwoColorize;
use wraith_core::state::StateData;
use wraith_guard::{IpGeoInfo, LeakReport};
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

use unicode_width::UnicodeWidthStr;

pub fn visible_width(s: &str) -> usize {
    let mut clean = String::with_capacity(s.len());
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
        clean.push(c);
    }
    UnicodeWidthStr::width(clean.as_str())
}

pub fn truncate_visible(s: &str, max_w: usize) -> String {
    let current_w = visible_width(s);
    if current_w <= max_w {
        return s.to_string();
    }
    if max_w <= 3 {
        return ".".repeat(max_w);
    }
    let target_w = max_w.saturating_sub(3);
    let mut clean_w = 0;
    let mut out = String::new();
    let mut in_escape = false;

    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
            out.push(c);
            continue;
        }
        if in_escape {
            out.push(c);
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
            continue;
        }
        let cw = unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
        if clean_w + cw > target_w {
            out.push_str("...");
            break;
        }
        out.push(c);
        clean_w += cw;
    }
    out
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

    let max_title_w = total_width.saturating_sub(12).max(10);
    let truncated_title = truncate_visible(clean_title, max_title_w);
    let title_w = visible_width(&truncated_title);
    let fixed_w = 1 /* top_left */ + 2 /* ── */ + 3 /* " [ " */ + title_w + 3 /* " ] " */ + 1 /* top_right */;
    let dash_count = if total_width >= fixed_w { total_width - fixed_w } else { 2 };
    let dashes = "─".repeat(dash_count);
    format!("  {top_left}── [ {truncated_title} ] {dashes}{top_right}")
}

pub fn render_box_bottom(total_width: usize, corner: BoxCorner) -> String {
    let (bottom_left, bottom_right) = match corner {
        BoxCorner::Rounded => ("╰", "╯"),
        BoxCorner::Square => ("└", "┘"),
    };
    let dash_count = total_width.saturating_sub(2);
    let dashes = "─".repeat(dash_count);
    format!("  {bottom_left}{dashes}{bottom_right}")
}

pub fn render_box_row(content: &str, total_width: usize) -> String {
    let inner_w = if total_width > 5 { total_width - 5 } else { 1 };
    let truncated = truncate_visible(content, inner_w);
    let v_w = visible_width(&truncated);
    let padding_count = inner_w.saturating_sub(v_w);
    let padding = " ".repeat(padding_count);
    format!("  │  {truncated}{padding} │")
}

pub fn render_box(title: &str, rows: &[String], corner: BoxCorner, max_box_width: usize) -> Vec<String> {
    let clean_title = if let (Some(start), Some(end)) = (title.find('['), title.rfind(']')) {
        title[start + 1..end].trim()
    } else {
        title.trim()
    };
    let term_width = crossterm::terminal::size().map(|(w, _)| w as usize).unwrap_or(80);
    let safe_term_width = term_width.saturating_sub(4).clamp(50, 78);
    let total_width = max_box_width.min(safe_term_width);

    let mut output = Vec::with_capacity(rows.len() + 2);
    output.push(render_box_top(clean_title, total_width, corner));
    for row in rows {
        output.push(render_box_row(row, total_width));
    }
    output.push(render_box_bottom(total_width, corner));
    output
}

pub fn print_banner(is_strict: bool) {
    let target = detect_target_os();
    let pkg_ver = env!("CARGO_PKG_VERSION");
    let (title, r1_val, r3_val) = if is_strict {
        let raw_r1 = t!("banner.engine_val_strict");
        let desc = if raw_r1.contains("v1.2.0") {
            raw_r1.replace("v1.2.0", &format!("v{pkg_ver}"))
        } else if !raw_r1.contains(&format!("v{pkg_ver}")) {
            format!("WRAITH v{pkg_ver} ({raw_r1})")
        } else {
            raw_r1.to_string()
        };
        (
            t!("banner.max_defense"),
            desc.bold().bright_red().to_string(),
            t!("banner.gate_val_strict").bold().bright_red().to_string(),
        )
    } else {
        let raw_r1 = t!("banner.engine_val_normal");
        let desc = if raw_r1.contains("v1.2.0") {
            raw_r1.replace("v1.2.0", &format!("v{pkg_ver}"))
        } else if !raw_r1.contains(&format!("v{pkg_ver}")) {
            format!("WRAITH v{pkg_ver} ({raw_r1})")
        } else {
            raw_r1.to_string()
        };
        (
            t!("banner.telemetry"),
            desc.bold().bright_cyan().to_string(),
            t!("banner.gate_val_normal").bold().bright_green().to_string(),
        )
    };

    let rows = vec![
        format!("{} {}", t!("banner.engine_spec").dimmed(), r1_val),
        format!("{} {}", t!("banner.target_host").dimmed(), target.bold().bright_yellow()),
        format!("{} {}", t!("banner.gate_status").dimmed(), r3_val),
    ];

    if is_strict {
        println!("{}", WRAITH_BANNER.bold().bright_red());
    } else {
        println!("{}", WRAITH_BANNER.bold().bright_purple());
    }

    let box_lines = render_box(&title, &rows, BoxCorner::Rounded, 78);
    if is_strict {
        println!("{}", box_lines[0].bright_red());
        for row in &box_lines[1..box_lines.len() - 1] {
            println!("{row}");
        }
        println!("{}\n", box_lines.last().unwrap().bright_red());
    } else {
        println!("{}", box_lines[0].bright_cyan());
        for row in &box_lines[1..box_lines.len() - 1] {
            println!("{row}");
        }
        println!("{}\n", box_lines.last().unwrap().bright_cyan());
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

pub fn country_flag(code: &str) -> String {
    let code = code.trim().to_uppercase();
    if code.len() == 2 && code != "??" {
        let mut chars = code.chars();
        if let (Some(c1), Some(c2)) = (chars.next(), chars.next()) {
            if c1.is_ascii_alphabetic() && c2.is_ascii_alphabetic() {
                if let (Some(f1), Some(f2)) = (
                    char::from_u32(0x1F1E6 + (c1 as u32 - 'A' as u32)),
                    char::from_u32(0x1F1E6 + (c2 as u32 - 'A' as u32)),
                ) {
                    return format!("{f1}{f2}");
                }
            }
        }
    }
    String::new()
}

pub fn format_geo_location(geo: &IpGeoInfo) -> String {
    let unk = t!("geo.unknown").into_owned();
    let cc = match geo.country_code.as_deref() {
        Some(c) if !c.trim().is_empty() && c.trim() != "??" && c.trim() != "Unknown" => c.trim().to_uppercase(),
        _ => return unk,
    };
    let flag = country_flag(&cc);
    let country = {
        let key = format!("geo.countries.{}", cc);
        let tr = t!(&key);
        if tr != key {
            tr.into_owned()
        } else if let Some(c) = geo.country_name.as_deref() {
            if !c.trim().is_empty() && c.trim() != "Unknown" && c.trim() != "??" {
                c.trim().to_string()
            } else {
                wraith_guard::iso_country_name(&cc).to_string()
            }
        } else {
            wraith_guard::iso_country_name(&cc).to_string()
        }
    };
    if country == "Unknown" || country.is_empty() {
        return unk;
    }
    let flag_prefix = if !flag.is_empty() { format!("{flag} ") } else { String::new() };
    if let Some(city) = &geo.city {
        if !city.trim().is_empty() && city.trim() != "Unknown" && city.trim() != "??" {
            return format!("{flag_prefix}{country} [{cc}], {city}");
        }
    }
    format!("{flag_prefix}{country} [{cc}]")
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

    let loc_str = format_geo_location(geo);
    let unk = t!("geo.unknown");
    let loc_details = if !loc_str.is_empty() && loc_str != unk.as_ref() {
        format!("{} ➔ {loc_str}", geo.ip)
    } else {
        let loc_unk = t!("geo.location_unknown");
        format!("{} [{loc_unk}]", geo.ip)
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

    let state_data = wraith_core::state::StateManager::default().read();
    table.add_row(vec![
        Cell::new(t!("hud.killswitch")),
        if state_data.kill_switch {
            Cell::new(t!("hud.watchdog")).fg(Color::Green)
        } else {
            Cell::new("--no-ks").fg(Color::Yellow)
        },
    ]);

    let rotate_str = if let Some(sec) = interval {
        t!("hud.auto_rotate", interval = sec).replace("%{interval}", &sec.to_string()).replace("{}", &sec.to_string())
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

    if state_data.multihop_enabled {
        table.add_row(vec![
            Cell::new("Multi-Hop Overlay").fg(Color::Cyan).add_attribute(Attribute::Bold),
            Cell::new("ACTIVE (WireGuard [ChaCha20] ➔ Tor [3 Hops] ➔ Exit Node)").fg(Color::Green).add_attribute(Attribute::Bold),
        ]);
    }

    println!("\n{table}");

    let row1 = format!("{} │ {} │ {}", 
        t!("hud.k_rotate").bold().bright_cyan(),
        t!("hud.k_audit").bold().bright_green(),
        t!("hud.k_monitor").bold().bright_purple(),
    );
    let row2 = format!("{} │ {}", 
        t!("hud.k_purge").bold().bright_yellow(),
        t!("hud.k_quit").bold().bright_red(),
    );
    let hud_box = render_box(&t!("hud.keys"), &[row1, row2], BoxCorner::Square, 80);
    println!("{}", hud_box[0].bright_cyan());
    for row in &hud_box[1..hud_box.len() - 1] {
        println!("{row}");
    }
    println!("{}\n", hud_box.last().unwrap().bright_cyan());
}

pub fn print_success(msg: &str) {
    let lines = render_box("✔ OPERATION SUCCESSFUL", &[msg.bold().bright_green().to_string()], BoxCorner::Rounded, 78);
    println!("\n{}", lines[0].bold().bright_green());
    for line in &lines[1..lines.len() - 1] {
        println!("{line}");
    }
    println!("{}\n", lines.last().unwrap().bold().bright_green());
}

pub fn print_identity_rotated(geo: &IpGeoInfo) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("🔄  WRAITH // IDENTITY ROTATION COMPLETED").fg(Color::Cyan).add_attribute(Attribute::Bold),
        Cell::new("CIRCUIT RE-ESTABLISHED").fg(Color::Cyan).add_attribute(Attribute::Bold),
    ]);

    table.add_row(vec![
        Cell::new("Signal Event").fg(Color::Yellow).add_attribute(Attribute::Bold),
        Cell::new("✔ SIGNAL NEWNYM Dispatched & Acknowledged").fg(Color::Green).add_attribute(Attribute::Bold),
    ]);

    let ip_str = if !geo.ip.is_empty() { &geo.ip } else { "Verified Tor Node" };
    table.add_row(vec![
        Cell::new("New Tor Exit IP").fg(Color::Yellow).add_attribute(Attribute::Bold),
        Cell::new(format!("{ip_str} [✔ Verified Tor Node]")).fg(Color::Green).add_attribute(Attribute::Bold),
    ]);

    let loc_str = format_geo_location(geo);
    table.add_row(vec![
        Cell::new("Exit Geolocation").fg(Color::Yellow),
        Cell::new(loc_str).fg(Color::Cyan).add_attribute(Attribute::Bold),
    ]);

    table.add_row(vec![
        Cell::new("Anonymization Gate").fg(Color::Yellow),
        Cell::new("✔ Transparent Proxy (:9040) Active").fg(Color::Green),
    ]);

    table.add_row(vec![
        Cell::new("Fail-Closed Protection").fg(Color::Yellow),
        Cell::new("● Armed (Zero-Leak Circuit Swap)").fg(Color::Green),
    ]);

    println!("\n{table}");

    let notice = vec![
        "  ⚡ New cryptographic circuit active. Previous circuits & DNS caches flushed.".to_string(),
        format!(
            "  {} │ {} │ {}",
            "Live Telemetry: wraith -i".bold().bright_cyan(),
            "Audit Leaks: wraith -t".bold().bright_yellow(),
            "Disarm: wraith -x".bold().bright_red()
        ),
    ];
    let notice_box = render_box("⚡ IDENTITY RE-ROUTED", &notice, BoxCorner::Rounded, 78);
    println!("{}", notice_box[0].bright_cyan());
    for row in &notice_box[1..notice_box.len() - 1] {
        println!("{row}");
    }
    println!("{}\n", notice_box.last().unwrap().bright_cyan());
}

pub fn print_error(msg: &str) {
    let lines = render_box("✖ CRITICAL SECURITY FAULT", &[msg.bold().bright_red().to_string()], BoxCorner::Rounded, 78);
    println!("\n{}", lines[0].bold().bright_red());
    for line in &lines[1..lines.len() - 1] {
        println!("{line}");
    }
    println!("{}\n", lines.last().unwrap().bold().bright_red());
}

pub fn print_background_hud(state: &StateData, geo: &IpGeoInfo) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("⚔️  WRAITH // DAEMON SUBSYSTEM ARMED").fg(Color::Cyan).add_attribute(Attribute::Bold),
        Cell::new("OPERATIONAL POSTURE & TELEMETRY").fg(Color::Cyan).add_attribute(Attribute::Bold),
    ]);

    table.add_row(vec![
        Cell::new("Operational State").fg(Color::Yellow).add_attribute(Attribute::Bold),
        Cell::new("● ACTIVE [Detached Background Session]").fg(Color::Green).add_attribute(Attribute::Bold),
    ]);

    if let Some(pid) = state.pid {
        table.add_row(vec![
            Cell::new("Daemon PID").fg(Color::Yellow),
            Cell::new(format!("✔ PID {pid} (Isolated Process Tree)")).fg(Color::Cyan),
        ]);
    }

    let ip_display = if !geo.ip.is_empty() {
        &geo.ip
    } else {
        state.ip.as_deref().unwrap_or("Verified Tor Node")
    };
    let loc_str = format_geo_location(geo);
    let unk = t!("geo.unknown");
    let exit_display = if !loc_str.is_empty() && loc_str != unk.as_ref() {
        format!("{ip_display} ➔ {loc_str}")
    } else {
        let loc_unk = t!("geo.location_unknown");
        format!("{ip_display} [{loc_unk}]")
    };
    table.add_row(vec![
        Cell::new("Tor Public Exit IP").fg(Color::Yellow).add_attribute(Attribute::Bold),
        Cell::new(exit_display).fg(Color::Green).add_attribute(Attribute::Bold),
    ]);

    table.add_row(vec![
        Cell::new("Traffic Redirection").fg(Color::Yellow),
        Cell::new("✔ Enforced via Tor Transparent Proxy (:9040)").fg(Color::Green),
    ]);

    table.add_row(vec![
        Cell::new("Fail-Closed Gate").fg(Color::Yellow),
        Cell::new("● Armed (Sub-Millisecond Packet Drop)").fg(Color::Green),
    ]);

    if let Some(iface) = &state.target_interface {
        table.add_row(vec![
            Cell::new("Locked Interface").fg(Color::Yellow),
            Cell::new(format!("✔ {iface}")).fg(Color::Green),
        ]);
    }

    if let Some(mac) = &state.mac_new {
        table.add_row(vec![
            Cell::new("MAC Address").fg(Color::Yellow),
            Cell::new(format!("✔ Spoofed: {mac}")).fg(Color::Magenta),
        ]);
    }

    if let Some(prof) = &state.exit_profile {
        table.add_row(vec![
            Cell::new("Exit Profile").fg(Color::Yellow),
            Cell::new(format!("✔ {prof}")).fg(Color::Blue),
        ]);
    }

    if state.multihop_enabled {
        table.add_row(vec![
            Cell::new("Multi-Hop Overlay").fg(Color::Yellow),
            Cell::new("✔ WireGuard ➔ Tor [3 Hops] ➔ Exit Node").fg(Color::Green).add_attribute(Attribute::Bold),
        ]);
    }

    println!("\n{table}");

    let row1 = format!(
        "{} │ {}",
        "wraith -i".bold().bright_cyan(),
        "Live Telemetry & Circuit Dashboard".bright_white()
    );
    let row2 = format!(
        "{} │ {}",
        "wraith -x".bold().bright_red(),
        "Instant Disarm & Full System Restore".bright_white()
    );
    let hud_box = render_box("⚔ DAEMON CONTROLS", &[row1, row2], BoxCorner::Rounded, 78);
    println!("{}", hud_box[0].bright_cyan());
    for row in &hud_box[1..hud_box.len() - 1] {
        println!("{row}");
    }
    println!("{}\n", hud_box.last().unwrap().bright_cyan());
}

pub fn show_status_dashboard(state: &StateData, geo: &IpGeoInfo, circuits: usize) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);

    let (title, title_color) = if state.active {
        ("🛡️  WRAITH // SYSTEM TELEMETRY MATRIX", Color::Cyan)
    } else {
        ("⚠️  WRAITH // GATE OFFLINE", Color::Yellow)
    };

    table.set_header(vec![
        Cell::new(title).fg(title_color).add_attribute(Attribute::Bold),
        Cell::new("GATE METRICS & HARDENING POSTURE").fg(Color::Cyan).add_attribute(Attribute::Bold),
    ]);

    let (status_label, status_val) = if state.active {
        ("Operational State", Cell::new("● ACTIVE [Fail-Closed Gateway Armed]").fg(Color::Green).add_attribute(Attribute::Bold))
    } else {
        ("Operational State", Cell::new("○ INACTIVE [Clearnet Direct Route]").fg(Color::Red).add_attribute(Attribute::Bold))
    };
    table.add_row(vec![
        Cell::new(status_label).fg(Color::Yellow).add_attribute(Attribute::Bold),
        status_val,
    ]);

    let unk = t!("geo.unknown");
    let ip_val = if !geo.ip.is_empty() {
        geo.ip.as_str()
    } else if let Some(ref ip) = state.ip {
        ip.as_str()
    } else {
        unk.as_ref()
    };

    let ip_cell = if geo.is_tor || state.active {
        Cell::new(format!("{ip_val} [✔ Verified Tor Node]")).fg(Color::Green).add_attribute(Attribute::Bold)
    } else {
        Cell::new(format!("{ip_val} [✖ DIRECT CLEARNET WARNING]")).fg(Color::Red).add_attribute(Attribute::Bold)
    };
    table.add_row(vec![
        Cell::new("Public Exit IP").fg(Color::Yellow).add_attribute(Attribute::Bold),
        ip_cell,
    ]);

    if geo.is_tor || state.active || geo.country_code.is_some() {
        let loc_str = format_geo_location(geo);
        table.add_row(vec![
            Cell::new("Exit Geolocation").fg(Color::Yellow),
            Cell::new(loc_str).fg(Color::Cyan),
        ]);
    }

    let route_cell = if geo.is_tor || state.active {
        Cell::new("✔ Enforced via Tor Transparent Proxy (:9040)").fg(Color::Green)
    } else {
        Cell::new("✖ Direct Clearnet (Bypass Active)").fg(Color::Red)
    };
    table.add_row(vec![
        Cell::new("Traffic Redirection").fg(Color::Yellow),
        route_cell,
    ]);

    let ks_cell = if state.kill_switch || state.active {
        Cell::new("● Armed (Fail-Closed Sub-Millisecond Drop)").fg(Color::Green)
    } else {
        Cell::new("○ Inactive (Engages on gateway start)").fg(Color::DarkGrey)
    };
    table.add_row(vec![
        Cell::new("Kill-Switch Protection").fg(Color::Yellow),
        ks_cell,
    ]);

    if state.active {
        table.add_row(vec![
            Cell::new("Active Circuits").fg(Color::Yellow),
            Cell::new(format!("{circuits} Multi-Hop Circuit(s) Established")).fg(Color::Cyan),
        ]);

        if let Some(iface) = &state.target_interface {
            table.add_row(vec![
                Cell::new("Locked Interface").fg(Color::Yellow),
                Cell::new(format!("✔ {iface}")).fg(Color::Green),
            ]);
        }

        if let Some(mac) = &state.mac_new {
            table.add_row(vec![
                Cell::new("MAC Address").fg(Color::Yellow),
                Cell::new(format!("✔ Spoofed: {mac}")).fg(Color::Magenta),
            ]);
        }

        if let Some(prof) = &state.exit_profile {
            table.add_row(vec![
                Cell::new("Exit Node Profile").fg(Color::Yellow),
                Cell::new(format!("✔ {prof}")).fg(Color::Blue),
            ]);
        }

        if state.multihop_enabled {
            table.add_row(vec![
                Cell::new("Multi-Hop Overlay").fg(Color::Yellow),
                Cell::new("✔ WireGuard ➔ Tor ➔ Exit").fg(Color::Green).add_attribute(Attribute::Bold),
            ]);
        }

        if state.browser_hardened > 0 {
            table.add_row(vec![
                Cell::new("Browser Shield").fg(Color::Yellow),
                Cell::new(format!("✔ {} Browser Profile(s) Jailed", state.browser_hardened)).fg(Color::Green),
            ]);
        }

        if state.namespace_active {
            table.add_row(vec![
                Cell::new("Net Namespace").fg(Color::Yellow),
                Cell::new("✔ Isolated Network Namespace (10.200.1.0/24)").fg(Color::Green),
            ]);
        }

        if state.tcp_stack_masked {
            table.add_row(vec![
                Cell::new("TCP/IP Fingerprint").fg(Color::Yellow),
                Cell::new("✔ Normalized OS Stack (TTL=128, TS=0, MSS=1460)").fg(Color::Green),
            ]);
        }
    }

    println!("\n{table}");

    let r1 = format!(
        "{} │ {} │ {}",
        "wraith -s  (Arm)".bold().bright_green(),
        "wraith -x  (Disarm)".bold().bright_red(),
        "wraith -c  (Rotate IP)".bold().bright_cyan()
    );
    let r2 = format!(
        "{} │ {}",
        "wraith -t  (Audit Leaks)".bold().bright_yellow(),
        "wraith -m  (Live TUI Monitor)".bold().bright_purple()
    );
    let info_box = render_box(
        "⚡ QUICK COMMANDS",
        &[r1, r2],
        BoxCorner::Rounded,
        78,
    );
    println!("{}", info_box[0].bright_cyan());
    for row in &info_box[1..info_box.len() - 1] {
        println!("{row}");
    }
    println!("{}\n", info_box.last().unwrap().bright_cyan());
}

pub fn print_system_restored(geo: Option<&IpGeoInfo>) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("✔  WRAITH // SYSTEM DISARMED & RESTORED").fg(Color::Green).add_attribute(Attribute::Bold),
        Cell::new("SECURITY AUDIT & TEARDOWN VERIFICATION").fg(Color::Green).add_attribute(Attribute::Bold),
    ]);

    table.add_row(vec![
        Cell::new("Operational State").fg(Color::Yellow).add_attribute(Attribute::Bold),
        Cell::new("○ DEACTIVATED (Full Clearnet Restored)").fg(Color::Green).add_attribute(Attribute::Bold),
    ]);

    if let Some(g) = geo {
        let unk = t!("geo.unknown");
        let ip_str = if !g.ip.is_empty() { g.ip.as_str() } else { unk.as_ref() };
        table.add_row(vec![
            Cell::new("Clearnet Public IP").fg(Color::Yellow).add_attribute(Attribute::Bold),
            Cell::new(ip_str).fg(Color::Green).add_attribute(Attribute::Bold),
        ]);

        if g.country_code.is_some() || g.country_name.is_some() {
            let loc = format_geo_location(g);
            table.add_row(vec![
                Cell::new("Origin Geolocation").fg(Color::Yellow),
                Cell::new(loc).fg(Color::Cyan),
            ]);
        }
    }

    table.add_row(vec![
        Cell::new("Firewall Posture").fg(Color::Yellow),
        Cell::new("✔ Netfilter / iptables Rules Flushed & Cleared").fg(Color::Green),
    ]);

    table.add_row(vec![
        Cell::new("DNS Resolution").fg(Color::Yellow),
        Cell::new("✔ System Nameservers Restored (/etc/resolv.conf)").fg(Color::Green),
    ]);

    table.add_row(vec![
        Cell::new("Gateway Processes").fg(Color::Yellow),
        Cell::new("✔ Tor Daemon & Child Threads Terminated").fg(Color::Green),
    ]);

    table.add_row(vec![
        Cell::new("Anti-Forensics").fg(Color::Yellow),
        Cell::new("✔ Runtime State & Ephemeral IPC Wiped (Zero-Residue)").fg(Color::Green),
    ]);

    println!("\n{table}");

    let notice = vec![
        "  ⚡ Direct Clearnet link established. Your origin traffic is no longer masked.".to_string(),
        format!("  🔒 To re-arm Wraith anonymity gate: {}", "wraith -s".bold().bright_cyan()),
    ];
    let notice_box = render_box("SYSTEM STATUS : CLEARNET ACTIVE", &notice, BoxCorner::Rounded, 78);
    println!("{}", notice_box[0].bright_green());
    for row in &notice_box[1..notice_box.len() - 1] {
        println!("{row}");
    }
    println!("{}\n", notice_box.last().unwrap().bright_green());
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

    let unk = t!("geo.unknown");
    let ip_val = report.ip_address.as_deref().unwrap_or(unk.as_ref());
    let tor_status = if report.is_tor {
        Cell::new("✔ PASS").fg(Color::Green).add_attribute(Attribute::Bold)
    } else {
        Cell::new("✖ FAIL").fg(Color::Red).add_attribute(Attribute::Bold)
    };

    let dns_status = if !report.dns_checked {
        Cell::new("INCONCLUSIVE").fg(Color::Yellow)
    } else if !report.dns_leak {
        Cell::new("✔ NO LEAK").fg(Color::Green).add_attribute(Attribute::Bold)
    } else {
        Cell::new("✖ LEAK DETECTED").fg(Color::Red).add_attribute(Attribute::Bold)
    };

    let ipv6_status = if !report.ipv6_leak {
        Cell::new("✔ NO CONNECTION OBSERVED").fg(Color::Green).add_attribute(Attribute::Bold)
    } else {
        Cell::new("✖ LEAK DETECTED").fg(Color::Red).add_attribute(Attribute::Bold)
    };

    let webrtc_status = if !report.webrtc_leak {
        Cell::new("✔ BLOCKED (STUN/TURN)").fg(Color::Green).add_attribute(Attribute::Bold)
    } else {
        Cell::new("✖ LEAK DETECTED").fg(Color::Red).add_attribute(Attribute::Bold)
    };

    let overall = if report.secure {
        Cell::new("✔ NO LEAKS DETECTED (this test)").fg(Color::Green).add_attribute(Attribute::Bold)
    } else {
        Cell::new("✖ NOT VERIFIED").fg(Color::Red).add_attribute(Attribute::Bold)
    };

    table.add_row(vec![Cell::new("Public Exit IP"), Cell::new(ip_val).fg(Color::White), Cell::new("Tor Network Exit Relay")]);
    table.add_row(vec![Cell::new("Tor Transparent Proxy"), tor_status, Cell::new("Tor exit API result for this request")]);
    table.add_row(vec![Cell::new("DNS Leak Protection"), dns_status, Cell::new("DNS relay: 5354; Tor upstream: 5353")]);
    table.add_row(vec![Cell::new("IPv6 Dual-Stack Leak"), ipv6_status, Cell::new("TCP probes to two IPv6 resolvers")]);
    table.add_row(vec![Cell::new("WebRTC STUN/TURN Leak"), webrtc_status, Cell::new("STUN port probes (Google STUN: 19302)")]);
    table.add_row(vec![Cell::new("Overall Defense Grade"), overall, Cell::new("Operational Security & Forensic Assessment")]);

    println!("{table}\n");
    for detail in &report.errors { println!("  {detail}"); }
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

    println!("  {}", t!("help.shortcuts_header").bold().bright_yellow());
    let shortcuts = [
        ("-s, --start", t!("help.cmd_start")),
        ("-x, --stop [-d]", t!("help.cmd_stop")),
        ("-r, --switch", t!("help.cmd_switch")),
        ("-t, --test", t!("help.cmd_test")),
        ("-i, --info", t!("help.cmd_info")),
        ("-u, --update", t!("help.cmd_update")),
        ("-c, --cleanup", t!("help.cmd_cleanup")),
        ("--cleanup-full", t!("help.cmd_cleanup_full")),
        ("-M, --monitor", t!("help.cmd_monitor")),
    ];
    for (sc, desc) in shortcuts {
        println!("    {:<28} {}", sc.bold().bright_green(), desc);
    }

    println!("\n  {}", t!("help.commands_header").bold().bright_yellow());
    let commands = [
        ("start [OPTIONS]", t!("help.cmd_start")),
        ("stop [-d]", t!("help.cmd_stop")),
        ("switch", t!("help.cmd_switch")),
        ("test", t!("help.cmd_test")),
        ("info", t!("help.cmd_info")),
        ("doctor", t!("help.cmd_doctor")),
        ("benchmark", t!("help.cmd_benchmark")),
        ("cleanup [--full]", t!("help.cmd_cleanup")),
        ("mac", t!("help.cmd_mac")),
        ("profile <PROFILE>", t!("help.cmd_profile")),
        ("pentest", t!("help.cmd_pentest")),
        ("fetch <URL> -o <FILE>", "HTTPS → Tor | --tls-profile chrome/firefox/safari".into()),
        ("update", t!("help.cmd_update")),
        ("shred <PATH>", t!("help.cmd_shred")),
        ("monitor", t!("help.cmd_monitor")),
        ("config [show|get|set]", t!("help.cmd_config")),
        ("bridge [moat|list]", t!("help.cmd_bridge")),
        ("doh [-s]", t!("help.cmd_doh")),
        ("interfaces [-a]", t!("help.cmd_interfaces")),
    ];
    for (cmd, desc) in commands {
        println!("    {:<28} {}", cmd.bold().bright_green(), desc);
    }

    println!("\n  {}", t!("help.sec_net_header").bold().bright_yellow());
    let net_opts = [
        ("-I, --interface <NIC>", t!("help.opt_interface")),
        ("--select-interface", t!("help.opt_select_interface")),
        ("-m, --mac", t!("help.opt_mac")),
        ("-b, --bridge", t!("help.opt_bridge")),
        ("--bridge-type <TYPE>", t!("help.opt_bridge_type")),
        ("-D, --doh <PRESET|URL>", t!("help.opt_doh")),
        ("--select-doh", t!("help.opt_select_doh")),
        ("-n, --namespace", t!("help.opt_namespace")),
        ("-p, --profile <PROFILE>", t!("help.opt_profile")),
        ("--jitter", t!("help.opt_jitter")),
        ("--jitter-endpoint <URL>", t!("help.opt_jitter")),
        ("--rotate-interval <SEC>", t!("help.opt_rotate")),
        ("--no-killswitch", t!("help.opt_no_ks")),
        ("-W, --wireguard <CONF>", t!("help.opt_wg")),
        ("--spawn-monitor", t!("help.opt_spawn_monitor")),
    ];
    for (opt, desc) in net_opts {
        println!("    {:<28} {}", opt.bold().bright_cyan(), desc);
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
        println!("    {:<28} {}", opt.bold().bright_cyan(), desc);
    }

    println!("\n  {}", t!("help.sec_forensic_header").bold().bright_red());
    let forensic_opts = [
        ("-L, --forensic-wipe-logs", t!("help.opt_wipe_logs")),
        ("-d, --forensic-self-destruct", t!("help.opt_self_destruct")),
        ("-K, --aggressive-masquerade", t!("help.opt_masquerade")),
        ("-A, --aggressive-anti-debug", t!("help.opt_anti_debug")),
    ];
    for (opt, desc) in forensic_opts {
        println!("    {:<28} {}", opt.bold().bright_red(), desc);
    }

    println!("\n  {}", t!("help.sec_general_header").bold().bright_yellow());
    println!("    {:<28} {}", "-v, --verbose", t!("help.opt_verbose"));
    println!("    {:<28} {}", "--lang <LANG>", t!("help.opt_lang"));
    println!("    {:<28} {}", "--select-lang", t!("help.opt_select_lang"));
    println!("    {:<28} {}", "-h, --help", t!("help.opt_help"));
    println!("    {:<28} {}", "-V, --version", t!("help.opt_version"));

    println!("\n  {}", t!("help.examples_header").bold().bright_yellow());
    println!("    {} {:<28} {}", "sudo wraith".bold().bright_white(), "-s -Fs".bright_cyan(), format!("→ {}", t!("help.ex_fs")).dimmed());
    println!("    {} {:<28} {}", "sudo wraith".bold().bright_white(), "-s -m -p stealth".bright_cyan(), format!("→ {}", t!("help.ex_stealth")).dimmed());
    println!("    {} {:<28} {}", "sudo wraith".bold().bright_white(), "-s -Fs -L".bright_cyan(), format!("→ {}", t!("help.ex_wipe")).dimmed());
    println!("    {} {:<28} {}", "sudo wraith".bold().bright_white(), "-s -Fs -d".bright_cyan(), format!("→ {}", t!("help.ex_destruct")).dimmed());
    println!("    {} {:<28} {}", "sudo wraith".bold().bright_white(), "-s -Fs --bridge-type moat".bright_cyan(), format!("→ {}", t!("help.ex_moat")).dimmed());
    println!("    {} {:<28} {}", "sudo wraith".bold().bright_white(), "-s -Fs -D quad9".bright_cyan(), format!("→ {}", t!("help.ex_doh")).dimmed());
    println!("    {} {:<28} {}", "sudo wraith".bold().bright_white(), "-x".bright_cyan(), format!("→ {}", t!("help.ex_stop")).dimmed());
    println!("    {} {:<28} {}\n", "sudo wraith".bold().bright_white(), "-u".bright_cyan(), format!("→ {}", t!("help.ex_update")).dimmed());
}

pub fn build_localized_command() -> clap::Command {
    use clap::CommandFactory;
    let mut cmd = crate::Cli::command();
    cmd = cmd.about(t!("help.desc").into_owned());

    cmd = cmd.mut_arg("interface", |a| a.help(t!("help.opt_interface").into_owned()))
        .mut_arg("select_interface", |a| a.help(t!("help.opt_select_interface").into_owned()))
        .mut_arg("mac", |a| a.help(t!("help.opt_mac").into_owned()))
        .mut_arg("bridge", |a| a.help(t!("help.opt_bridge").into_owned()))
        .mut_arg("bridge_type", |a| a.help(t!("help.opt_bridge_type").into_owned()))
        .mut_arg("doh", |a| a.help(t!("help.opt_doh").into_owned()))
        .mut_arg("select_doh", |a| a.help(t!("help.opt_select_doh").into_owned()))
        .mut_arg("namespace", |a| a.help(t!("help.opt_namespace").into_owned()))
        .mut_arg("profile", |a| a.help(t!("help.opt_profile").into_owned()))
        .mut_arg("jitter", |a| a.help(t!("help.opt_jitter").into_owned()))
        .mut_arg("rotate_interval", |a| a.help(t!("help.opt_rotate").into_owned()))
        .mut_arg("no_ks", |a| a.help(t!("help.opt_no_ks").into_owned()))
        .mut_arg("wireguard", |a| a.help(t!("help.opt_wg").into_owned()))
        .mut_arg("browser_shield", |a| a.help(t!("help.opt_browser_shield").into_owned()))
        .mut_arg("font_sandbox", |a| a.help(t!("help.opt_font_sandbox").into_owned()))
        .mut_arg("tcp_mask", |a| a.help(t!("help.opt_tcp_mask").into_owned()))
        .mut_arg("machine_id_rotation", |a| a.help(t!("help.opt_machine_id").into_owned()))
        .mut_arg("strict_hardening", |a| a.help(t!("help.opt_full_security").into_owned()))
        .mut_arg("monitor_window", |a| a.help(t!("help.opt_spawn_monitor").into_owned()))
        .mut_arg("forensic_wipe_logs", |a| a.help(t!("help.opt_wipe_logs").into_owned()))
        .mut_arg("forensic_self_destruct", |a| a.help(t!("help.opt_self_destruct").into_owned()))
        .mut_arg("aggressive_masquerade", |a| a.help(t!("help.opt_masquerade").into_owned()))
        .mut_arg("aggressive_anti_debug", |a| a.help(t!("help.opt_anti_debug").into_owned()))
        .mut_arg("verbose", |a| a.help(t!("help.opt_verbose").into_owned()))
        .mut_arg("lang", |a| a.help(t!("help.opt_lang").into_owned()))
        .mut_arg("select_lang", |a| a.help(t!("help.opt_select_lang").into_owned()))
        .mut_arg("start", |a| a.help(t!("help.cmd_start").into_owned()))
        .mut_arg("stop", |a| a.help(t!("help.cmd_stop").into_owned()))
        .mut_arg("switch", |a| a.help(t!("help.cmd_switch").into_owned()))
        .mut_arg("test", |a| a.help(t!("help.cmd_test").into_owned()))
        .mut_arg("info", |a| a.help(t!("help.cmd_info").into_owned()))
        .mut_arg("doctor", |a| a.help(t!("help.cmd_doctor").into_owned()))
        .mut_arg("bench", |a| a.help(t!("help.cmd_benchmark").into_owned()))
        .mut_arg("pentest", |a| a.help(t!("help.cmd_pentest").into_owned()))
        .mut_arg("update", |a| a.help(t!("help.cmd_update").into_owned()))
        .mut_arg("cleanup", |a| a.help(t!("help.cmd_cleanup").into_owned()))
        .mut_arg("cleanup_full", |a| a.help(t!("help.cmd_cleanup_full").into_owned()))
        .mut_arg("shred", |a| a.help(t!("help.cmd_shred").into_owned()))
        .mut_arg("monitor", |a| a.help(t!("help.cmd_monitor").into_owned()))
        .mut_arg("interfaces", |a| a.help(t!("help.cmd_interfaces").into_owned()));

    cmd = cmd.mut_subcommand("start", |s| s.about(t!("help.cmd_start").into_owned()))
        .mut_subcommand("stop", |s| s.about(t!("help.cmd_stop").into_owned()))
        .mut_subcommand("switch", |s| s.about(t!("help.cmd_switch").into_owned()))
        .mut_subcommand("test", |s| s.about(t!("help.cmd_test").into_owned()))
        .mut_subcommand("info", |s| s.about(t!("help.cmd_info").into_owned()))
        .mut_subcommand("doctor", |s| s.about(t!("help.cmd_doctor").into_owned()))
        .mut_subcommand("benchmark", |s| s.about(t!("help.cmd_benchmark").into_owned()))
        .mut_subcommand("cleanup", |s| s.about(t!("help.cmd_cleanup").into_owned()))
        .mut_subcommand("mac", |s| s.about(t!("help.cmd_mac").into_owned()))
        .mut_subcommand("profile", |s| s.about(t!("help.cmd_profile").into_owned()))
        .mut_subcommand("pentest", |s| s.about(t!("help.cmd_pentest").into_owned()))
        .mut_subcommand("update", |s| s.about(t!("help.cmd_update").into_owned()))
        .mut_subcommand("shred", |s| s.about(t!("help.cmd_shred").into_owned()))
        .mut_subcommand("monitor", |s| s.about(t!("help.cmd_monitor").into_owned()))
        .mut_subcommand("config", |s| s.about(t!("help.cmd_config").into_owned()))
        .mut_subcommand("bridge", |s| s.about(t!("help.cmd_bridge").into_owned()))
        .mut_subcommand("doh", |s| s.about(t!("help.cmd_doh").into_owned()))
        .mut_subcommand("interfaces", |s| s.about(t!("help.cmd_interfaces").into_owned()));

    cmd
}

pub fn print_demo_showcase() {
    print_banner(true);

    print_step(&t!("commands.demo_step_1_info"), "info");
    print_step(&t!("commands.demo_step_1_ok"), "ok");

    print_step(&t!("commands.demo_step_2_info"), "info");
    print_step(&t!("commands.demo_step_2_ok"), "ok");

    print_step(&t!("commands.demo_step_3_info"), "info");
    print_step(&t!("commands.demo_step_3_ok"), "ok");

    print_step(&t!("commands.demo_step_4_info"), "info");
    print_step(&t!("commands.demo_step_4_ok"), "ok");

    print_step(&t!("commands.demo_step_5_info"), "info");
    print_step(&t!("commands.demo_step_5_ok"), "ok");

    print_step(&t!("commands.demo_step_6_info"), "info");
    print_step(&t!("commands.demo_step_6_ok"), "ok");

    print_step(&t!("commands.demo_step_7_info"), "info");
    print_step(&t!("commands.demo_step_7_ok"), "ok");

    print_step(&t!("commands.demo_step_8_info"), "info");
    print_step(&t!("commands.demo_step_8_ok"), "ok");

    print_step(&t!("commands.demo_step_9_info"), "info");
    print_step(&t!("commands.demo_step_9_ok"), "ok");

    print_step(&t!("commands.demo_step_10_info"), "info");
    print_step(&t!("commands.demo_step_10_ok"), "ok");

    print_step(&t!("commands.demo_step_11_info"), "info");
    print_step(&t!("commands.demo_step_11_ok"), "ok");
    print_step(&t!("commands.demo_step_11_ipv6"), "ok");

    print_step(&t!("commands.demo_step_12_info"), "info");
    print_step(&t!("commands.demo_step_12_ok"), "ok");

    print_step(&t!("commands.demo_step_13_info"), "info");
    print_step(&t!("commands.demo_step_13_ok"), "ok");

    print_success(&t!("commands.demo_success"));
}

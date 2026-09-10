//! Wraith Interactive Network Interface Selector TUI
//! High-visibility interactive terminal UI for discovering, inspecting,
//! and selecting hardware adapters for sovereign network routing.

use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, CellAlignment, Color, ContentArrangement, Table};
use crossterm::cursor::{Hide, Show};
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use owo_colors::OwoColorize;
use rust_i18n::t;
use std::io::Write;
use std::time::Duration;
use wraith_core::error::{Result, WraithError};
use wraith_net::NetworkInterface;

struct TerminalGuardStderr;

impl TerminalGuardStderr {
    fn new() -> Self {
        let _ = enable_raw_mode();
        let _ = execute!(std::io::stderr(), EnterAlternateScreen, Hide);
        Self
    }
}

impl Drop for TerminalGuardStderr {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stderr(), LeaveAlternateScreen, Show);
    }
}

/// Interactive TUI for selecting an active network interface from the list of candidates
pub fn select_interface_tui(interfaces: &[NetworkInterface]) -> Result<String> {
    if interfaces.is_empty() {
        return Err(WraithError::Hardware(
            "No network interfaces available for interactive selection".to_string(),
        ));
    }

    let _guard = TerminalGuardStderr::new();
    let total = interfaces.len();
    let mut cursor: usize = 0;
    const BOX_WIDTH: usize = 88;

    loop {
        let _ = execute!(
            std::io::stderr(),
            crossterm::cursor::MoveTo(0, 0),
            crossterm::terminal::Clear(crossterm::terminal::ClearType::All)
        );

        let mut rows = Vec::new();
        rows.push(format!(
            "Controls: {} {} │ {} {} │ {} {}",
            "[↑ / ↓]".bold().white(),
            t!("interface_tui.controls_navigate"),
            "[ENTER]".bold().bright_green(),
            t!("interface_tui.controls_select"),
            "[Q / ESC]".bold().bright_red(),
            t!("interface_tui.controls_cancel")
        ));
        rows.push("─".repeat(BOX_WIDTH.saturating_sub(7)));

        for (i, iface) in interfaces.iter().enumerate() {
            let state_icon = match iface.state {
                wraith_net::InterfaceState::Up => "● UP".bold().bright_green().to_string(),
                wraith_net::InterfaceState::Down => "○ DOWN".bold().bright_red().to_string(),
                wraith_net::InterfaceState::Dormant => "◑ DORM".bold().bright_yellow().to_string(),
                wraith_net::InterfaceState::Unknown => "? UNK".dimmed().to_string(),
            };

            let kind_label = if iface.is_wireless {
                "WLAN".bold().bright_cyan().to_string()
            } else if iface.is_loopback {
                "LOOP".dimmed().to_string()
            } else if iface.is_virtual {
                "VIRT".dimmed().to_string()
            } else {
                "ETH ".bold().bright_blue().to_string()
            };

            let mac_str = iface.mac.as_deref().unwrap_or("--:--:--:--:--:--");
            let ip_str = iface.ipv4.as_deref().unwrap_or("-");

            if i == cursor {
                rows.push(format!(
                    "{} [{:<8}] {:<6} {:<18} {:<15} {}",
                    "➔".bold().bright_green(),
                    iface.name.bold().bright_white(),
                    kind_label,
                    mac_str.bold().bright_cyan(),
                    ip_str.bold().bright_yellow(),
                    state_icon
                ));
            } else {
                rows.push(format!(
                    "   [{:<8}] {:<6} {:<18} {:<15} {}",
                    iface.name.white(),
                    kind_label,
                    mac_str.dimmed(),
                    ip_str.dimmed(),
                    state_icon
                ));
            }
        }

        rows.push("─".repeat(BOX_WIDTH.saturating_sub(7)));
        let selected = &interfaces[cursor];
        rows.push(format!(
            "Target: {} (Driver: {}, MTU: {}, Speed: {})",
            selected.name.bold().bright_green(),
            selected.driver.as_deref().unwrap_or("generic").bright_cyan(),
            selected.mtu.to_string().bright_yellow(),
            selected.speed_mbps.map(|s| format!("{s} Mbps")).unwrap_or_else(|| "N/A".to_string()).white()
        ));

        let title = format!("🌐 WRAITH // {}", t!("interface_tui.title"));
        let box_lines = crate::display::render_box(
            &title,
            &rows,
            crate::display::BoxCorner::Square,
            BOX_WIDTH,
        );

        eprintln!("\r\n{}", box_lines[0].bright_cyan());
        for row in &box_lines[1..box_lines.len() - 1] {
            eprintln!("\r{row}");
        }
        if let Some(last) = box_lines.last() {
            eprintln!("\r{}", last.bright_cyan());
        }
        let _ = std::io::stderr().flush();

        if event::poll(Duration::from_millis(100)).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
                if (key.modifiers.contains(KeyModifiers::CONTROL) && (key.code == KeyCode::Char('c') || key.code == KeyCode::Char('C')))
                    || key.code == KeyCode::Char('q')
                    || key.code == KeyCode::Char('Q')
                    || key.code == KeyCode::Esc
                {
                    return Err(WraithError::Hardware(t!("interface_tui.controls_cancel").to_string()));
                }

                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        cursor = cursor.saturating_sub(1);
                    }
                    KeyCode::Down | KeyCode::Char('j') if cursor + 1 < total => {
                        cursor += 1;
                    }
                    KeyCode::Enter => {
                        return Ok(interfaces[cursor].name.clone());
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Print formatted table of network interfaces using comfy-table
pub fn print_interfaces_table(interfaces: &[NetworkInterface]) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("IDX").set_alignment(CellAlignment::Center),
            Cell::new("NAME").set_alignment(CellAlignment::Left),
            Cell::new("STATE").set_alignment(CellAlignment::Center),
            Cell::new("TYPE").set_alignment(CellAlignment::Center),
            Cell::new("MAC ADDRESS").set_alignment(CellAlignment::Left),
            Cell::new("IPv4 ADDRESS").set_alignment(CellAlignment::Left),
            Cell::new("MTU").set_alignment(CellAlignment::Right),
            Cell::new("DRIVER").set_alignment(CellAlignment::Left),
        ]);

    for iface in interfaces {
        let state_cell = match iface.state {
            wraith_net::InterfaceState::Up => Cell::new("UP").fg(Color::Green),
            wraith_net::InterfaceState::Down => Cell::new("DOWN").fg(Color::Red),
            wraith_net::InterfaceState::Dormant => Cell::new("DORMANT").fg(Color::Yellow),
            wraith_net::InterfaceState::Unknown => Cell::new("UNKNOWN").fg(Color::DarkGrey),
        };

        let type_str = if iface.is_loopback {
            "LOOPBACK"
        } else if iface.is_wireless {
            "WIRELESS"
        } else if iface.is_virtual {
            "VIRTUAL"
        } else {
            "ETHERNET"
        };

        let type_color = if iface.is_wireless {
            Color::Cyan
        } else if iface.is_virtual || iface.is_loopback {
            Color::DarkGrey
        } else {
            Color::Blue
        };

        table.add_row(vec![
            Cell::new(iface.index).set_alignment(CellAlignment::Center),
            Cell::new(&iface.name).fg(Color::White),
            state_cell.set_alignment(CellAlignment::Center),
            Cell::new(type_str).fg(type_color).set_alignment(CellAlignment::Center),
            Cell::new(iface.mac.as_deref().unwrap_or("-")),
            Cell::new(iface.ipv4.as_deref().unwrap_or("-")),
            Cell::new(iface.mtu).set_alignment(CellAlignment::Right),
            Cell::new(iface.driver.as_deref().unwrap_or("unknown")),
        ]);
    }

    println!("{table}");
}

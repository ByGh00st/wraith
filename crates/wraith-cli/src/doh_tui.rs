//! Wraith Interactive DNS-over-HTTPS (DoH) Provider Selector TUI
//! High-visibility interactive terminal UI for selecting curated privacy DoH resolvers
//! or configuring user-defined RFC 8484 custom encrypted endpoints.

use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, CellAlignment, Color, ContentArrangement, Table};
use crossterm::cursor::{Hide, Show};
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use owo_colors::OwoColorize;
use rust_i18n::t;
use std::io::{stdin, stdout, Write};
use std::time::Duration;
use wraith_core::error::{Result, WraithError};
use wraith_guard::{DohProvider, DOH_PRESETS};

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

/// Interactive TUI for selecting a DoH provider or entering a custom URL
pub fn select_doh_tui() -> Result<DohProvider> {
    let presets = DOH_PRESETS;
    // Items: all presets + 1 for Custom option
    let total = presets.len() + 1;
    let mut cursor: usize = 0;
    const BOX_WIDTH: usize = 94;

    loop {
        // Run inner raw-mode loop
        let selected_index = {
            let _guard = TerminalGuardStderr::new();

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
                    t!("doh_tui.controls_navigate"),
                    "[ENTER]".bold().bright_green(),
                    t!("doh_tui.controls_select"),
                    "[Q / ESC]".bold().bright_red(),
                    t!("doh_tui.controls_cancel")
                ));
                rows.push("─".repeat(BOX_WIDTH.saturating_sub(7)));

                for i in 0..total {
                    if i < presets.len() {
                        let p = &presets[i];
                        if i == cursor {
                            rows.push(format!(
                                "{} [{:<12}] {:<32} {}",
                                "➔".bold().bright_green(),
                                p.key.bold().bright_white(),
                                p.name.bold().bright_cyan(),
                                p.jurisdiction.bold().bright_yellow()
                            ));
                        } else {
                            rows.push(format!(
                                "   [{:<12}] {:<32} {}",
                                p.key.dimmed(),
                                p.name.white(),
                                p.jurisdiction.dimmed()
                            ));
                        }
                    } else {
                        // Custom entry
                        if i == cursor {
                            rows.push(format!(
                                "{} [{:<12}] {:<32} {}",
                                "➔".bold().bright_green(),
                                "custom".bold().bright_white(),
                                format!("✏️  {}", t!("doh_tui.custom_label")).bold().bright_magenta(),
                                t!("doh_tui.custom_jurisdiction").bold().bright_yellow()
                            ));
                        } else {
                            rows.push(format!(
                                "   [{:<12}] {:<32} {}",
                                "custom".dimmed(),
                                format!("✏️  {}", t!("doh_tui.custom_label")).white(),
                                t!("doh_tui.custom_jurisdiction").dimmed()
                            ));
                        }
                    }
                }

                rows.push("─".repeat(BOX_WIDTH.saturating_sub(7)));

                // Hovered item details card
                if cursor < presets.len() {
                    let p = &presets[cursor];
                    rows.push(format!("{} {}", t!("doh_tui.endpoint_label"), p.url.bold().bright_cyan()));
                    rows.push(format!("{} {}", t!("doh_tui.description_label"), p.description.white()));
                    rows.push(format!("{} {}", t!("doh_tui.attributes_label"), p.features.bold().bright_green()));
                } else {
                    rows.push(format!("{} {}", t!("doh_tui.endpoint_label"), t!("doh_tui.custom_endpoint_hint").bold().bright_cyan()));
                    rows.push(format!("{} {}", t!("doh_tui.description_label"), t!("doh_tui.custom_description").white()));
                    rows.push(format!("{} {}", t!("doh_tui.attributes_label"), t!("doh_tui.custom_attributes").bold().bright_green()));
                }

                // Render framed box
                let title = format!("🛡️ WRAITH-PRIME // {}", t!("doh_tui.title"));
                let top_border_len = BOX_WIDTH.saturating_sub(title.len() + 6);
                let _ = writeln!(
                    std::io::stderr(),
                    "┌─ [ {} ] {}┐",
                    title.bold().bright_cyan(),
                    "─".repeat(top_border_len)
                );

                for row in rows {
                    let _ = writeln!(std::io::stderr(), "│  {:<90}│", row);
                }

                let _ = writeln!(std::io::stderr(), "└{}┘", "─".repeat(BOX_WIDTH.saturating_sub(2)));
                let _ = std::io::stderr().flush();

                if event::poll(Duration::from_millis(150)).unwrap_or(false) {
                    if let Ok(Event::Key(key)) = event::read() {
                        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                            return Err(WraithError::Custom(t!("doh_tui.selection_aborted").to_string()));
                        }

                        match key.code {
                            KeyCode::Up | KeyCode::Char('k') => {
                                cursor = if cursor == 0 { total - 1 } else { cursor - 1 };
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                cursor = (cursor + 1) % total;
                            }
                            KeyCode::Enter => {
                                break cursor;
                            }
                            KeyCode::Esc | KeyCode::Char('q') => {
                                return Err(WraithError::Custom(t!("doh_tui.selection_cancelled").to_string()));
                            }
                            _ => {}
                        }
                    }
                }
            }
        };

        if selected_index < presets.len() {
            return Ok(DohProvider::Preset(&presets[selected_index]));
        } else {
            // Prompt for custom URL
            println!();
            print!("  \x1b[1;36m{} \x1b[0m", t!("doh_tui.prompt_custom_url"));
            let _ = stdout().flush();

            let mut input = String::new();
            if stdin().read_line(&mut input).is_ok() {
                let trimmed = input.trim();
                if trimmed.is_empty() {
                    continue;
                }
                match DohProvider::parse_input(trimmed) {
                    Ok(provider) => return Ok(provider),
                    Err(e) => {
                        eprintln!("  \x1b[1;31mError: {}\x1b[0m\n", e);
                        std::thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                }
            }
        }
    }
}

/// Print formatted table of all available DoH resolver presets
pub fn print_doh_table() {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Key").set_alignment(CellAlignment::Left).fg(Color::Cyan),
            Cell::new("Provider Name").set_alignment(CellAlignment::Left).fg(Color::White),
            Cell::new("Jurisdiction").set_alignment(CellAlignment::Left).fg(Color::Yellow),
            Cell::new("Attributes & Features").set_alignment(CellAlignment::Left).fg(Color::Green),
            Cell::new("RFC 8484 Endpoint").set_alignment(CellAlignment::Left).fg(Color::DarkCyan),
        ]);

    for p in DOH_PRESETS {
        table.add_row(vec![
            Cell::new(p.key).fg(Color::Cyan),
            Cell::new(p.name).fg(Color::White),
            Cell::new(p.jurisdiction).fg(Color::Yellow),
            Cell::new(p.features).fg(Color::Green),
            Cell::new(p.url).fg(Color::DarkCyan),
        ]);
    }

    println!("\n  \x1b[1;36m{}\x1b[0m\n", t!("commands.doh_matrix_title"));
    println!("{table}\n");
}

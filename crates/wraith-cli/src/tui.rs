//! Wraith Real-Time Telemetry Dashboard (TUI)
//! Live multi-pane monitoring console with interactive hotkeys, circuit maps, and IDS feeds.

use crossterm::cursor::{Hide, Show};
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use owo_colors::OwoColorize;
use std::io::stdout;
use std::time::Duration;
use tokio::time::sleep;
use rust_i18n::t;
use wraith_core::error::Result;
use wraith_core::state::StateManager;
use wraith_guard::verify_tor_connection;
use wraith_tor::{get_circuit_telemetry, TorControlClient};

pub struct SovereignDashboard {
    running: bool,
}

impl Default for SovereignDashboard {
    fn default() -> Self {
        Self::new()
    }
}

impl SovereignDashboard {
    pub fn new() -> Self {
        Self { running: true }
    }

    pub async fn run(&mut self) -> Result<()> {
        let mut stdout_handle = stdout();
        let _ = enable_raw_mode();
        let _ = execute!(stdout_handle, EnterAlternateScreen, Hide);

        let state_mgr = StateManager::default();

        while self.running {
            let state_data = state_mgr.read();
            let (is_tor, tor_ip) = verify_tor_connection().await;
            let ip_display = tor_ip.unwrap_or_else(|| "127.0.0.1 (Tor TransProxy)".into());
            let telemetry = match get_circuit_telemetry().await {
                Ok(t) => t,
                Err(e) => {
                    tracing::debug!("TUI dashboard could not fetch circuit telemetry: {e}");
                    wraith_tor::TorTelemetry::default()
                }
            };

            let is_strict = state_data.namespace_active && state_data.tcp_stack_masked;

            // Clear screen
            print!("\x1B[2J\x1B[1;1H");

            // 1. Header Pane
            if is_strict {
                println!(" {}", "══════════════════════════════════════════════════════════════════════════════════════════".bold().red());
                println!("  {}  {} | {} | {}",
                    "⚡ WRAITH".bold().red(),
                    t!("tui.header_strict").bold().red(),
                    format!("{} {}", t!("tui.pid"), std::process::id()).dimmed(),
                    t!("tui.armed_strict").bold().red()
                );
                println!(" {}", "══════════════════════════════════════════════════════════════════════════════════════════".bold().red());
            } else {
                println!(" {}", "══════════════════════════════════════════════════════════════════════════════════════════".bold().purple());
                println!("  {}  {} | {} | {}",
                    "⚡ WRAITH".bold().purple(),
                    t!("tui.header_normal").bold().cyan(),
                    format!("{} {}", t!("tui.pid"), std::process::id()).dimmed(),
                    t!("tui.armed_normal").bold().green()
                );
                println!(" {}", "══════════════════════════════════════════════════════════════════════════════════════════".bold().purple());
            }

            // 2. Identity & Routing Grid
            let id_rows = vec![
                format!("{:<20} : {}", t!("tui.public_ip"), ip_display.bold().white()),
                format!("{:<20} : {}", t!("tui.tor_network"), if is_tor { t!("tui.verified").bold().green().to_string() } else { t!("tui.unverified").bold().red().to_string() }),
                format!("{:<20} : {}", t!("tui.hardware_mac"), state_data.mac_new.as_deref().unwrap_or(&*t!("tui.static")).bold().magenta()),
                format!("{:<20} : {}", t!("tui.machine_id"), if state_data.machine_id_old.is_some() { t!("tui.rotated").bold().green().to_string() } else { t!("tui.original").dimmed().to_string() }),
                format!("{:<20} : {}", t!("tui.tcp_stack"), if state_data.tcp_stack_masked { t!("tui.win_profile").bold().green().to_string() } else { t!("tui.linux_std").dimmed().to_string() }),
                format!("{:<20} : {}", t!("tui.exit_policy"), state_data.exit_profile.as_deref().unwrap_or(&*t!("tui.stealth")).bold().blue()),
                format!("{:<20} : {}", "Multi-Hop Tunnel", if state_data.multihop_enabled { "ACTIVE (WireGuard ➔ Tor [3 Hops])".bold().green().to_string() } else { "OFF (Standard Tor Onion)".dimmed().to_string() }),
            ];
            let id_box = crate::display::render_box(&t!("tui.identity_box"), &id_rows, crate::display::BoxCorner::Square, 92);
            println!("\n{}", id_box[0].bright_cyan());
            for row in &id_box[1..id_box.len() - 1] {
                println!("{row}");
            }
            println!("{}", id_box.last().unwrap().bright_cyan());

            // 3. Multi-Layer Defense Matrix
            let def_rows = vec![
                t!("tui.def_netfilter").into_owned(),
                t!("tui.def_seccomp").into_owned(),
                t!("tui.def_ebpf").into_owned(),
                t!("tui.def_lockdown").into_owned(),
                t!("tui.def_dns").into_owned(),
                t!("tui.def_tls").into_owned(),
                t!("tui.def_ramfs").into_owned(),
                t!("tui.def_ids").into_owned(),
            ];
            let def_box = crate::display::render_box(&t!("tui.defense_matrix"), &def_rows, crate::display::BoxCorner::Square, 92);
            println!("\n{}", def_box[0].bright_yellow());
            for row in &def_box[1..def_box.len() - 1] {
                println!("{row}");
            }
            println!("{}", def_box.last().unwrap().bright_yellow());

            // 4. Active Tor Circuit Map
            let circ_rows = if telemetry.circuits.is_empty() {
                vec![t!("tui.syncing").into_owned()]
            } else {
                telemetry.circuits.iter().take(4).map(|circ| {
                    let path = circ.path.join(" ➔ ");
                    format!("Circuit #{:<3} [{:<7}] : {}", circ.id.bold().yellow(), circ.purpose.dimmed(), path.bold().green())
                }).collect()
            };
            let circ_box = crate::display::render_box(&t!("tui.circuits_box"), &circ_rows, crate::display::BoxCorner::Square, 92);
            println!("\n{}", circ_box[0].bright_green());
            for row in &circ_box[1..circ_box.len() - 1] {
                println!("{row}");
            }
            println!("{}", circ_box.last().unwrap().bright_green());

            // 5. Bandwidth Stats
            println!(
                "  {} Tor v{} | ↓ Ingress: {:.2} MB | ↑ Egress: {:.2} MB\n",
                "[BANDWIDTH]".dimmed(),
                telemetry.version,
                telemetry.bytes_read as f64 / (1024.0 * 1024.0),
                telemetry.bytes_written as f64 / (1024.0 * 1024.0)
            );

            // 6. Interactive Hotkeys Footer
            println!("  {}\n", t!("tui.hotkeys"));

            // Non-blocking key check for 1 second
            if event::poll(Duration::from_millis(1000)).unwrap_or(false) {
                if let Ok(Event::Key(key)) = event::read() {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') => {
                            self.running = false;
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Char('r') | KeyCode::Char('R') => {
                            let mut client = TorControlClient::default();
                            if client.connect().await.is_ok() {
                                let _ = client.signal_newnym().await;
                            }
                        }
                        KeyCode::Char('c') | KeyCode::Char('C') => {
                            let _ = wraith_forensic::run_full_cleanup(true, false);
                        }
                        _ => {}
                    }
                }
            } else {
                sleep(Duration::from_millis(50)).await;
            }
        }

        let _ = disable_raw_mode();
        let _ = execute!(stdout_handle, LeaveAlternateScreen, Show);
        Ok(())
    }
}

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
            println!("\n  {}", t!("tui.identity_box"));
            println!("  │  {:<20} : {:<60} │", t!("tui.public_ip"), ip_display.bold().white());
            println!("  │  {:<20} : {:<60} │", t!("tui.tor_network"), if is_tor { t!("tui.verified").bold().green().to_string() } else { t!("tui.unverified").bold().red().to_string() });
            println!("  │  {:<20} : {:<60} │", t!("tui.hardware_mac"), state_data.mac_new.as_deref().unwrap_or(&*t!("tui.static")).bold().magenta());
            println!("  │  {:<20} : {:<60} │", t!("tui.machine_id"), if state_data.machine_id_old.is_some() { t!("tui.rotated").bold().green().to_string() } else { t!("tui.original").dimmed().to_string() });
            println!("  │  {:<20} : {:<60} │", t!("tui.tcp_stack"), if state_data.tcp_stack_masked { t!("tui.win_profile").bold().green().to_string() } else { t!("tui.linux_std").dimmed().to_string() });
            println!("  │  {:<20} : {:<60} │", t!("tui.exit_policy"), state_data.exit_profile.as_deref().unwrap_or(&*t!("tui.stealth")).bold().blue());
            println!("  │  {:<20} : {:<60} │", "Multi-Hop Tunnel", if state_data.multihop_enabled { "ACTIVE (WireGuard ➔ Tor [3 Hops])".bold().green().to_string() } else { "OFF (Standard Tor Onion)".dimmed().to_string() });
            println!("  └────────────────────────────────────────────────────────────────────────────────────────┘");

            // 3. Multi-Layer Defense Matrix
            println!("\n  {}", t!("tui.defense_matrix"));
            println!("  │  {:<91} │", t!("tui.def_netfilter"));
            println!("  │  {:<91} │", t!("tui.def_seccomp"));
            println!("  │  {:<91} │", t!("tui.def_ebpf"));
            println!("  │  {:<91} │", t!("tui.def_lockdown"));
            println!("  │  {:<91} │", t!("tui.def_dns"));
            println!("  │  {:<91} │", t!("tui.def_tls"));
            println!("  │  {:<91} │", t!("tui.def_ramfs"));
            println!("  │  {:<91} │", t!("tui.def_ids"));
            println!("  └────────────────────────────────────────────────────────────────────────────────────────┘");

            // 4. Active Tor Circuit Map
            println!("\n  {}", t!("tui.circuits_box"));
            if telemetry.circuits.is_empty() {
                println!("  │  {:<91} │", t!("tui.syncing"));
            } else {
                for circ in telemetry.circuits.iter().take(4) {
                    let path = circ.path.join(" ➔ ");
                    println!("  │  Circuit #{:<3} [{:<7}] : {:<54} │", circ.id.bold().yellow(), circ.purpose.dimmed(), path.bold().green());
                }
            }
            println!("  └────────────────────────────────────────────────────────────────────────────────────────┘");

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

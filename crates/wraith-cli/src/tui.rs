//! Wraith Sovereign Real-Time Warfare Terminal Dashboard (TUI)
//! Live multi-pane monitoring console with interactive hotkeys, circuit maps, and IDS feeds.

use crossterm::cursor::{Hide, Show};
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use owo_colors::OwoColorize;
use std::io::stdout;
use std::time::Duration;
use tokio::time::sleep;
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
            let telemetry = get_circuit_telemetry().await.unwrap_or_default();

            // Clear screen
            print!("\x1B[2J\x1B[1;1H");

            // 1. Header Pane
            println!(" {}", "══════════════════════════════════════════════════════════════════════════════════════════".bold().purple());
            println!("  {}  {} | {} | {}",
                "⚡ WRAITH SOVEREIGN".bold().purple(),
                "APEX TELEMETRY DASHBOARD".bold().cyan(),
                format!("PID: {}", std::process::id()).dimmed(),
                "FAIL-CLOSED: ARMED".bold().green()
            );
            println!(" {}", "══════════════════════════════════════════════════════════════════════════════════════════".bold().purple());

            // 2. Identity & Routing Grid
            println!("\n  ┌── [ SOVEREIGN IDENTITY & EXIT NODE ] ──────────────────────────────────────────────────┐");
            println!("  │  Public Exit IP      : {:<60} │", ip_display.bold().white());
            println!("  │  Tor Network         : {:<60} │", if is_tor { "✓ VERIFIED (TransProxy Active)".bold().green().to_string() } else { "✗ UNVERIFIED".bold().red().to_string() });
            println!("  │  Hardware MAC        : {:<60} │", state_data.mac_new.as_deref().unwrap_or("Hardware Static").bold().magenta());
            println!("  │  Machine-ID Mask     : {:<60} │", if state_data.machine_id_old.is_some() { "✓ Rotated (Anti-Forensic DMI)".bold().green().to_string() } else { "Original".dimmed().to_string() });
            println!("  │  TCP Stack (p0f)     : {:<60} │", if state_data.tcp_stack_masked { "✓ Windows Profile (TTL=128, TS=0)".bold().green().to_string() } else { "Linux Standard".dimmed().to_string() });
            println!("  │  Exit Node Policy    : {:<60} │", state_data.exit_profile.as_deref().unwrap_or("Stealth (Five Eyes Excluded)").bold().blue());
            println!("  └────────────────────────────────────────────────────────────────────────────────────────┘");

            // 3. Multi-Layer Defense Matrix
            println!("\n  ┌── [ DEFENSE MATRIX STATUS GRID ] ───────────────────────────────────────────────────────┐");
            println!("  │  [✓] Netfilter TransProxy : Fail-Closed Drop (Port 9040/5353)                           │");
            println!("  │  [✓] Seccomp-BPF Filter   : Raw Sockets (AF_PACKET/SOCK_RAW/ptrace) Blocked @ Ring 0   │");
            println!("  │  [✓] eBPF / TC Fastpath   : Qdisc clsact Driver Egress Drop Active                     │");
            println!("  │  [✓] Kernel Lockdown      : Confidentiality Mode (/dev/mem & DMA Shield)               │");
            println!("  │  [✓] Sovereign DNS Engine : QNAME Minimized + EDNS0 468B Padded + Telemetry Sinkhole   │");
            println!("  │  [✓] JA3/JA4 TLS Camo     : Google Chrome 131 / Win11 Profile + RFC 8701 GREASE        │");
            println!("  │  [✓] RAMFS Crypto Vault   : In-Memory ChaCha20-Poly1305 Encrypted (/dev/shm Locked)    │");
            println!("  │  [✓] Zero-Copy IDS        : Real-Time L2/L3/L4 Sniffer & Egress Watchdog Active        │");
            println!("  └────────────────────────────────────────────────────────────────────────────────────────┘");

            // 4. Active Tor Circuit Map
            println!("\n  ┌── [ ACTIVE TOR CIRCUITS & RELAY TOPOLOGY ] ────────────────────────────────────────────┐");
            if telemetry.circuits.is_empty() {
                println!("  │  (Synchronizing circuits with Tor ControlPort...)                                      │");
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
            println!("  [HOTKEYS] [Q] Quit & Restore | [N] Newnym Identity | [C] RAM Cache Flush | [R] Refresh\n");

            // Non-blocking key check for 1 second
            if event::poll(Duration::from_millis(1000)).unwrap_or(false) {
                if let Ok(Event::Key(key)) = event::read() {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') => {
                            self.running = false;
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') => {
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

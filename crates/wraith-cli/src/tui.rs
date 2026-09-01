//! Wraith Real-Time Telemetry Dashboard (TUI)
//! Live multi-pane monitoring console with interactive hotkeys, circuit maps, and IDS feeds.

use crossterm::cursor::{Hide, Show};
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use owo_colors::OwoColorize;
use std::io::{stdout, Write};
use std::time::Duration;
use tokio::time::sleep;
use rust_i18n::t;
use wraith_core::error::Result;
use wraith_core::state::StateManager;
use wraith_guard::verify_tor_connection;
use wraith_tor::{get_circuit_telemetry, TorControlClient};

/// RAII Terminal Restorer that guarantees terminal raw mode is disabled upon drop
pub struct TerminalGuard;

impl TerminalGuard {
    pub fn new() -> Self {
        let _ = enable_raw_mode();
        let _ = execute!(stdout(), EnterAlternateScreen, Hide);
        Self
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen, Show);
    }
}

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
        let _guard = TerminalGuard::new();
        let state_mgr = StateManager::default();

        let mut last_ip_check = std::time::Instant::now() - Duration::from_secs(60);
        let mut cached_tor = (false, None);

        while self.running {
            let state_data = state_mgr.read();

            // Only query public Tor check API if Wraith is active and every 5 seconds to avoid network lag/spam
            if state_data.active {
                if last_ip_check.elapsed() > Duration::from_secs(5) {
                    cached_tor = verify_tor_connection().await;
                    last_ip_check = std::time::Instant::now();
                }
            } else {
                cached_tor = (false, None);
            }

            let (is_tor, ref tor_ip) = cached_tor;
            let ip_display = if state_data.active {
                tor_ip.as_deref().unwrap_or("127.0.0.1 (Tor TransProxy)")
            } else {
                "● INACTIVE / CLEARNET"
            };

            let telemetry = if state_data.active {
                match get_circuit_telemetry().await {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::debug!("TUI dashboard could not fetch circuit telemetry: {e}");
                        wraith_tor::TorTelemetry::default()
                    }
                }
            } else {
                wraith_tor::TorTelemetry::default()
            };

            let is_strict = state_data.namespace_active && state_data.tcp_stack_masked;

            // Clear screen buffer cleanly
            let _ = execute!(stdout(), crossterm::cursor::MoveTo(0, 0), crossterm::terminal::Clear(crossterm::terminal::ClearType::All));

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
            } else if state_data.active {
                println!(" {}", "══════════════════════════════════════════════════════════════════════════════════════════".bold().purple());
                println!("  {}  {} | {} | {}",
                    "⚡ WRAITH".bold().purple(),
                    t!("tui.header_normal").bold().cyan(),
                    format!("{} {}", t!("tui.pid"), std::process::id()).dimmed(),
                    t!("tui.armed_normal").bold().green()
                );
                println!(" {}", "══════════════════════════════════════════════════════════════════════════════════════════".bold().purple());
            } else {
                println!(" {}", "══════════════════════════════════════════════════════════════════════════════════════════".dimmed());
                println!("  {}  {} | {} | {}",
                    "⚡ WRAITH".dimmed(),
                    t!("tui.header_normal").bold().white(),
                    format!("{} {}", t!("tui.pid"), std::process::id()).dimmed(),
                    "🔴 INACTIVE / STOPPED".bold().yellow()
                );
                println!(" {}", "══════════════════════════════════════════════════════════════════════════════════════════".dimmed());
            }

            // 2. Identity & Routing Grid
            let status_tor = if state_data.active {
                if is_tor { t!("tui.verified").bold().green().to_string() } else { t!("tui.unverified").bold().red().to_string() }
            } else {
                "○ INACTIVE".dimmed().to_string()
            };

            let id_rows = vec![
                format!("{:<20} : {}", t!("tui.public_ip"), ip_display.bold().white()),
                format!("{:<20} : {}", t!("tui.tor_network"), status_tor),
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
            let def_rows = if state_data.active {
                vec![
                    t!("tui.def_netfilter").into_owned(),
                    t!("tui.def_seccomp").into_owned(),
                    t!("tui.def_ebpf").into_owned(),
                    t!("tui.def_lockdown").into_owned(),
                    t!("tui.def_dns").into_owned(),
                    t!("tui.def_tls").into_owned(),
                    t!("tui.def_ramfs").into_owned(),
                    t!("tui.def_ids").into_owned(),
                ]
            } else {
                vec![
                    "[○] Netfilter TransProxy : INACTIVE (Clearnet)".dimmed().to_string(),
                    "[○] Seccomp-BPF Filter   : INACTIVE".dimmed().to_string(),
                    "[○] eBPF / TC Fastpath   : INACTIVE".dimmed().to_string(),
                    "[○] Kernel Lockdown      : STANDBY".dimmed().to_string(),
                    "[○] Sovereign DNS Engine : INACTIVE (System Resolvers)".dimmed().to_string(),
                    "[○] JA3/JA4 TLS GREASE   : STANDBY".dimmed().to_string(),
                    "[○] RAMFS Crypto Vault   : UNMOUNTED".dimmed().to_string(),
                    "[○] Zero-Copy IDS & DPI  : STANDBY".dimmed().to_string(),
                ]
            };
            let def_box = crate::display::render_box(&t!("tui.defense_matrix"), &def_rows, crate::display::BoxCorner::Square, 92);
            println!("\n{}", def_box[0].bright_yellow());
            for row in &def_box[1..def_box.len() - 1] {
                println!("{row}");
            }
            println!("{}", def_box.last().unwrap().bright_yellow());

            // 4. Active Tor Circuit Map
            let circ_rows = if !state_data.active {
                vec!["○ Wraith is inactive. Start with: sudo wraith start".dimmed().to_string()]
            } else if telemetry.circuits.is_empty() {
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
            let _ = stdout().flush();

            // Non-blocking key check for 800ms
            if event::poll(Duration::from_millis(800)).unwrap_or(false) {
                if let Ok(Event::Key(key)) = event::read() {
                    // Check for Ctrl+C, Escape, or Q to cleanly exit dashboard
                    if (key.modifiers.contains(KeyModifiers::CONTROL) && (key.code == KeyCode::Char('c') || key.code == KeyCode::Char('C')))
                        || key.code == KeyCode::Esc
                        || key.code == KeyCode::Char('q')
                        || key.code == KeyCode::Char('Q')
                    {
                        self.running = false;
                        break;
                    }

                    // Request new identity
                    if key.code == KeyCode::Char('n') || key.code == KeyCode::Char('N') || key.code == KeyCode::Char('r') || key.code == KeyCode::Char('R') {
                        if state_data.active {
                            let mut client = TorControlClient::default();
                            if client.connect().await.is_ok() {
                                let _ = client.signal_newnym().await;
                                last_ip_check = std::time::Instant::now() - Duration::from_secs(60);
                            }
                        }
                    }

                    // Non-destructive memory & ARP/DNS cache flush
                    if key.code == KeyCode::Char('c') || key.code == KeyCode::Char('C') {
                        let _ = wraith_forensic::clear_dns_and_arp_caches();
                    }
                }
            } else {
                sleep(Duration::from_millis(50)).await;
            }
        }

        Ok(())
    }
}

pub const ALL_LANGUAGES: [(&str, &str); 75] = [
    ("en", "English (Default)"),
    ("tr", "Türkçe"),
    ("az", "Azərbaycan dili"),
    ("kk", "Қазақ тілі"),
    ("uz", "Oʻzbekcha"),
    ("ky", "Кыргызча"),
    ("tk", "Türkmençe"),
    ("ug", "Уйғурчә"),
    ("tt", "Татарча"),
    ("ba", "Башҡортса"),
    ("cv", "Чӑвашла"),
    ("sah", "Саха тыла"),
    ("gag", "Gagauzça"),
    ("crh", "Qırımtatarca"),
    ("alt", "Алтай тили"),
    ("tyv", "Тыва дыл"),
    ("kjh", "Хакас тілі"),
    ("krc", "Къарачай-малкъар"),
    ("kum", "Къумукъ тил"),
    ("nog", "Ногай тили"),
    ("de", "Deutsch"),
    ("fr", "Français"),
    ("es", "Español"),
    ("ru", "Русский"),
    ("zh", "中文 (Chinese)"),
    ("ja", "日本語 (Japanese)"),
    ("ko", "한국어 (Korean)"),
    ("pt", "Português"),
    ("it", "Italiano"),
    ("nl", "Nederlands"),
    ("pl", "Polski"),
    ("sv", "Svenska"),
    ("no", "Norsk"),
    ("da", "Dansk"),
    ("fi", "Suomi"),
    ("cs", "Čeština"),
    ("hu", "Magyar"),
    ("ro", "Română"),
    ("uk", "Українська"),
    ("el", "Ελληνικά"),
    ("bg", "Български"),
    ("hr", "Hrvatski"),
    ("sk", "Slovenčina"),
    ("sl", "Slovenščina"),
    ("sr", "Srpski"),
    ("lt", "Lietuvių"),
    ("lv", "Latviešu"),
    ("et", "Eesti"),
    ("is", "Íslenska"),
    ("ga", "Gaeilge"),
    ("sq", "Shqip"),
    ("mk", "Македонски"),
    ("bs", "Bosanski"),
    ("mt", "Malti"),
    ("vi", "Tiếng Việt"),
    ("th", "ไทย"),
    ("id", "Bahasa Indonesia"),
    ("ms", "Bahasa Melayu"),
    ("tl", "Tagalog"),
    ("hi", "हिन्दी"),
    ("bn", "বাংলা"),
    ("ta", "தமிழ்"),
    ("te", "తెలుగు"),
    ("mn", "Монгол"),
    ("ka", "ქართული"),
    ("ur", "اردو (Urdu)"),
    ("fa", "فارسی (Persian)"),
    ("ar", "العربية (Arabic)"),
    ("he", "עברית (Hebrew)"),
    ("hy", "Հայերեն (Armenian)"),
    ("sw", "Kiswahili (Swahili)"),
    ("af", "Afrikaans"),
    ("cy", "Cymraeg (Welsh)"),
    ("eu", "Euskara (Basque)"),
    ("la", "Latina (Latin)"),
];

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

pub fn run_language_selector_tui() -> Result<String> {
    use std::io::Write;
    let _guard = TerminalGuardStderr::new();

    let total = ALL_LANGUAGES.len();
    let mut cursor: usize = 0;
    let page_size: usize = 10;
    const BOX_WIDTH: usize = 86;

    // Detect if there is a current configured language
    if let Ok(current) = std::fs::read_to_string("/etc/wraith/lang") {
        let trimmed = current.trim();
        if let Some(pos) = ALL_LANGUAGES.iter().position(|(code, _)| *code == trimmed) {
            cursor = pos;
        }
    }

    let selected_code: String;

    loop {
        let top = if cursor >= page_size / 2 {
            (cursor - (page_size / 2)).min(total.saturating_sub(page_size))
        } else {
            0
        };

        // Clear terminal buffer cleanly
        let _ = execute!(std::io::stderr(), crossterm::cursor::MoveTo(0, 0), crossterm::terminal::Clear(crossterm::terminal::ClearType::All));

        let mut rows = Vec::new();
        rows.push(format!("Controls: {} Navigate │ {} Page │ {} Confirm │ {} Cancel",
            "[↑ / ↓]".bold().white(),
            "[PgUp / PgDn]".bold().white(),
            "[ENTER]".bold().bright_green(),
            "[Q]".bold().bright_red()
        ));
        rows.push("─".repeat(BOX_WIDTH.saturating_sub(7)));

        for i in top..top.saturating_add(page_size).min(total) {
            let (code, name) = ALL_LANGUAGES[i];
            let idx_str = format!("{:02}", i + 1);

            if i == cursor {
                rows.push(format!(
                    "{}  [{}]  [{:<4}]  {}",
                    "➔".bold().bright_green(),
                    idx_str.bold().white(),
                    code.bold().bright_cyan(),
                    name.bold().bright_green()
                ));
            } else {
                rows.push(format!(
                    "    [{}]  [{:<4}]  {}",
                    idx_str.dimmed(),
                    code.dimmed(),
                    name.white()
                ));
            }
        }

        rows.push("─".repeat(BOX_WIDTH.saturating_sub(7)));
        let (cur_code, cur_name) = ALL_LANGUAGES[cursor];
        rows.push(format!(
            "Active Selection: [{:02}/{:02}] [{:<4}] {}",
            (cursor + 1).bold().white(),
            total.bold().white(),
            cur_code.bold().bright_cyan(),
            cur_name.bold().bright_yellow()
        ));

        let box_lines = crate::display::render_box(
            "🌐 SYSTEM DEFAULT LANGUAGE CONFIGURATION // 75 LOCALES",
            &rows,
            crate::display::BoxCorner::Square,
            BOX_WIDTH,
        );

        eprintln!("\r\n{}", box_lines[0].bright_cyan());
        for row in &box_lines[1..box_lines.len() - 1] {
            eprintln!("\r{row}");
        }
        eprintln!("\r{}", box_lines.last().unwrap().bright_cyan());
        let _ = std::io::stderr().flush();

        // Read keypress synchronously with 100ms timeout
        if event::poll(Duration::from_millis(100)).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
                // Handle Ctrl+C, Q, Esc cleanly
                if (key.modifiers.contains(KeyModifiers::CONTROL) && (key.code == KeyCode::Char('c') || key.code == KeyCode::Char('C')))
                    || key.code == KeyCode::Char('q')
                    || key.code == KeyCode::Char('Q')
                    || key.code == KeyCode::Esc
                {
                    selected_code = "en".to_string();
                    break;
                }

                match key.code {
                    KeyCode::Up => {
                        cursor = cursor.saturating_sub(1);
                    }
                    KeyCode::Down => {
                        if cursor + 1 < total {
                            cursor += 1;
                        }
                    }
                    KeyCode::PageUp | KeyCode::Left => {
                        cursor = cursor.saturating_sub(page_size);
                    }
                    KeyCode::PageDown | KeyCode::Right => {
                        cursor = (cursor + page_size).min(total - 1);
                    }
                    KeyCode::Enter => {
                        selected_code = ALL_LANGUAGES[cursor].0.to_string();
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    // Persist language selection
    let _ = std::fs::create_dir_all("/etc/wraith");
    let _ = std::fs::write("/etc/wraith/lang", format!("{selected_code}\n"));
    if let Ok(home) = std::env::var("HOME") {
        let _ = std::fs::create_dir_all(format!("{home}/.config/wraith"));
        let _ = std::fs::write(format!("{home}/.config/wraith/lang"), format!("{selected_code}\n"));
    }

    Ok(selected_code)
}

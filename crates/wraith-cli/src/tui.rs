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

pub const ALL_LANGUAGES: [(&str, &str); 65] = [
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
];

pub fn run_language_selector_tui() -> Result<String> {
    use std::io::{stdout, Write};
    let mut stdout_handle = stdout();
    let _ = enable_raw_mode();
    let _ = execute!(stdout_handle, EnterAlternateScreen, Hide);

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
        let _ = execute!(stdout_handle, crossterm::cursor::MoveTo(0, 0), crossterm::terminal::Clear(crossterm::terminal::ClearType::All));

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
            "🌐 SYSTEM DEFAULT LANGUAGE CONFIGURATION // 65 LOCALES",
            &rows,
            crate::display::BoxCorner::Square,
            BOX_WIDTH,
        );

        println!("\r\n{}", box_lines[0].bright_cyan());
        for row in &box_lines[1..box_lines.len() - 1] {
            println!("\r{row}");
        }
        println!("\r{}", box_lines.last().unwrap().bright_cyan());
        let _ = stdout_handle.flush();

        // Read keypress synchronously with 100ms timeout
        if event::poll(Duration::from_millis(100)).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
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
                    KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                        selected_code = "en".to_string();
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    let _ = disable_raw_mode();
    let _ = execute!(stdout_handle, LeaveAlternateScreen, Show);

    // Persist language selection
    let _ = std::fs::create_dir_all("/etc/wraith");
    let _ = std::fs::write("/etc/wraith/lang", format!("{selected_code}\n"));
    if let Ok(home) = std::env::var("HOME") {
        let _ = std::fs::create_dir_all(format!("{home}/.config/wraith"));
        let _ = std::fs::write(format!("{home}/.config/wraith/lang"), format!("{selected_code}\n"));
    }

    Ok(selected_code)
}

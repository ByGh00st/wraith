//! Wraith Interactive Terminal UI Module
//! Language configuration TUI and terminal state management.

use crossterm::cursor::{Hide, Show};
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use owo_colors::OwoColorize;
use std::time::Duration;
use wraith_core::error::Result;

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

        for (i, &(code, name)) in ALL_LANGUAGES.iter().enumerate().take(top.saturating_add(page_size).min(total)).skip(top) {
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
                    KeyCode::Down if cursor + 1 < total => {
                        cursor += 1;
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

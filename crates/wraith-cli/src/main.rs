//! Wraith CLI — Main Entry Point for Kali Linux
//! High-Assurance Network Anonymization & OS Fingerprint Hardening Engine in Pure Rust.

mod benchmark;
mod commands;
mod diagnostics;
mod display;
pub mod tui;

use clap::{Args, Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use wraith_core::error::Result;

rust_i18n::i18n!("locales");

#[derive(Args, Clone, Debug, Default)]
#[command(args_override_self = true)]
pub struct StartArgs {
    // ─── [1. NETWORK & ROUTING ISOLATION] ──────────────────────────────────────────
    /// Randomize network interface L2 MAC address and hostname
    #[arg(short = 'm', long = "mac", help_heading = "Network Isolation")]
    pub mac: bool,

    /// Route traffic through censorship-resistant obfs4 Tor bridges
    #[arg(short = 'b', long = "bridge", help_heading = "Network Isolation")]
    pub bridge: bool,

    /// Restrict routing to an isolated Linux Network Namespace (10.200.1.0/24)
    #[arg(short = 'n', long = "namespace", help_heading = "Network Isolation")]
    pub namespace: bool,

    /// Enforce geographic Tor exit node profile (e.g. stealth, speed, research, darkweb)
    #[arg(short = 'p', long = "profile", value_name = "PROFILE", help_heading = "Network Isolation")]
    pub profile: Option<String>,

    /// Inject synthetic traffic cells & Poisson timing jitter to resist traffic flow correlation
    #[arg(long = "jitter", help_heading = "Network Isolation")]
    pub jitter: bool,

    /// Automatically rotate Tor exit node identity every N seconds (e.g. --rotate 60)
    #[arg(long = "rotate-interval", visible_aliases = ["interval", "rotate", "auto-rotate"], value_name = "SECONDS", help_heading = "Network Isolation")]
    pub rotate_interval: Option<u64>,

    /// Disable the Fail-Closed KillSwitch watchdog monitor
    #[arg(long = "no-killswitch", visible_aliases = ["no-ks"], help_heading = "Network Isolation")]
    pub no_ks: bool,

    /// Encapsulate Tor traffic inside a kernel WireGuard tunnel (Multi-Hop DPI/ISP bypass)
    #[arg(
        short = 'W',
        long = "wireguard",
        visible_aliases = ["multihop", "wg", "hybrid"],
        value_name = "CONFIG_PATH",
        help_heading = "Network Isolation"
    )]
    pub wireguard: Option<String>,

    // ─── [2. HOST & SYSTEM FINGERPRINT HARDENING] ──────────────────────────────────
    /// Inject WebGL, Canvas, Audio, GPU, Font and Resolution anti-fingerprint profiles into browsers
    #[arg(long = "browser-shield", visible_aliases = ["shield", "canvas-shield"], help_heading = "System Hardening")]
    pub browser_shield: bool,

    /// Restrict OS-level font discovery via Fontconfig sandbox
    #[arg(long = "font-sandbox", visible_aliases = ["font-jail"], help_heading = "System Hardening")]
    pub font_sandbox: bool,

    /// Normalize TCP/IP L4 stack parameters (TTL=128, timestamps=0) to resist OS fingerprinting
    #[arg(long = "tcp-mask", help_heading = "System Hardening")]
    pub tcp_mask: bool,

    /// Rotate unique OS /etc/machine-id and system hardware identifiers
    #[arg(long = "machine-id", visible_aliases = ["cloaking"], help_heading = "System Hardening")]
    pub machine_id_rotation: bool,

    /// Engage ALL 16 defense layers: GPU/Font Shield, MAC, Machine-ID, TCP-Mask, Jitter, Seccomp, eBPF, RAMFS Vault
    #[arg(
        short = 'F',
        long = "full-security", 
        visible_aliases = ["full", "strict", "harden", "max-hardening", "full-defense", "strict-hardening", "fs"],
        help_heading = "System Hardening"
    )]
    pub strict_hardening: bool,

    /// Automatically spawn a dedicated real-time DPI & IDS monitor terminal window on startup
    #[arg(
        long = "spawn-monitor", 
        visible_aliases = ["popup", "live-window", "monitor-window"], 
        help_heading = "Network Isolation"
    )]
    pub monitor_window: bool,

    // ─── [3. HIGH-RISK & FORENSIC OPERATIONS] ──────────────────────────────────────────
    /// ⚠ IRREVERSIBLE: Eradicate system authentication logs, event logs, and user shell history files
    #[arg(
        short = 'L',
        long = "forensic-wipe-logs", 
        visible_aliases = ["destructive-cleanup", "wipe-logs", "wipe"],
        help_heading = "High-Risk & Forensic Operations"
    )]
    pub forensic_wipe_logs: bool,

    /// ⚠ IRREVERSIBLE: Cryptographically shred binary from disk and wipe memory artifacts on exit (SIGINT)
    #[arg(
        short = 'd', 
        long = "forensic-self-destruct", 
        visible_aliases = ["self-destruct"],
        help_heading = "High-Risk & Forensic Operations"
    )]
    pub forensic_self_destruct: bool,

    /// ⚠ EVASIVE: Spoof process name in Linux kernel scheduler as kernel worker thread ([kworker/u16:0])
    #[arg(
        short = 'K',
        long = "aggressive-masquerade", 
        visible_aliases = ["process-masquerade", "cloaked-process", "masquerade", "kworker"],
        help_heading = "High-Risk & Forensic Operations"
    )]
    pub aggressive_masquerade: bool,

    /// ⚠ EMERGENCY ABORT: Enforce anti-debugging probe; immediately triggers SIGKILL if attached to a debugger
    #[arg(
        short = 'A',
        long = "aggressive-anti-debug", 
        visible_aliases = ["anti-debug", "anti-ptrace"], 
        help_heading = "High-Risk & Forensic Operations"
    )]
    pub aggressive_anti_debug: bool,
}

impl StartArgs {
    /// Checks if any anonymization, shield, or network flag was passed at top-level
    pub fn has_active_flags(&self) -> bool {
        self.mac
            || self.bridge
            || self.namespace
            || self.profile.is_some()
            || self.wireguard.is_some()
            || self.jitter
            || self.browser_shield
            || self.font_sandbox
            || self.tcp_mask
            || self.machine_id_rotation
            || self.strict_hardening
            || self.monitor_window
            || self.forensic_wipe_logs
            || self.forensic_self_destruct
            || self.aggressive_masquerade
            || self.aggressive_anti_debug
    }
}

#[derive(Parser)]
#[command(
    name = "wraith",
    author = "WRAITH Engineering Team",
    version = env!("CARGO_PKG_VERSION"),
    about = "Linux Network Anonymization & OS Fingerprint Normalization Engine",
    long_about = "Wraith establishes fail-closed Tor transparent proxying with netfilter enforcement, TCP/IP stack normalization, hardware identifier rotation, and browser fingerprint sandboxing.",
    args_override_self = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    start_opts: StartArgs,

    /// Quick start shortcut with options from StartArgs
    #[arg(short = 's', long)]
    start: bool,

    /// Quick stop shortcut
    #[arg(short = 'x', long)]
    stop: bool,

    /// Launch real-time dedicated DPI & IDS live interceptor monitor
    #[arg(short = 'M', long = "monitor", visible_aliases = ["live", "ids-monitor"])]
    monitor: bool,

    /// Request new Tor exit node identity
    #[arg(short = 'r', long)]
    switch: bool,

    /// Run comprehensive leak tests
    #[arg(short = 't', long)]
    test: bool,

    /// Display telemetry dashboard & circuits
    #[arg(short = 'i', long)]
    info: bool,

    /// Launch interactive terminal telemetry dashboard
    #[arg(long)]
    dashboard: bool,

    /// Run deep multi-tier kernel diagnostics auditor
    #[arg(long)]
    doctor: bool,

    /// Run high-performance cryptographic and kernel benchmarks
    #[arg(long)]
    bench: bool,

    /// Display offensive security & pentest tool sanitization guide (Nmap, Sqlmap, Ffuf)
    #[arg(long)]
    pentest: bool,

    /// Fetch latest updates and recompile/hot-swap binary in-place
    #[arg(short = 'u', long)]
    update: bool,

    /// Anti-forensic cleanup
    #[arg(short = 'c', long)]
    cleanup: bool,

    /// Thorough anti-forensic purge (wipes swap, RAM caches, logs)
    #[arg(long)]
    cleanup_full: bool,

    /// Securely shred a target file using DoD 5220.22-M 7-pass standard
    #[arg(long)]
    shred: Option<String>,

    /// Enable verbose debug logging
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Override system language (e.g. 'en', 'tr')
    #[arg(long, global = true)]
    lang: Option<String>,

    /// Launch interactive 75-language configuration TUI
    #[arg(long = "select-lang", visible_aliases = ["lang-menu"], hide = true)]
    select_lang: bool,

    /// Generate shell auto-completion script (bash, zsh, fish, powershell)
    #[arg(long = "generate-completions", value_name = "SHELL", hide = true)]
    completions: Option<clap_complete::Shell>,
}

#[derive(Subcommand)]
#[command(args_override_self = true)]
enum Commands {
    /// Start Wraith network anonymization
    Start(StartArgs),
    /// Stop Wraith and restore normal network
    Stop {
        /// ⚠ Cryptographically shred binary and state files during shutdown
        #[arg(short = 'd', long = "forensic-self-destruct", visible_aliases = ["self-destruct"])]
        self_destruct: bool,
    },
    /// Request new Tor exit identity
    Switch,
    /// Run leak verification suite
    Test,
    /// Show status telemetry dashboard
    Info,
    /// Launch interactive terminal telemetry dashboard
    Dashboard,
    /// Run multi-vector deep kernel integrity & network diagnostics
    Doctor,
    /// Run high-performance cryptographic and kernel subsystem benchmarks
    Benchmark,
    /// Perform anti-forensic purge
    Cleanup {
        #[arg(long)]
        full: bool,
    },
    /// Randomize MAC address and hostname
    Mac,
    /// Apply geographic exit profile
    Profile {
        name: String,
    },
    /// Display offensive security & pentest tool sanitization guide (Nmap, Sqlmap, Ffuf)
    Pentest,
    /// Fetch latest upstream updates and recompile binary in-place
    Update,
    /// Securely shred and overwrite a file using DoD 5220.22-M 7-pass standard
    Shred {
        /// Target file path to shred
        target: String,
        /// Number of overwrite passes (default: 7)
        #[arg(short = 'p', long, default_value_t = 7)]
        passes: u32,
    },
    /// Launch real-time dedicated DPI & IDS live interceptor monitor
    #[command(name = "monitor", visible_aliases = ["live", "ids-monitor"])]
    Monitor,
}

fn install_emergency_panic_sentry() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen, crossterm::cursor::Show);
        let _ = crossterm::execute!(std::io::stderr(), crossterm::terminal::LeaveAlternateScreen, crossterm::cursor::Show);
        let panic_str = format!("CRASH DIAGNOSIS : {}", format!("{panic_info}").chars().take(50).collect::<String>());
        let rows = vec![
            panic_str,
            "AUTO-RECOVERY   : Restoring netfilter, DNS, DHCP, and clearnet routes...".to_string(),
        ];
        let p_box = crate::display::render_box("💥 CRITICAL ENGINE FAULT TRAPPED", &rows, crate::display::BoxCorner::Rounded, 78);
        eprintln!("\n\r{}", p_box[0]);
        for row in &p_box[1..p_box.len() - 1] {
            eprintln!("\r{row}");
        }
        eprintln!("\r{}\n", p_box.last().unwrap());
        emergency_kernel_recovery();
        default_hook(panic_info);
    }));
}

pub fn emergency_kernel_recovery() {
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("chattr").args(["-i", "/etc/resolv.conf"]).output();
        let _ = std::fs::write("/etc/resolv.conf", "nameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 1.0.0.1\n");
        let _ = std::process::Command::new("iptables").args(["-P", "INPUT", "ACCEPT"]).output();
        let _ = std::process::Command::new("iptables").args(["-P", "FORWARD", "ACCEPT"]).output();
        let _ = std::process::Command::new("iptables").args(["-P", "OUTPUT", "ACCEPT"]).output();
        let _ = std::process::Command::new("iptables").args(["-F"]).output();
        let _ = std::process::Command::new("iptables").args(["-X"]).output();
        let _ = std::process::Command::new("iptables").args(["-t", "nat", "-F"]).output();
        let _ = std::process::Command::new("iptables").args(["-t", "nat", "-X"]).output();
        let _ = std::process::Command::new("iptables").args(["-t", "mangle", "-F"]).output();

        let _ = std::process::Command::new("ip6tables").args(["-P", "INPUT", "ACCEPT"]).output();
        let _ = std::process::Command::new("ip6tables").args(["-P", "FORWARD", "ACCEPT"]).output();
        let _ = std::process::Command::new("ip6tables").args(["-P", "OUTPUT", "ACCEPT"]).output();
        let _ = std::process::Command::new("ip6tables").args(["-F"]).output();
        let _ = std::process::Command::new("ip6tables").args(["-X"]).output();

        let _ = std::process::Command::new("pkill").args(["-f", "tor.*-f"]).output();
        let _ = std::process::Command::new("pkill").args(["-9", "dhclient"]).output();

        let iface = wraith_net::get_default_interface().unwrap_or_else(|_| "eth0".to_string());
        let _ = std::process::Command::new("ip").args(["link", "set", &iface, "up"]).output();
        let _ = std::process::Command::new("systemctl").args(["restart", "NetworkManager"]).output();
        let _ = std::process::Command::new("service").args(["NetworkManager", "restart"]).output();
        let _ = std::process::Command::new("nmcli").args(["networking", "on"]).output();
        let _ = std::process::Command::new("nmcli").args(["device", "set", &iface, "managed", "yes"]).output();
        let _ = std::process::Command::new("nmcli").args(["device", "connect", &iface]).output();
        let _ = std::process::Command::new("dhclient").args(["-v", &iface]).output();
        let _ = std::process::Command::new("resolvectl").arg("flush-caches").output();
    }
}

fn check_root() -> Result<()> {
    #[cfg(unix)]
    {
        if nix::unistd::geteuid().as_raw() != 0 {
            return Err(wraith_core::error::WraithError::PermissionDenied);
        }
    }
    Ok(())
}

fn detect_system_language(raw_args: &[String]) -> String {
    // 1. CLI argument override: --lang <code>
    for i in 0..raw_args.len() {
        if raw_args[i] == "--lang" && i + 1 < raw_args.len() {
            return raw_args[i + 1].clone();
        }
    }
    // 2. Environment variable: WRAITH_LANG
    if let Ok(lang) = std::env::var("WRAITH_LANG") {
        let trimmed = lang.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    // 3. Persistent system-wide config: /etc/wraith/lang
    if let Ok(content) = std::fs::read_to_string("/etc/wraith/lang") {
        let trimmed = content.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    // 4. Persistent user config: ~/.config/wraith/lang
    if let Ok(home) = std::env::var("HOME") {
        let path = format!("{home}/.config/wraith/lang");
        if let Ok(content) = std::fs::read_to_string(path) {
            let trimmed = content.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
    }
    // 5. Fallback
    "en".to_string()
}

#[tokio::main]
pub async fn main() -> Result<()> {
    install_emergency_panic_sentry();

    // 1. Initialize multi-language i18n from argv, env, or /etc/wraith/lang
    let raw_args: Vec<String> = std::env::args().collect();
    let initial_lang = detect_system_language(&raw_args);
    rust_i18n::set_locale(&initial_lang);

    // 2. Intercept -h / --help / help to show fully localized help screen
    if raw_args.iter().any(|arg| arg == "-h" || arg == "--help" || arg == "help") {
        display::print_localized_help();
        return Ok(());
    }

    let cli = Cli::parse();

    if cli.select_lang {
        let chosen = tui::run_language_selector_tui()?;
        println!("{chosen}");
        return Ok(());
    }

    if let Some(shell) = cli.completions {
        let mut cmd = display::build_localized_command();
        clap_complete::generate(shell, &mut cmd, "wraith", &mut std::io::stdout());
        return Ok(());
    }

    // Initialize logging
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("warn")
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Unified command mapping from top-level shortcuts and subcommands
    let command = if let Some(cmd) = cli.command {
        cmd
    } else if cli.start || cli.start_opts.has_active_flags() {
        Commands::Start(cli.start_opts)
    } else if cli.stop {
        Commands::Stop { self_destruct: cli.start_opts.forensic_self_destruct }
    } else if cli.switch {
        Commands::Switch
    } else if cli.test {
        Commands::Test
    } else if cli.info {
        Commands::Info
    } else if cli.dashboard {
        Commands::Dashboard
    } else if cli.doctor {
        Commands::Doctor
    } else if cli.bench {
        Commands::Benchmark
    } else if cli.cleanup || cli.cleanup_full {
        Commands::Cleanup { full: cli.cleanup_full }
    } else if cli.pentest {
        Commands::Pentest
    } else if cli.update {
        Commands::Update
    } else if let Some(ref target) = cli.shred {
        Commands::Shred { target: target.clone(), passes: 7 }
    } else if cli.monitor {
        Commands::Monitor
    } else {
        display::print_banner(false);
        println!("  {}\n", rust_i18n::t!("runtime.help_hint"));
        return Ok(());
    };

    // Check root privileges for system-modifying operations
    match &command {
        Commands::Pentest => {} // Read-only pentest matrix does not require root
        _ => {
            if let Err(e) = check_root() {
                display::print_error(&format!("{}", rust_i18n::t!("runtime.root_required", e = e.to_string())));
                std::process::exit(1);
            }
        }
    }

    // Single unified dispatch pipeline with fail-safe SIGINT guard
    match command {
        Commands::Start(args) => {
            tokio::select! {
                res = commands::cmd_start(args) => {
                    if let Err(e) = res {
                        display::print_error(&format!("{}", rust_i18n::t!("runtime.startup_aborted", e = e.to_string())));
                        let _ = commands::cmd_stop(false).await;
                        return Err(e);
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    let _ = crossterm::terminal::disable_raw_mode();
                    println!("\r\n\n  {}", rust_i18n::t!("runtime.emergency_abort_title"));
                    println!("  {}", rust_i18n::t!("runtime.emergency_abort_desc"));
                    println!("  {}\n", rust_i18n::t!("runtime.emergency_abort_foot"));
                    let _ = commands::cmd_stop(false).await;
                }
            }
        }
        Commands::Stop { self_destruct } => {
            commands::cmd_stop(self_destruct).await?;
        }
        Commands::Switch => {
            commands::cmd_switch().await?;
        }
        Commands::Test => {
            commands::cmd_test().await?;
        }
        Commands::Info => {
            commands::cmd_info().await?;
        }
        Commands::Dashboard => {
            commands::cmd_dashboard().await?;
        }
        Commands::Doctor => {
            let checks = diagnostics::DiagnosticsRunner::run_all();
            diagnostics::DiagnosticsRunner::print_report(&checks);
        }
        Commands::Benchmark => {
            let results = benchmark::BenchmarkSuite::run_all();
            benchmark::BenchmarkSuite::print_report(&results);
        }
        Commands::Cleanup { full } => {
            commands::cmd_cleanup(full).await?;
        }
        Commands::Mac => {
            let _ = wraith_net::change_mac(None, None);
            let _ = wraith_net::randomize_hostname();
            display::print_success(&rust_i18n::t!("runtime.mac_randomized"));
        }
        Commands::Profile { name } => {
            let _ = wraith_tor::apply_exit_profile(&name).await?;
            display::print_success(&format!("{}", rust_i18n::t!("runtime.profile_applied", name = name.as_str())));
        }
        Commands::Pentest => {
            commands::cmd_pentest()?;
        }
        Commands::Update => {
            commands::cmd_update().await?;
        }
        Commands::Shred { target, passes } => {
            commands::cmd_shred(&target, passes).await?;
        }
        Commands::Monitor => {
            commands::cmd_monitor().await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_cli_parsing_flags() {
        let cli1 = Cli::try_parse_from(["wraith", "-Fs"]).expect("Failed to parse -Fs");
        assert!(cli1.start_opts.strict_hardening);
        assert!(cli1.start);

        let cli2 = Cli::try_parse_from(["wraith", "-sF"]).expect("Failed to parse -sF");
        assert!(cli2.start_opts.strict_hardening);
        assert!(cli2.start);

        let cli3 = Cli::try_parse_from(["wraith", "--full-security"]).expect("Failed to parse --full-security");
        assert!(cli3.start_opts.strict_hardening);

        let cli4 = Cli::try_parse_from(["wraith", "-F"]).expect("Failed to parse -F");
        assert!(cli4.start_opts.strict_hardening);

        let cli5 = Cli::try_parse_from(["wraith", "start", "-F"]).expect("Failed to parse start -F");
        if let Some(Commands::Start(args)) = cli5.command {
            assert!(args.strict_hardening);
        } else {
            panic!("Expected Commands::Start");
        }
    }
}


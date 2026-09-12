//! Wraith CLI — Main Entry Point for Kali Linux
//! High-Assurance Network Anonymization & OS Fingerprint Hardening Engine in Pure Rust.

mod benchmark;
mod commands;
mod diagnostics;
mod display;
pub mod doh_tui;
pub mod interface_tui;
pub mod tui;

use clap::{Args, Parser, Subcommand};
use owo_colors::OwoColorize;
use tracing_subscriber::EnvFilter;
use wraith_core::error::Result;

rust_i18n::i18n!("locales");

#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
#[command(args_override_self = true)]
pub struct StartArgs {
    // ─── [1. NETWORK & ROUTING ISOLATION] ──────────────────────────────────────────
    /// Target network interface adapter for L2/L3 operations (e.g. -I eth0, --interface wlan0)
    #[arg(
        short = 'I',
        long = "interface",
        visible_aliases = ["iface", "nic", "adapter"],
        value_name = "INTERFACE",
        help_heading = "Network Isolation"
    )]
    pub interface: Option<String>,

    /// Launch interactive TUI menu to select target network interface adapter
    #[arg(
        long = "select-interface",
        visible_aliases = ["pick-nic", "choose-interface"],
        help_heading = "Network Isolation"
    )]
    pub select_interface: bool,

    /// Randomize network interface L2 MAC address and hostname
    #[arg(short = 'm', long = "mac", help_heading = "Network Isolation")]
    pub mac: bool,

    /// Route traffic through censorship-resistant Tor bridges
    #[arg(short = 'b', long = "bridge", help_heading = "Network Isolation")]
    pub bridge: bool,

    /// Pluggable transport type or circumvention protocol (obfs4, snowflake, meek, webtunnel, moat)
    #[arg(
        long = "bridge-type",
        visible_aliases = ["transport", "pt"],
        value_name = "TYPE",
        help_heading = "Network Isolation"
    )]
    pub bridge_type: Option<String>,

    /// Upstream DNS-over-HTTPS resolver preset (quad9, mullvad, cloudflare, adguard, controld, google) or custom URL
    #[arg(
        short = 'D',
        long = "doh",
        visible_aliases = ["doh-provider", "doh-url", "dns"],
        value_name = "PRESET_OR_URL",
        help_heading = "Network Isolation"
    )]
    pub doh: Option<String>,

    /// Launch interactive TUI menu to select or input custom DNS-over-HTTPS resolver
    #[arg(
        long = "select-doh",
        visible_aliases = ["pick-doh", "choose-doh"],
        help_heading = "Network Isolation"
    )]
    pub select_doh: bool,

    /// Restrict routing to an isolated Linux Network Namespace (10.200.1.0/24)
    #[arg(short = 'n', long = "namespace", help_heading = "Network Isolation")]
    pub namespace: bool,

    /// Enforce geographic Tor exit node profile (stealth, speed, journalists, research, darkweb)
    #[arg(
        short = 'p',
        long = "profile",
        value_name = "PROFILE",
        value_parser = ["stealth", "speed", "journalists", "research", "darkweb"],
        help_heading = "Network Isolation"
    )]
    pub profile: Option<String>,

    /// Send bounded, randomized HTTPS cover requests through Tor to your endpoint
    #[arg(
        long = "jitter",
        requires = "jitter_endpoint",
        help_heading = "Network Isolation"
    )]
    pub jitter: bool,

    /// HTTPS endpoint you control or have permission to use for cover traffic
    #[arg(
        long = "jitter-endpoint",
        requires = "jitter",
        help_heading = "Network Isolation"
    )]
    pub jitter_endpoint: Option<String>,

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

    /// Arm an Ephemeral v3 Onion Hidden Service forwarding <VIRT_PORT:TARGET_PORT> (e.g. --onion 80:8080)
    #[arg(
        long = "onion",
        visible_aliases = ["hidden-service", "hs", "onion-service"],
        value_name = "VIRT_PORT:TARGET_PORT",
        help_heading = "Network Isolation"
    )]
    pub onion_service: Option<String>,

    /// Apply optional Linux TC/Netem delay, jitter, loss and rate settings
    #[arg(
        long = "shaper",
        visible_aliases = ["traffic-shaper", "netem", "tc-shaper"],
        help_heading = "Network Isolation"
    )]
    pub traffic_shaper: bool,

    // ─── [2. HOST & SYSTEM FINGERPRINT HARDENING] ──────────────────────────────────
    /// Inject WebGL, Canvas, Audio, GPU, Font and Resolution anti-fingerprint profiles into browsers
    #[arg(long = "browser-shield", visible_aliases = ["shield", "canvas-shield"], help_heading = "System Hardening")]
    pub browser_shield: bool,

    /// Restrict OS-level font discovery via Fontconfig sandbox
    #[arg(long = "font-sandbox", visible_aliases = ["font-jail"], help_heading = "System Hardening")]
    pub font_sandbox: bool,

    /// Spawn isolated X11 Virtual Display sandbox (Xvfb 1920x1080@24bit) to mask physical display EDID
    #[arg(
        long = "display-sandbox",
        visible_aliases = ["display-jail", "xvfb", "virtual-display"],
        help_heading = "System Hardening"
    )]
    pub display_sandbox: bool,

    /// Arm localhost deception honey-port traps on common lateral movement ports (2222, 3306, 5432, 6379, 8080, 27017)
    #[arg(
        long = "honey-ports",
        visible_aliases = ["honeypot", "honey-trap", "trap-ports"],
        help_heading = "System Hardening"
    )]
    pub honey_ports: bool,

    /// 🚨 LAN SENSOR MODE: Bind honeypot traps to 0.0.0.0 (Exposes decoy ports to Wi-Fi/LAN scanners & tarpits them)
    #[arg(
        long = "honey-lan",
        visible_aliases = ["lan-honeypot", "lan-trap", "deception-sensor"],
        help_heading = "System Hardening"
    )]
    pub honey_lan: bool,

    /// Normalize TCP/IP L4 stack parameters (TTL=128, timestamps=0) to resist OS fingerprinting
    #[arg(long = "tcp-mask", help_heading = "System Hardening")]
    pub tcp_mask: bool,

    /// Rotate unique OS /etc/machine-id and system hardware identifiers
    #[arg(long = "machine-id", visible_aliases = ["cloaking"], help_heading = "System Hardening")]
    pub machine_id_rotation: bool,

    /// Require strict Tor egress, kill switch, MAC, browser shield, namespace, seccomp and memory protection
    #[arg(
        short = 'F',
        long = "full-security",
        conflicts_with = "no_ks",
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

    /// ⚠ INTERNAL: Run as a background daemon worker
    #[arg(long = "daemon-worker", hide = true)]
    pub daemon_worker: bool,
}

impl StartArgs {
    /// Checks if any anonymization, shield, or network flag was passed at top-level
    pub fn has_active_flags(&self) -> bool {
        self.interface.is_some()
            || self.select_interface
            || self.mac
            || self.bridge
            || self.bridge_type.is_some()
            || self.doh.is_some()
            || self.select_doh
            || self.namespace
            || self.profile.is_some()
            || self.wireguard.is_some()
            || self.onion_service.is_some()
            || self.traffic_shaper
            || self.jitter
            || self.jitter_endpoint.is_some()
            || self.browser_shield
            || self.font_sandbox
            || self.display_sandbox
            || self.honey_ports
            || self.honey_lan
            || self.tcp_mask
            || self.machine_id_rotation
            || self.strict_hardening
            || self.monitor_window
            || self.forensic_wipe_logs
            || self.forensic_self_destruct
            || self.aggressive_masquerade
            || self.aggressive_anti_debug
            || self.daemon_worker
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
    #[arg(short = 's', long, conflicts_with = "stop")]
    start: bool,

    /// Quick stop shortcut
    #[arg(short = 'x', long, conflicts_with = "start")]
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

    /// Run deep multi-tier kernel diagnostics auditor
    #[arg(long)]
    doctor: bool,

    /// Run high-performance cryptographic and kernel benchmarks
    #[arg(long)]
    bench: bool,

    /// Display authorized security auditing & pentest tool sanitization guide (Nmap, Sqlmap, Ffuf)
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

    /// Launch interactive multi-language configuration TUI
    #[arg(long = "select-lang", visible_aliases = ["lang-menu"], hide = true)]
    select_lang: bool,

    /// Generate shell auto-completion script (bash, zsh, fish, powershell)
    #[arg(long = "generate-completions", value_name = "SHELL", hide = true)]
    completions: Option<clap_complete::Shell>,

    /// Print demonstration showcase screen with all 16 layers armed
    #[arg(long = "demo", hide = true)]
    demo: bool,

    /// Enumerate network adapters and display hardware attributes
    #[arg(long = "interfaces", visible_aliases = ["nics", "adapters", "ifaces"])]
    interfaces: bool,
}

#[derive(Subcommand, Clone, Debug, PartialEq, Eq)]
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
    /// Enumerate network interfaces and display adapter attributes
    #[command(name = "interfaces", visible_aliases = ["nics", "adapters", "ifaces"])]
    Interfaces {
        /// Display all interfaces including loopback and virtual adapters
        #[arg(short = 'a', long = "all")]
        all: bool,
    },
    /// Request new Tor exit identity
    Switch,
    /// Run leak verification suite
    Test,
    /// Show status telemetry dashboard
    Info,
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
        /// Profile name (stealth, speed, journalists, research, darkweb)
        #[arg(value_parser = ["stealth", "speed", "journalists", "research", "darkweb"])]
        name: String,
    },
    /// Display authorized security auditing & pentest tool sanitization guide (Nmap, Sqlmap, Ffuf)
    Pentest,
    /// Fetch HTTPS over Tor with a real browser-profile TLS/HTTP2 handshake
    Fetch {
        url: String,
        #[arg(long, default_value = "chrome", value_parser = ["chrome", "firefox", "safari"])]
        tls_profile: String,
        /// Save the response atomically; refuse an existing output file
        #[arg(short, long)]
        output: std::path::PathBuf,
    },
    /// Update from official GitHub, or install an optional signed offline release
    Update {
        #[arg(long, requires_all = ["manifest", "signature"])]
        artifact: Option<std::path::PathBuf>,
        #[arg(long, requires_all = ["artifact", "signature"])]
        manifest: Option<std::path::PathBuf>,
        #[arg(long, requires_all = ["artifact", "manifest"])]
        signature: Option<std::path::PathBuf>,
    },
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
    /// Manage persistent configuration settings (/etc/wraith/config.toml)
    #[command(name = "config")]
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
    /// Manage censorship circumvention bridges via Tor Moat Protocol
    #[command(name = "bridge", visible_aliases = ["bridges", "moat"])]
    Bridge {
        #[command(subcommand)]
        action: Option<BridgeAction>,
    },
    /// Inspect or select DNS-over-HTTPS (DoH) providers
    #[command(name = "doh", visible_aliases = ["dns"])]
    Doh {
        /// Launch interactive TUI selector
        #[arg(short = 's', long = "select")]
        select: bool,
    },
}

#[derive(Subcommand, Clone, Debug, PartialEq, Eq)]
pub enum BridgeAction {
    /// Query Tor BridgeDB via Moat Protocol (JSON-API)
    Moat {
        /// Transport protocol (obfs4, snowflake, webtunnel, meek-azure)
        #[arg(short = 't', long, default_value = "obfs4")]
        transport: String,
        /// Challenge solution if known
        #[arg(short = 's', long)]
        solution: Option<String>,
        /// Automatically fallback to circumvention defaults
        #[arg(short = 'a', long)]
        auto: bool,
    },
    /// List built-in censorship evasion bridge pools
    List,
}

#[derive(Subcommand, Clone, Debug, PartialEq, Eq)]
pub enum ConfigAction {
    /// Show current persistent configuration settings
    Show,
    /// Get individual configuration value
    Get {
        /// Configuration key (e.g. interface, profile, bridge, strict, lang)
        key: String,
    },
    /// Set individual configuration value and save to disk
    Set {
        /// Configuration key (e.g. interface, profile, bridge, strict, lang)
        key: String,
        /// New configuration value
        value: String,
    },
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
            "POLICY RETAINED : Use sudo wraith -x for recorded-session recovery.".to_string(),
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
    // A panic must never open clearnet or overwrite the saved resolver.
    // Retain the policy and session record for an explicit recovery operation.
    eprintln!("Wraith stopped unexpectedly. Network policy retained; use sudo wraith -x from a console to recover.");
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

pub(crate) fn resolve_command(cli: &Cli) -> Option<Commands> {
    if let Some(ref cmd) = cli.command {
        Some(cmd.clone())
    } else if cli.stop {
        Some(Commands::Stop {
            self_destruct: cli.start_opts.forensic_self_destruct,
        })
    } else if cli.start {
        Some(Commands::Start(cli.start_opts.clone()))
    } else if cli.switch {
        Some(Commands::Switch)
    } else if cli.test {
        Some(Commands::Test)
    } else if cli.info {
        Some(Commands::Info)
    } else if cli.doctor {
        Some(Commands::Doctor)
    } else if cli.bench {
        Some(Commands::Benchmark)
    } else if cli.cleanup || cli.cleanup_full {
        Some(Commands::Cleanup {
            full: cli.cleanup_full,
        })
    } else if cli.pentest {
        Some(Commands::Pentest)
    } else if cli.update {
        Some(Commands::Update {
            artifact: None,
            manifest: None,
            signature: None,
        })
    } else if let Some(ref target) = cli.shred {
        Some(Commands::Shred {
            target: target.clone(),
            passes: 7,
        })
    } else if cli.monitor {
        Some(Commands::Monitor)
    } else if cli.interfaces {
        Some(Commands::Interfaces { all: false })
    } else if cli.start_opts.has_active_flags() {
        Some(Commands::Start(cli.start_opts.clone()))
    } else {
        None
    }
}

#[tokio::main]
pub async fn main() -> Result<()> {
    install_emergency_panic_sentry();

    // 1. Initialize multi-language i18n from argv, env, or /etc/wraith/lang
    let raw_args: Vec<String> = std::env::args().collect();
    let initial_lang = detect_system_language(&raw_args);
    rust_i18n::set_locale(&initial_lang);

    // 2. Intercept -h / --help / help to show fully localized help screen
    let has_subcommand = <Cli as clap::CommandFactory>::command().get_subcommands().any(|command| {
        raw_args.iter().skip(1).any(|arg| arg == command.get_name())
    });
    if !has_subcommand
        && raw_args
            .iter()
            .any(|arg| arg == "-h" || arg == "--help" || arg == "help")
    {
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

    if cli.demo {
        display::print_demo_showcase();
        return Ok(());
    }

    // Initialize logging
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("warn,hickory_net=error,hickory_proto=error,wreq=error,btls=error")
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Unified command mapping from top-level shortcuts and subcommands
    let command = match resolve_command(&cli) {
        Some(cmd) => cmd,
        None => {
            display::print_banner(false);
            println!("  {}\n", rust_i18n::t!("runtime.help_hint"));
            return Ok(());
        }
    };

    // Check root privileges for system-modifying operations
    match &command {
        Commands::Pentest | Commands::Interfaces { .. } | Commands::Config { .. } | Commands::Fetch { .. } => {} // Read-only or self-managing operations do not require root
        _ => {
            if let Err(e) = check_root() {
                display::print_error(&format!("{}", rust_i18n::t!("runtime.root_required", e = e.to_string())));
                std::process::exit(1);
            }
        }
    }

    // Single unified dispatch pipeline with fail-safe SIGINT guard
    match command {
        Commands::Fetch {
            url,
            tls_profile,
            output,
        } => {
            let client = wraith_tor::BrowserTlsClient::new(tls_profile.parse()?)?;
            let response = client.get(&url, 8 * 1024 * 1024).await?;
            if !(200..300).contains(&response.status) {
                return Err(wraith_core::error::WraithError::Network(format!(
                    "HTTPS request returned status {}; redirects are not followed",
                    response.status
                )));
            }
            let parent = output
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or(std::path::Path::new("."));
            let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
            std::io::Write::write_all(&mut temporary, &response.body)?;
            temporary.as_file().sync_all()?;
            temporary
                .persist_noclobber(&output)
                .map_err(|error| error.error)?;
            println!(
                "Saved {} bytes ({}, {} profile) to {}",
                response.body.len(),
                response.protocol,
                tls_profile,
                output.display()
            );
        }
        Commands::Config { action } => {
            let mut cfg = wraith_core::WraithConfig::load().unwrap_or_default();
            match action.unwrap_or(ConfigAction::Show) {
                ConfigAction::Show => {
                    display::print_banner(false);
                    let pretty = toml::to_string_pretty(&cfg).unwrap_or_default();
                    println!("  \x1b[1;36m{}\x1b[0m\n", rust_i18n::t!("config_cmd.show_title"));
                    for line in pretty.lines() {
                        println!("    {line}");
                    }
                    println!();
                }
                ConfigAction::Get { key } => {
                    let val: String = match key.to_lowercase().as_str() {
                        "interface" | "nic" | "adapter" | "network.interface" => {
                            cfg.network.default_interface.or(cfg.default_interface).unwrap_or_else(|| "unset".to_string())
                        }
                        "profile" | "tor.profile" => {
                            cfg.tor.default_profile.or(cfg.default_profile).unwrap_or_else(|| "unset".to_string())
                        }
                        "bridge" | "tor.bridge" => {
                            cfg.tor.bridge.or(cfg.bridge).map(|b| b.to_string()).unwrap_or_else(|| "unset".to_string())
                        }
                        "bridge_type" | "tor.bridge_type" => {
                            cfg.tor.bridge_type.or(cfg.bridge_type).unwrap_or_else(|| "unset".to_string())
                        }
                        "moat_transport" | "tor.moat_transport" => {
                            cfg.tor.moat_transport.unwrap_or_else(|| "unset".to_string())
                        }
                        "strict" | "hardening.strict" => {
                            cfg.hardening.strict.or(cfg.strict_hardening).map(|b| b.to_string()).unwrap_or_else(|| "unset".to_string())
                        }
                        "dns" | "dns_transport" | "dns.transport" => {
                            cfg.dns.transport.or(cfg.dns_transport).unwrap_or_else(|| "unset".to_string())
                        }
                        "provider" | "dns.provider" => {
                            cfg.dns.provider.unwrap_or_else(|| "unset".to_string())
                        }
                        "doh" | "upstream" | "dns.upstream" => {
                            cfg.dns.upstream.or(cfg.doh_upstream).unwrap_or_else(|| "unset".to_string())
                        }
                        "rotate" | "interval" | "tor.rotate_interval" => {
                            cfg.tor.rotate_interval.or(cfg.rotate_interval).map(|n| n.to_string()).unwrap_or_else(|| "unset".to_string())
                        }
                        "lang" | "general.lang" => {
                            cfg.general.lang.or(cfg.lang).unwrap_or_else(|| "unset".to_string())
                        }
                        "fonts.allowed" | "fonts.allowed_fonts" => {
                            cfg.fonts.allowed_fonts.as_ref().map(|v| v.join(", ")).unwrap_or_else(|| "unset".to_string())
                        }
                        "fonts.blocked" | "fonts.blocked_fonts" => {
                            cfg.fonts.blocked_fonts.as_ref().map(|v| v.join(", ")).unwrap_or_else(|| "unset".to_string())
                        }
                        "fonts.blocked_paths" => {
                            cfg.fonts.blocked_paths.as_ref().map(|v| v.join(", ")).unwrap_or_else(|| "unset".to_string())
                        }
                        "fonts.monospace" | "fonts.preferred_monospace" => {
                            cfg.fonts.preferred_monospace.as_ref().map(|v| v.join(", ")).unwrap_or_else(|| "unset".to_string())
                        }
                        _ => rust_i18n::t!("config_cmd.key_unknown").to_string(),
                    };
                    println!("{val}");
                }
                ConfigAction::Set { key, value } => {
                    cfg.set_key(&key, &value)?;
                    let path = cfg.save()?;
                    display::print_success(&format!("{}", rust_i18n::t!("config_cmd.set_success", key = &key, value = &value, path = format!("{path:?}"))));
                }
            }
        }
        Commands::Interfaces { all } => {
            let ifaces = if all {
                wraith_net::list_all_interfaces()?
            } else {
                wraith_net::list_physical_interfaces()?
            };
            display::print_banner(false);
            interface_tui::print_interfaces_table(&ifaces);
        }
        Commands::Start(args) => {
            // Check if we need to daemonize (-s without -F/strict_hardening and not already daemon_worker)
            if !args.strict_hardening && !args.daemon_worker {
                #[cfg(target_os = "linux")]
                {
                    let is_systemd_active = std::process::Command::new("systemctl")
                        .args(["is-active", "--quiet", "wraith.service"])
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false);
                    if is_systemd_active {
                        display::print_error(&t!("daemon_cli.systemd_running_err"));
                        println!("{}", t!("daemon_cli.systemd_manage_hint"));
                        return Ok(());
                    }
                }

                let state_mgr = wraith_core::state::StateManager::default();
                if state_mgr.is_running() {
                    let st = state_mgr.read();
                    if st.active {
                        display::print_banner(false);
                        display::print_step(&t!("daemon_cli.already_armed_bg"), "warn");
                        let geo = wraith_guard::get_current_ip_geo().await;
                        display::print_background_hud(&st, &geo);
                        return Ok(());
                    }
                }

                display::print_banner(false);
                let init_rows = vec![
                    t!("daemon_cli.init_row1").bright_white().to_string(),
                    t!("daemon_cli.init_row2").dimmed().to_string(),
                ];
                let init_box = display::render_box(
                    &t!("daemon_cli.init_title"),
                    &init_rows,
                    display::BoxCorner::Rounded,
                    78,
                );
                println!("{}", init_box[0].bright_cyan());
                for row in &init_box[1..init_box.len() - 1] {
                    println!("{row}");
                }
                println!("{}", init_box.last().unwrap().bright_cyan());
                
                let mut cmd = std::process::Command::new(std::env::current_exe()?);
                // Forward all original arguments and append --daemon-worker
                cmd.args(std::env::args().skip(1));
                cmd.arg("--daemon-worker");
                
                // Detach from current terminal
                cmd.stdin(std::process::Stdio::null());
                #[cfg(unix)]
                {
                    use std::os::unix::process::CommandExt;
                    unsafe {
                        cmd.pre_exec(|| {
                            libc::setsid();
                            Ok(())
                        });
                    }
                }

                let _ = std::fs::create_dir_all("/var/log/wraith");
                let log_file = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open("/var/log/wraith/daemon.log");
                if let Ok(ref file) = log_file {
                    if let Ok(out_f) = file.try_clone() {
                        cmd.stdout(out_f);
                    }
                    if let Ok(err_f) = file.try_clone() {
                        cmd.stderr(err_f);
                    }
                } else {
                    cmd.stdout(std::process::Stdio::null());
                    cmd.stderr(std::process::Stdio::null());
                }
                
                let mut child = match cmd.spawn() {
                    Ok(c) => c,
                    Err(e) => {
                        let spawn_err = t!("daemon_cli.spawn_failed", err = e.to_string());
                        display::print_error(&spawn_err);
                        return Err(wraith_core::error::WraithError::Custom(spawn_err));
                    }
                };

                // Wait for daemon to initialize Tor and activate routing
                use std::io::Write;
                let spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
                let mut activated = false;
                for i in 0..60 {
                    let frame = spinner_frames[i % spinner_frames.len()];
                    let secs_val = (i / 2) + 1;
                    let spin_text = t!("daemon_cli.establishing_spinner", secs = secs_val);
                    print!("\r  \x1b[1;36m{frame}\x1b[0m \x1b[1;37m{spin_text}\x1b[0m");
                    let _ = std::io::stdout().flush();
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    
                    if let Ok(Some(status)) = child.try_wait() {
                        print!("\r\x1b[2K");
                        let _ = std::io::stdout().flush();
                        let log_content = std::fs::read_to_string("/var/log/wraith/daemon.log").unwrap_or_default();
                        let err_detail = log_content.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("Unknown exit reason");
                        let exit_msg = t!("daemon_cli.unexpected_exit", status = status.to_string(), detail = err_detail);
                        display::print_error(&exit_msg);
                        return Err(wraith_core::error::WraithError::Custom("Daemon startup failed".into()));
                    }

                    if state_mgr.is_active() {
                        activated = true;
                        break;
                    }
                }
                print!("\r\x1b[2K");
                let _ = std::io::stdout().flush();

                if activated {
                    let state = state_mgr.read();
                    let geo = wraith_guard::get_current_ip_geo().await;
                    display::print_background_hud(&state, &geo);
                } else {
                    display::print_step(&t!("daemon_cli.awaiting_bootstrap"), "warn");
                    display::print_step(&t!("daemon_cli.run_info_shortly"), "info");
                }
                return Ok(());
            }

            tokio::select! {
                res = commands::cmd_start(args) => {
                    if let Err(e) = res {
                        let prefix = rust_i18n::t!("runtime.startup_aborted");
                        let err_msg = if prefix.contains("{}") {
                            prefix.replace("{}", &e.to_string())
                        } else if prefix.contains("%{e}") {
                            prefix.replace("%{e}", &e.to_string())
                        } else {
                            format!("{prefix}: {e}")
                        };
                        display::print_error(&err_msg);
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
        Commands::Update { artifact, manifest, signature } => {
            commands::cmd_update(artifact, manifest, signature).await?;
        }
        Commands::Shred { target, passes } => {
            commands::cmd_shred(&target, passes).await?;
        }
        Commands::Monitor => {
            commands::cmd_monitor().await?;
        }
        Commands::Bridge { action } => {
            commands::cmd_bridge(action).await?;
        }
        Commands::Doh { select } => {
            commands::cmd_doh(select)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updater_supports_github_and_requires_complete_offline_inputs() {
        assert!(Cli::try_parse_from(["wraith", "-u"]).unwrap().update);
        assert!(matches!(Cli::try_parse_from(["wraith", "update"]).unwrap().command,
            Some(Commands::Update { artifact: None, manifest: None, signature: None })));
        assert!(Cli::try_parse_from(["wraith", "update", "--artifact", "binary"]).is_err());
        assert!(Cli::try_parse_from(["wraith", "update", "--artifact", "binary", "--manifest", "release.json", "--signature", "release.minisig"]).is_ok());
    }
    use clap::Parser;

    #[test]
    fn profiled_fetch_and_cover_traffic_require_explicit_arguments() {
        assert!(Cli::try_parse_from([
            "wraith",
            "fetch",
            "https://example.org",
            "--output",
            "page.html",
            "--tls-profile",
            "firefox"
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["wraith", "fetch", "https://example.org"]).is_err());
        assert!(Cli::try_parse_from([
            "wraith",
            "fetch",
            "https://example.org",
            "--output",
            "page.html",
            "--tls-profile",
            "unknown"
        ])
        .is_err());
        assert!(Cli::try_parse_from(["wraith", "--jitter"]).is_err());
        assert!(
            Cli::try_parse_from(["wraith", "--jitter-endpoint", "https://example.org"]).is_err()
        );
        assert!(Cli::try_parse_from([
            "wraith",
            "--jitter",
            "--jitter-endpoint",
            "https://example.org"
        ])
        .is_ok());
    }

    #[test]
    fn full_security_rejects_disabled_watchdog() {
        assert!(Cli::try_parse_from(["wraith", "-Fs", "--no-ks"]).is_err());
        assert!(Cli::try_parse_from(["wraith", "start", "-F", "--no-ks"]).is_err());
    }

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

        let cli6 = Cli::try_parse_from([
            "wraith",
            "--onion", "80:8080",
            "--shaper",
            "--honey-ports",
            "--honey-lan",
            "--display-sandbox",
        ]).expect("Failed to parse new isolation flags");
        assert_eq!(cli6.start_opts.onion_service.as_deref(), Some("80:8080"));
        assert!(cli6.start_opts.traffic_shaper);
        assert!(cli6.start_opts.honey_ports);
        assert!(cli6.start_opts.honey_lan);
        assert!(cli6.start_opts.display_sandbox);
        assert!(cli6.start_opts.has_active_flags());

        let cli7 = Cli::try_parse_from(["wraith", "-I", "wlan0"]).expect("Failed to parse -I wlan0");
        assert_eq!(cli7.start_opts.interface.as_deref(), Some("wlan0"));
        assert!(cli7.start_opts.has_active_flags());

        let cli8 = Cli::try_parse_from(["wraith", "--select-interface"]).expect("Failed to parse --select-interface");
        assert!(cli8.start_opts.select_interface);
        assert!(cli8.start_opts.has_active_flags());

        let cli9 = Cli::try_parse_from(["wraith", "interfaces", "-a"]).expect("Failed to parse interfaces -a");
        if let Some(Commands::Interfaces { all }) = cli9.command {
            assert!(all);
        } else {
            panic!("Expected Commands::Interfaces");
        }

        let cli10 = Cli::try_parse_from(["wraith", "--doh", "quad9"]).expect("Failed to parse --doh quad9");
        assert_eq!(cli10.start_opts.doh.as_deref(), Some("quad9"));
        assert!(cli10.start_opts.has_active_flags());

        let cli11 = Cli::try_parse_from(["wraith", "--select-doh"]).expect("Failed to parse --select-doh");
        assert!(cli11.start_opts.select_doh);
        assert!(cli11.start_opts.has_active_flags());

        let cli12 = Cli::try_parse_from(["wraith", "config", "set", "tor.profile", "stealth"]).expect("Failed to parse config set");
        if let Some(Commands::Config { action: Some(ConfigAction::Set { key, value }) }) = cli12.command {
            assert_eq!(key, "tor.profile");
            assert_eq!(value, "stealth");
        } else {
            panic!("Expected Commands::Config Set");
        }

        let cli13 = Cli::try_parse_from(["wraith", "bridge", "moat", "--transport", "obfs4", "-a"]).expect("Failed to parse bridge moat");
        if let Some(Commands::Bridge { action: Some(BridgeAction::Moat { transport, auto, .. }) }) = cli13.command {
            assert_eq!(transport, "obfs4");
            assert!(auto);
        } else {
            panic!("Expected Commands::Bridge Moat");
        }

        let cli14 = Cli::try_parse_from(["wraith", "doh", "-s"]).expect("Failed to parse doh -s");
        if let Some(Commands::Doh { select }) = cli14.command {
            assert!(select);
        } else {
            panic!("Expected Commands::Doh");
        }
    }

    #[test]
    fn test_resolve_command_all_shortcuts_and_subcommands() {
        // Stop shortcuts
        let cli_stop = Cli::try_parse_from(["wraith", "-x"]).unwrap();
        assert_eq!(resolve_command(&cli_stop), Some(Commands::Stop { self_destruct: false }));

        let cli_stop_destruct = Cli::try_parse_from(["wraith", "-x", "-d"]).unwrap();
        assert_eq!(resolve_command(&cli_stop_destruct), Some(Commands::Stop { self_destruct: true }));

        let cli_stop_sub = Cli::try_parse_from(["wraith", "stop"]).unwrap();
        assert_eq!(resolve_command(&cli_stop_sub), Some(Commands::Stop { self_destruct: false }));

        let cli_stop_sub_d = Cli::try_parse_from(["wraith", "stop", "-d"]).unwrap();
        assert_eq!(resolve_command(&cli_stop_sub_d), Some(Commands::Stop { self_destruct: true }));

        // Start & strict hardening shortcuts
        let cli_start = Cli::try_parse_from(["wraith", "-s"]).unwrap();
        assert_eq!(resolve_command(&cli_start), Some(Commands::Start(StartArgs::default())));

        let cli_fs = Cli::try_parse_from(["wraith", "-Fs"]).unwrap();
        assert!(matches!(resolve_command(&cli_fs), Some(Commands::Start(args)) if args.strict_hardening));

        let cli_f = Cli::try_parse_from(["wraith", "-F"]).unwrap();
        assert!(matches!(resolve_command(&cli_f), Some(Commands::Start(args)) if args.strict_hardening));

        // Start modifier flags without -s (implicit start via has_active_flags)
        let cli_iface = Cli::try_parse_from(["wraith", "-I", "eth0"]).unwrap();
        assert!(matches!(resolve_command(&cli_iface), Some(Commands::Start(args)) if args.interface.as_deref() == Some("eth0")));

        let cli_mac = Cli::try_parse_from(["wraith", "-m"]).unwrap();
        assert!(matches!(resolve_command(&cli_mac), Some(Commands::Start(args)) if args.mac));

        let cli_bridge = Cli::try_parse_from(["wraith", "-b", "--bridge-type", "obfs4"]).unwrap();
        assert!(matches!(resolve_command(&cli_bridge), Some(Commands::Start(args)) if args.bridge && args.bridge_type.as_deref() == Some("obfs4")));

        let cli_doh = Cli::try_parse_from(["wraith", "-D", "quad9"]).unwrap();
        assert!(matches!(resolve_command(&cli_doh), Some(Commands::Start(args)) if args.doh.as_deref() == Some("quad9")));

        let cli_ns = Cli::try_parse_from(["wraith", "-n"]).unwrap();
        assert!(matches!(resolve_command(&cli_ns), Some(Commands::Start(args)) if args.namespace));

        let cli_prof = Cli::try_parse_from(["wraith", "-p", "stealth"]).unwrap();
        assert!(matches!(resolve_command(&cli_prof), Some(Commands::Start(args)) if args.profile.as_deref() == Some("stealth")));

        let cli_shaper = Cli::try_parse_from(["wraith", "--shaper"]).unwrap();
        assert!(matches!(resolve_command(&cli_shaper), Some(Commands::Start(args)) if args.traffic_shaper));

        let cli_onion = Cli::try_parse_from(["wraith", "--onion", "80:8080"]).unwrap();
        assert!(matches!(resolve_command(&cli_onion), Some(Commands::Start(args)) if args.onion_service.as_deref() == Some("80:8080")));

        let cli_honey = Cli::try_parse_from(["wraith", "--honey-ports", "--honey-lan"]).unwrap();
        assert!(matches!(resolve_command(&cli_honey), Some(Commands::Start(args)) if args.honey_ports && args.honey_lan));

        let cli_tcpm = Cli::try_parse_from(["wraith", "--tcp-mask"]).unwrap();
        assert!(matches!(resolve_command(&cli_tcpm), Some(Commands::Start(args)) if args.tcp_mask));

        let cli_mid = Cli::try_parse_from(["wraith", "--machine-id"]).unwrap();
        assert!(matches!(resolve_command(&cli_mid), Some(Commands::Start(args)) if args.machine_id_rotation));

        let cli_bshield = Cli::try_parse_from(["wraith", "--browser-shield"]).unwrap();
        assert!(matches!(resolve_command(&cli_bshield), Some(Commands::Start(args)) if args.browser_shield));

        let cli_fsandbox = Cli::try_parse_from(["wraith", "--font-sandbox"]).unwrap();
        assert!(matches!(resolve_command(&cli_fsandbox), Some(Commands::Start(args)) if args.font_sandbox));

        let cli_dsandbox = Cli::try_parse_from(["wraith", "--display-sandbox"]).unwrap();
        assert!(matches!(resolve_command(&cli_dsandbox), Some(Commands::Start(args)) if args.display_sandbox));

        let cli_smon = Cli::try_parse_from(["wraith", "--spawn-monitor"]).unwrap();
        assert!(matches!(resolve_command(&cli_smon), Some(Commands::Start(args)) if args.monitor_window));

        let cli_wipe = Cli::try_parse_from(["wraith", "-L"]).unwrap();
        assert!(matches!(resolve_command(&cli_wipe), Some(Commands::Start(args)) if args.forensic_wipe_logs));

        let cli_masq = Cli::try_parse_from(["wraith", "-K"]).unwrap();
        assert!(matches!(resolve_command(&cli_masq), Some(Commands::Start(args)) if args.aggressive_masquerade));

        let cli_antid = Cli::try_parse_from(["wraith", "-A"]).unwrap();
        assert!(matches!(resolve_command(&cli_antid), Some(Commands::Start(args)) if args.aggressive_anti_debug));

        // Core operational shortcuts
        let cli_switch = Cli::try_parse_from(["wraith", "-r"]).unwrap();
        assert_eq!(resolve_command(&cli_switch), Some(Commands::Switch));

        let cli_test = Cli::try_parse_from(["wraith", "-t"]).unwrap();
        assert_eq!(resolve_command(&cli_test), Some(Commands::Test));

        let cli_info = Cli::try_parse_from(["wraith", "-i"]).unwrap();
        assert_eq!(resolve_command(&cli_info), Some(Commands::Info));

        let cli_doctor = Cli::try_parse_from(["wraith", "--doctor"]).unwrap();
        assert_eq!(resolve_command(&cli_doctor), Some(Commands::Doctor));

        let cli_bench = Cli::try_parse_from(["wraith", "--bench"]).unwrap();
        assert_eq!(resolve_command(&cli_bench), Some(Commands::Benchmark));

        let cli_pentest = Cli::try_parse_from(["wraith", "--pentest"]).unwrap();
        assert_eq!(resolve_command(&cli_pentest), Some(Commands::Pentest));

        let cli_update = Cli::try_parse_from(["wraith", "-u"]).unwrap();
        assert_eq!(resolve_command(&cli_update), Some(Commands::Update { artifact: None, manifest: None, signature: None }));

        let cli_cleanup = Cli::try_parse_from(["wraith", "-c"]).unwrap();
        assert_eq!(resolve_command(&cli_cleanup), Some(Commands::Cleanup { full: false }));

        let cli_cleanup_full = Cli::try_parse_from(["wraith", "--cleanup-full"]).unwrap();
        assert_eq!(resolve_command(&cli_cleanup_full), Some(Commands::Cleanup { full: true }));

        let cli_shred = Cli::try_parse_from(["wraith", "--shred", "/tmp/victim.log"]).unwrap();
        assert_eq!(resolve_command(&cli_shred), Some(Commands::Shred { target: "/tmp/victim.log".to_string(), passes: 7 }));

        let cli_monitor = Cli::try_parse_from(["wraith", "-M"]).unwrap();
        assert_eq!(resolve_command(&cli_monitor), Some(Commands::Monitor));

        let cli_ifaces = Cli::try_parse_from(["wraith", "--interfaces"]).unwrap();
        assert_eq!(resolve_command(&cli_ifaces), Some(Commands::Interfaces { all: false }));

        // Conflicting start & stop
        assert!(Cli::try_parse_from(["wraith", "-s", "-x"]).is_err());
        assert!(Cli::try_parse_from(["wraith", "--start", "--stop"]).is_err());
    }
}


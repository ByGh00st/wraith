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
use tracing_subscriber::EnvFilter;
use wraith_core::error::Result;

rust_i18n::i18n!("locales");

#[derive(Args, Clone, Debug, Default)]
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

    /// Arm an Ephemeral v3 Onion Hidden Service forwarding <VIRT_PORT:TARGET_PORT> (e.g. --onion 80:8080)
    #[arg(
        long = "onion",
        visible_aliases = ["hidden-service", "hs", "onion-service"],
        value_name = "VIRT_PORT:TARGET_PORT",
        help_heading = "Network Isolation"
    )]
    pub onion_service: Option<String>,

    /// Enforce Linux TC/Netem kernel traffic shaping & jitter distribution (anti-flow correlation)
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

#[derive(Subcommand, Clone, Debug)]
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

#[derive(Subcommand, Clone, Debug)]
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

    if cli.demo {
        display::print_demo_showcase();
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
    } else if cli.interfaces {
        Commands::Interfaces { all: false }
    } else {
        display::print_banner(false);
        println!("  {}\n", rust_i18n::t!("runtime.help_hint"));
        return Ok(());
    };

    // Check root privileges for system-modifying operations
    match &command {
        Commands::Pentest | Commands::Interfaces { .. } | Commands::Config { .. } => {} // Read-only or self-managing operations do not require root
        _ => {
            if let Err(e) = check_root() {
                display::print_error(&format!("{}", rust_i18n::t!("runtime.root_required", e = e.to_string())));
                std::process::exit(1);
            }
        }
    }

    // Single unified dispatch pipeline with fail-safe SIGINT guard
    match command {
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
    use clap::Parser;

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
}


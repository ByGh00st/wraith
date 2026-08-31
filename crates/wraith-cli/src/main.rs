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

#[derive(Args, Clone, Debug, Default)]
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

    /// Disable the Fail-Closed KillSwitch watchdog monitor
    #[arg(long = "no-killswitch", visible_aliases = ["no-ks"], help_heading = "Network Isolation")]
    pub no_ks: bool,

    // ─── [2. HOST & SYSTEM FINGERPRINT HARDENING] ──────────────────────────────────
    /// Inject WebGL, Canvas, Audio, GPU, Font and Resolution anti-fingerprint profiles into browsers
    #[arg(long = "browser-shield", visible_aliases = ["shield", "harden"], help_heading = "System Hardening")]
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

    /// Engage ALL non-destructive hardening layers (Shield, NetNS, MAC, Machine-ID, TCP-Mask, Jitter, Seccomp, eBPF)
    #[arg(
        long = "strict-hardening", 
        visible_aliases = ["black-level", "gen4", "full-defense", "apex"],
        help_heading = "System Hardening"
    )]
    pub strict_hardening: bool,

    // ─── [3. HIGH-RISK & FORENSIC OPERATIONS — EXPLICIT OPT-IN ONLY] ─────────────────────
    /// ⚠ IRREVERSIBLE: Eradicate system authentication logs, event logs, and user shell history files
    #[arg(
        long = "forensic-wipe-logs", 
        visible_aliases = ["destructive-cleanup", "wipe-logs"],
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
        long = "aggressive-masquerade", 
        visible_aliases = ["process-masquerade", "cloaked-process"],
        help_heading = "High-Risk & Forensic Operations"
    )]
    pub aggressive_masquerade: bool,

    /// ⚠ DEFENSIVE SUICIDE: Enforce anti-debugging probe; immediately triggers SIGKILL if attached to a debugger
    #[arg(
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
            || self.jitter
            || self.browser_shield
            || self.font_sandbox
            || self.tcp_mask
            || self.machine_id_rotation
            || self.strict_hardening
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
    long_about = "Wraith establishes fail-closed Tor transparent proxying with netfilter enforcement, TCP/IP stack normalization, hardware identifier rotation, and browser fingerprint sandboxing."
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

    /// Anti-forensic cleanup
    #[arg(short = 'c', long)]
    cleanup: bool,

    /// Thorough anti-forensic purge (wipes swap, RAM caches, logs)
    #[arg(long)]
    cleanup_full: bool,

    /// Enable verbose debug logging
    #[arg(short = 'v', long)]
    verbose: bool,
}

#[derive(Subcommand)]
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("warn")
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Check root privileges
    if let Err(e) = check_root() {
        display::print_error(&format!("{e}"));
        std::process::exit(1);
    }

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
    } else {
        display::print_banner();
        println!("  Use 'wraith --help' for available commands and options.\n");
        return Ok(());
    };

    // Single unified dispatch pipeline
    match command {
        Commands::Start(args) => {
            commands::cmd_start(args).await?;
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
            display::print_success("Hardware MAC and Hostname randomized");
        }
        Commands::Profile { name } => {
            let _ = wraith_tor::apply_exit_profile(&name).await?;
            display::print_success(&format!("Applied exit profile: {name}"));
        }
        Commands::Pentest => {
            commands::cmd_pentest()?;
        }
    }

    Ok(())
}

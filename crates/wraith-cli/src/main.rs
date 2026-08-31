//! Wraith CLI — Main Entry Point for Kali Linux
//! Sovereign Tier-1 Network Anonymization & Hardware Cloaking Engine in Pure Rust.

mod benchmark;
mod commands;
mod diagnostics;
mod display;
pub mod tui;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use wraith_core::error::Result;

#[derive(Parser)]
#[command(
    name = "wraith",
    author = "WRAITH-PRIME / ByGhost",
    version = "1.0.0",
    about = "Sovereign Tier-1 Network Anonymization & Hardware Cloaking Engine for Linux",
    long_about = "Wraith routes all TCP/DNS traffic through Tor with Fail-Closed netfilter, anti-forensics, font/GPU/resolution shields, TCP/IP stack normalization, and traffic jitter obfuscation."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Quick start shortcut with default options
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

    /// Launch interactive real-time warfare TUI dashboard
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

    /// Randomize hardware MAC address
    #[arg(short = 'm', long)]
    mac: bool,

    /// Enable censorship-resistant obfs4 bridge mode
    #[arg(short = 'b', long)]
    bridge: bool,

    /// Enable Linux network namespace isolation
    #[arg(short = 'n', long)]
    namespace: bool,

    /// Geographic exit node profile (stealth/speed/journalists/research/darkweb)
    #[arg(short = 'p', long)]
    profile: Option<String>,

    /// Apply standard browser hardening
    #[arg(long)]
    harden: bool,

    /// Sovereign Shield: GPU, WebGL, Canvas, Audio, Font & Screen Resolution Anti-Fingerprint Mask
    #[arg(long)]
    shield: bool,

    /// Enforce OS-level Fontconfig sandbox to block font discovery
    #[arg(long)]
    font_jail: bool,

    /// Normalize TCP/IP stack L4 parameters (TTL=128, timestamps=0 to evade p0f/Nmap)
    #[arg(long)]
    tcp_mask: bool,

    /// Rotate /etc/machine-id and mask hardware DMI identifiers
    #[arg(long)]
    cloaking: bool,

    /// Inject synthetic traffic padding cells & Poisson timing jitter (anti-correlation)
    #[arg(long)]
    jitter: bool,

    /// BLACK-LEVEL: Engage ALL hardening vectors (Shield, NetNS, MAC, Cloaking, TCP-Mask, Jitter, Stealth)
    #[arg(long)]
    black_level: bool,

    /// GEN-4 SOVEREIGN: Engage Seccomp-BPF, eBPF TC Fastpath, JA3/JA4 Camouflage & Kernel Lockdown
    #[arg(long)]
    gen4: bool,

    /// Self-Destruct / Ephemeral Mode: Shred binary & all artifacts from disk/RAM on exit (Ctrl+C)
    #[arg(short = 'd', long)]
    self_destruct: bool,

    /// Disable the Fail-Closed KillSwitch watchdog
    #[arg(long)]
    no_ks: bool,

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
    Start {
        #[arg(short, long)]
        mac: bool,
        #[arg(short, long)]
        bridge: bool,
        #[arg(short, long)]
        namespace: bool,
        #[arg(short, long)]
        profile: Option<String>,
        #[arg(long)]
        harden: bool,
        #[arg(long)]
        shield: bool,
        #[arg(long)]
        font_jail: bool,
        #[arg(long)]
        tcp_mask: bool,
        #[arg(long)]
        cloaking: bool,
        #[arg(long)]
        jitter: bool,
        #[arg(long)]
        black_level: bool,
        #[arg(long)]
        gen4: bool,
        #[arg(short, long)]
        self_destruct: bool,
        #[arg(long)]
        no_ks: bool,
    },
    /// Stop Wraith and restore normal network
    Stop {
        #[arg(short, long)]
        self_destruct: bool,
    },
    /// Request new Tor exit identity
    Switch,
    /// Run leak verification suite
    Test,
    /// Show status telemetry dashboard
    Info,
    /// Launch interactive real-time warfare TUI dashboard
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

    // Command dispatching
    if let Some(cmd) = cli.command {
        match cmd {
            Commands::Start {
                mac,
                bridge,
                namespace,
                profile,
                harden,
                shield,
                font_jail,
                tcp_mask,
                cloaking,
                jitter,
                black_level,
                gen4,
                self_destruct,
                no_ks,
            } => {
                commands::cmd_start(
                    mac,
                    bridge,
                    namespace,
                    profile,
                    harden,
                    shield,
                    font_jail,
                    tcp_mask,
                    cloaking,
                    jitter,
                    black_level,
                    gen4,
                    self_destruct,
                    no_ks,
                )
                .await?;
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
    } else if cli.pentest {
        commands::cmd_pentest()?;
    } else if cli.dashboard {
        commands::cmd_dashboard().await?;
    } else if cli.doctor {
        let checks = diagnostics::DiagnosticsRunner::run_all();
        diagnostics::DiagnosticsRunner::print_report(&checks);
    } else if cli.bench {
        let results = benchmark::BenchmarkSuite::run_all();
        benchmark::BenchmarkSuite::print_report(&results);
    } else if cli.start || cli.black_level || cli.gen4 {
        commands::cmd_start(
            cli.mac,
            cli.bridge,
            cli.namespace,
            cli.profile,
            cli.harden,
            cli.shield,
            cli.font_jail,
            cli.tcp_mask,
            cli.cloaking,
            cli.jitter,
            cli.black_level,
            cli.gen4,
            cli.self_destruct,
            cli.no_ks,
        )
        .await?;
    } else if cli.stop {
        commands::cmd_stop(cli.self_destruct).await?;
    } else if cli.switch {
        commands::cmd_switch().await?;
    } else if cli.test {
        commands::cmd_test().await?;
    } else if cli.info {
        commands::cmd_info().await?;
    } else if cli.cleanup || cli.cleanup_full {
        commands::cmd_cleanup(cli.cleanup_full).await?;
    } else if cli.mac {
        let _ = wraith_net::change_mac(None, None);
        let _ = wraith_net::randomize_hostname();
        display::print_success("Hardware MAC and Hostname randomized");
    } else {
        display::print_banner();
        println!("  Use 'wraith --help' for available commands and options.\n");
    }

    Ok(())
}

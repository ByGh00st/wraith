//! Validate an invocation before a shortcut, helper or daemon can perform work.
use crate::{Cli, StartArgs};
use clap::{error::ErrorKind, CommandFactory, FromArgMatches};
use std::ffi::OsString;

pub fn parse(args: impl IntoIterator<Item = impl Into<OsString> + Clone>) -> Result<Cli, clap::Error> {
    let normalized_args: Vec<OsString> = args
        .into_iter()
        .map(|arg| {
            let os_str: OsString = arg.into();
            if let Some(s) = os_str.to_str() {
                if s == "-rN" || s == "-rn" || s == "--rN" || s == "--rn" {
                    return OsString::from("--reset");
                }
            }
            os_str
        })
        .collect();
    let mut command = crate::display::build_localized_command();
    let matches = command.try_get_matches_from_mut(normalized_args)?;
    let cli = Cli::from_arg_matches(&matches)?;
    validate(&cli).map_err(|message| command.error(ErrorKind::ArgumentConflict, message))?;
    Ok(cli)
}

fn validate(cli: &Cli) -> Result<(), &'static str> {
    let mut is_switch = cli.switch;
    if cli.reset && is_switch {
        is_switch = false;
    }
    let actions = [cli.command.is_some(), cli.start, cli.stop, cli.reset, cli.monitor, is_switch,
        cli.test, cli.info, cli.doctor, cli.bench, cli.pentest, cli.update,
        cli.cleanup || cli.cleanup_full, cli.shred.is_some(), cli.select_lang,
        cli.completions.is_some(), cli.demo, cli.interfaces];
    let count = actions.into_iter().filter(|active| *active).count();
    if count > 1 { return Err("Choose one operation; command shortcuts and subcommands cannot be combined"); }
    if cli.command.is_some() && cli.start_opts.has_active_flags() {
        return Err("Put session options after 'start', or use them with -s; options before a subcommand would be ignored");
    }
    let mut options = cli.start_opts.clone();
    if cli.stop { options.forensic_self_destruct = false; } // documented -x -d
    if count == 1 && !cli.start && options.has_active_flags() {
        return Err("Session options require start/-s; only -d may accompany the -x stop shortcut");
    }
    Ok(())
}

pub fn parse_transport(value: &str) -> Result<String, String> {
    wraith_tor::PluggableTransportType::from_str(value)
        .map(|transport| transport.as_str().to_string())
        .ok_or_else(|| "Supported transports: obfs4, snowflake, meek-azure (webtunnel is not implemented)".into())
}

pub fn parse_bridge(value: &str) -> Result<String, String> {
    if value.eq_ignore_ascii_case("moat") { Ok("moat".into()) } else { parse_transport(value) }
}

pub fn language_override(args: &[OsString]) -> Option<String> {
    // No raw argv scanning: '--lang' in an exec payload belongs to the child.
    Cli::command().disable_help_flag(true).disable_help_subcommand(true).ignore_errors(true)
        .try_get_matches_from(args).ok()?.get_one::<String>("lang").cloned()
}

pub fn should_background(args: &StartArgs) -> bool {
    !args.strict_hardening && !args.daemon_worker && !args.select_interface && !args.select_doh
}

pub fn worker_arguments(mut args: Vec<OsString>) -> Vec<OsString> {
    let index = args.iter().position(|arg| arg == "--").unwrap_or(args.len());
    args.insert(index, "--daemon-worker".into());
    args
}

pub fn worker_is_ready(state: &wraith_core::StateData, child: u32, running: bool) -> bool {
    state.active && state.state == Some(wraith_core::State::Active) && state.pid == Some(child) && running
}

pub fn requires_root(command: &crate::Commands) -> bool {
    use crate::{BridgeAction, Commands};
    !matches!(command, Commands::Pentest | Commands::Interfaces { .. } | Commands::Config { .. }
        | Commands::Fetch { .. } | Commands::Update { .. } | Commands::Doh { select: false }
        | Commands::Bridge { action: None | Some(BridgeAction::List) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Commands;

    #[test]
    fn competing_shortcuts_and_subcommands_never_choose_by_precedence() {
        let selectors = ["-s", "-x", "--reset", "-r", "-i", "-t", "-c", "-u", "-M", "--doctor", "--bench", "--pentest", "--interfaces", "--demo", "--select-lang"];
        for (i, first) in selectors.iter().enumerate() {
            for second in selectors.iter().skip(i + 1) {
                assert!(parse(["wraith", *first, *second]).is_err(), "{first} {second}");
            }
            assert!(parse(["wraith", *first, "info"]).is_err(), "{first} info");
        }
        assert!(parse(["wraith", "--shred", "data", "-x"]).is_err());
        assert!(parse(["wraith", "--generate-completions", "bash", "-s"]).is_err());
    }

    #[test]
    fn session_options_cannot_silently_disappear() {
        for args in [vec!["wraith", "-F", "start"], vec!["wraith", "-F", "-i"],
            vec!["wraith", "-x", "-L"], vec!["wraith", "--morph-l4", "off", "info"],
            vec!["wraith", "--rotate", "60", "info"], vec!["wraith", "--no-ks", "-i"],
            vec!["wraith", "--tls-profile", "safari", "fetch", "https://example.org", "-o", "page"]] {
            assert!(parse(args).is_err());
        }
        for args in [vec!["wraith", "-Fs"], vec!["wraith", "-x", "-d"],
            vec!["wraith", "stop", "-d"], vec!["wraith", "start", "-F"],
            vec!["wraith", "-c", "--cleanup-full"]] { assert!(parse(args).is_ok()); }
    }

    #[test]
    fn help_uses_alias_scope_and_does_not_intercept_argument_values() {
        let error = parse(["wraith", "nics", "--help"]).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::DisplayHelp);
        assert!(error.to_string().contains("--all"));
        assert!(parse(["wraith", "--shred", "help"]).unwrap().shred.is_some());
        let error = parse(["wraith", "--help"]).err().unwrap();
        for flag in ["--morph-l4", "--tls-profile", "--display-sandbox"] { assert!(error.to_string().contains(flag)); }
    }

    #[test]
    fn general_flags_and_child_arguments_keep_their_scope() {
        let cli = parse(["wraith", "info", "-v", "--lang=tr"]).unwrap();
        assert!(cli.verbose);
        assert_eq!(cli.lang.as_deref(), Some("tr"));
        let args: Vec<OsString> = ["wraith", "--lang=tr", "exec", "--", "app", "--lang", "de", "--help", "-v"].into_iter().map(Into::into).collect();
        assert_eq!(language_override(&args).as_deref(), Some("tr"));
        let cli = parse(args).unwrap();
        assert!(!cli.verbose);
        assert!(matches!(cli.command, Some(Commands::Exec { command }) if command == ["app", "--lang", "de", "--help", "-v"]));
    }

    #[test]
    fn numeric_and_selection_errors_are_rejected_by_the_parser() {
        for value in ["0", "18446744073709551615"] { assert!(parse(["wraith", "-s", "--rotate", value]).is_err()); }
        for value in ["0", "256"] { assert!(parse(["wraith", "shred", "data", "--passes", value]).is_err()); }
        assert!(parse(["wraith", "-I", "eth0", "--select-interface"]).is_err());
        assert!(parse(["wraith", "-D", "quad9", "--select-doh"]).is_err());
        for value in ["webtunnel", "typo"] {
            assert!(parse(["wraith", "--bridge-type", value]).is_err());
            assert!(parse(["wraith", "bridge", "moat", "--transport", value]).is_err());
        }
    }

    #[test]
    fn interactive_start_and_worker_argument_boundaries_are_preserved() {
        let args = StartArgs { select_doh: true, ..Default::default() };
        assert!(!should_background(&args));
        assert!(should_background(&StartArgs::default()));
        for original in [vec!["-s", "--"], vec!["start", "--"], vec!["start"]] {
            let mut args = vec![OsString::from("wraith")];
            args.extend(worker_arguments(original.into_iter().map(Into::into).collect()));
            assert!(matches!(crate::resolve_command(&parse(args).unwrap()), Some(Commands::Start(args)) if args.daemon_worker));
        }
    }

    #[test]
    fn background_readiness_requires_our_childs_active_record() {
        let mut state = wraith_core::StateData::configured(|data| { data.active = true; data.state = Some(wraith_core::State::Active); data.pid = Some(10); });
        assert!(worker_is_ready(&state, 10, true));
        assert!(!worker_is_ready(&state, 11, true));
        assert!(!worker_is_ready(&state, 10, false));
        state.state = Some(wraith_core::State::Arming);
        assert!(!worker_is_ready(&state, 10, true));
    }


    #[test]
    fn test_rn_bundled_shortcut_resolves_to_reset() {
        for flag in ["-rN", "-rn", "--rN", "--rn", "rn", "rN"] {
            let cli = parse(["wraith", flag]).unwrap();
            assert!(cli.reset, "Expected reset for flag: {}", flag);
            assert_eq!(crate::resolve_command(&cli), Some(Commands::Reset { target: "network".to_string() }));
        }
    }

    #[test]
    fn listing_providers_does_not_require_privilege_but_bridge_writes_do() {
        for args in [vec!["wraith", "doh"], vec!["wraith", "bridge"], vec!["wraith", "bridge", "list"]] {
            assert!(!requires_root(&crate::resolve_command(&parse(args).unwrap()).unwrap()));
        }
        for args in [vec!["wraith", "bridge", "moat"], vec!["wraith", "-s"], vec!["wraith", "-x"]] {
            assert!(requires_root(&crate::resolve_command(&parse(args).unwrap()).unwrap()));
        }
    }
}

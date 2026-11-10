//! `printer_exporter`: a dependency-free Prometheus exporter for SNMP printers.
//!
//! Built against a Xerox(R) B225 MFP (Lexmark engine) but written against the
//! standard Printer-MIB (RFC 3805), Host-Resources-MIB and IF-MIB, so it works
//! with most network printers. The printer is scraped live on every
//! `/metrics` request, using SNMP GET/GETNEXT only: the exporter never sets a
//! value, prints, or scans.

mod http;
mod metrics;
mod snmp;

use std::env;
use std::io::Write;
use std::net::TcpListener;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

/// Hard cap on one scrape, however many rows the device keeps returning.
const SCRAPE_BUDGET: Duration = Duration::from_secs(60);

const USAGE: &str = "\
Prometheus exporter for SNMP printers.

Usage: printer_exporter [OPTIONS]

Options (each defaults to its environment variable, then the built-in default):
      --target <HOST>        printer IP/host        [env: PRINTER_TARGET]    [default: 127.0.0.1]
      --community <STRING>   SNMP v2c community     [env: PRINTER_COMMUNITY] [default: public]
                             (prefer the env var: flags are visible in `ps`)
      --snmp-port <PORT>     SNMP UDP port          [env: PRINTER_SNMP_PORT] [default: 161]
      --listen-addr <ADDR>   HTTP listen address    [env: EXPORTER_ADDR]     [default: 0.0.0.0]
      --listen-port <PORT>   HTTP listen port       [env: EXPORTER_PORT]     [default: 9109]
      --timeout <SECONDS>    per-request SNMP timeout [env: SNMP_TIMEOUT]    [default: 2.0]
      --once                 collect once, print metrics to stdout, exit
      --healthcheck          exit 0 if the exporter's own HTTP listener answers
                             (for container health checks; does not query the printer)
  -h, --help                 print this help
  -V, --version              print version
";

#[derive(Debug, PartialEq)]
struct Config {
    target: String,
    community: String,
    snmp_port: u16,
    listen_addr: String,
    listen_port: u16,
    timeout: f64,
    once: bool,
    healthcheck: bool,
}

#[derive(Debug, PartialEq)]
enum Parsed {
    Run(Config),
    Help,
    Version,
}

fn parse_num<T: FromStr>(what: &str, raw: &str) -> Result<T, String> {
    raw.trim().parse().map_err(|_| format!("invalid value {raw:?} for {what}"))
}

/// Build the configuration: built-in defaults, overridden by environment
/// variables, overridden by flags. Flags accept `--flag value` and
/// `--flag=value`.
fn parse_config(
    args: impl IntoIterator<Item = String>,
    env: impl Fn(&str) -> Option<String>,
) -> Result<Parsed, String> {
    // Empty variables count as unset (common with systemd EnvironmentFile).
    let env = |k: &str| env(k).filter(|v| !v.is_empty());
    let env_num = |k: &str, default: &str| parse_num(k, &env(k).unwrap_or_else(|| default.into()));

    let mut cfg = Config {
        target: env("PRINTER_TARGET").unwrap_or_else(|| "127.0.0.1".into()),
        community: env("PRINTER_COMMUNITY").unwrap_or_else(|| "public".into()),
        snmp_port: env_num("PRINTER_SNMP_PORT", "161")?,
        listen_addr: env("EXPORTER_ADDR").unwrap_or_else(|| "0.0.0.0".into()),
        listen_port: env_num("EXPORTER_PORT", "9109")?,
        timeout: parse_num("SNMP_TIMEOUT", &env("SNMP_TIMEOUT").unwrap_or_else(|| "2.0".into()))?,
        once: false,
        healthcheck: false,
    };

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (arg, None),
        };
        match flag.as_str() {
            "-h" | "--help" => return Ok(Parsed::Help),
            "-V" | "--version" => return Ok(Parsed::Version),
            "--once" if inline.is_none() => cfg.once = true,
            "--healthcheck" if inline.is_none() => cfg.healthcheck = true,
            "--target" | "--community" | "--snmp-port" | "--listen-addr" | "--listen-port"
            | "--timeout" => {
                let value = inline
                    .or_else(|| args.next())
                    .ok_or_else(|| format!("{flag} requires a value"))?;
                match flag.as_str() {
                    "--target" => cfg.target = value,
                    "--community" => cfg.community = value,
                    "--snmp-port" => cfg.snmp_port = parse_num(&flag, &value)?,
                    "--listen-addr" => cfg.listen_addr = value,
                    "--listen-port" => cfg.listen_port = parse_num(&flag, &value)?,
                    _ => cfg.timeout = parse_num(&flag, &value)?,
                }
            }
            _ => return Err(format!("unrecognized argument {flag:?}")),
        }
    }

    if !(cfg.timeout.is_finite() && cfg.timeout > 0.0 && cfg.timeout <= 3600.0) {
        return Err(format!("timeout must be between 0 and 3600 seconds, got {}", cfg.timeout));
    }
    if cfg.target.is_empty() {
        return Err("target must not be empty".into());
    }
    Ok(Parsed::Run(cfg))
}

fn main() -> ExitCode {
    let cfg = match parse_config(env::args().skip(1), |k| env::var(k).ok()) {
        Ok(Parsed::Run(cfg)) => cfg,
        Ok(Parsed::Help) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Parsed::Version) => {
            println!("printer_exporter {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("printer_exporter: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let client = snmp::Client {
        host: cfg.target.clone(),
        port: cfg.snmp_port,
        community: cfg.community.clone(),
        timeout: Duration::from_secs_f64(cfg.timeout),
        budget: SCRAPE_BUDGET,
    };

    if cfg.healthcheck {
        return if http::healthcheck(&cfg.listen_addr, cfg.listen_port) {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    if cfg.once {
        let body = metrics::collect(&client, &cfg.target);
        // Ignore a closed pipe (e.g. `--once | head`).
        let _ = std::io::stdout().write_all(body.as_bytes());
        return ExitCode::SUCCESS;
    }

    let listener = match TcpListener::bind((cfg.listen_addr.as_str(), cfg.listen_port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "printer_exporter: cannot listen on {}:{}: {e}",
                cfg.listen_addr, cfg.listen_port
            );
            return ExitCode::FAILURE;
        }
    };
    eprintln!(
        "printer_exporter: scraping {} via SNMP:{}, serving http://{}:{}/metrics",
        cfg.target, cfg.snmp_port, cfg.listen_addr, cfg.listen_port
    );
    http::serve(&listener, client, cfg.target);
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str], env: &[(&str, &str)]) -> Result<Parsed, String> {
        parse_config(args.iter().map(std::string::ToString::to_string), |k| {
            env.iter().find(|(name, _)| *name == k).map(|(_, v)| v.to_string())
        })
    }

    fn run(args: &[&str], env: &[(&str, &str)]) -> Config {
        match parse(args, env) {
            Ok(Parsed::Run(c)) => c,
            other => panic!("expected a config, got {other:?}"),
        }
    }

    #[test]
    fn defaults() {
        assert_eq!(
            run(&[], &[]),
            Config {
                target: "127.0.0.1".into(),
                community: "public".into(),
                snmp_port: 161,
                listen_addr: "0.0.0.0".into(),
                listen_port: 9109,
                timeout: 2.0,
                once: false,
                healthcheck: false,
            }
        );
    }

    #[test]
    fn env_overrides_defaults_and_flags_override_env() {
        let env = [
            ("PRINTER_TARGET", "10.0.0.1"),
            ("PRINTER_COMMUNITY", "secret"),
            ("PRINTER_SNMP_PORT", "1161"),
            ("EXPORTER_ADDR", "127.0.0.1"),
            ("EXPORTER_PORT", "9200"),
            ("SNMP_TIMEOUT", "0.5"),
        ];
        let c = run(&[], &env);
        assert_eq!((c.target.as_str(), c.community.as_str()), ("10.0.0.1", "secret"));
        assert_eq!((c.snmp_port, c.listen_port, c.timeout), (1161, 9200, 0.5));
        assert_eq!(c.listen_addr, "127.0.0.1");

        let c = run(
            &["--target", "printer.lan", "--listen-port=9300", "--timeout", "3", "--once"],
            &env,
        );
        assert_eq!(
            (c.target.as_str(), c.listen_port, c.timeout, c.once),
            ("printer.lan", 9300, 3.0, true)
        );
        assert_eq!(c.community, "secret"); // untouched env value survives
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse(&["--bogus"], &[]).is_err());
        assert!(parse(&["--target"], &[]).is_err());
        assert!(parse(&["--snmp-port", "99999"], &[]).is_err());
        assert!(parse(&["--timeout", "0"], &[]).is_err());
        assert!(parse(&["--timeout", "nan"], &[]).is_err());
        assert!(parse(&[], &[("EXPORTER_PORT", "abc")]).is_err());
        assert_eq!(parse(&["--help"], &[]), Ok(Parsed::Help));
        assert!(run(&["--healthcheck"], &[]).healthcheck);
    }
}

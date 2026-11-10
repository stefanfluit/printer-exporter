//! Scrape the printer and render Prometheus text exposition format.
//!
//! Metric names, labels and types match the Python reference so existing
//! dashboards keep working. Standard MIBs come first (portable), vendor OIDs
//! are best-effort extras that are skipped silently when absent.

use std::collections::HashMap;
use std::fmt::Display;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

use crate::snmp::{oid_to_string, parse_oid, Client, Oid, Session, SnmpError, Value};

// ---- OIDs -----------------------------------------------------------------

// System group
const SYS_DESCR: &str = "1.3.6.1.2.1.1.1.0";
const SYS_UPTIME: &str = "1.3.6.1.2.1.1.3.0";
const SYS_NAME: &str = "1.3.6.1.2.1.1.5.0";
const SYS_LOCATION: &str = "1.3.6.1.2.1.1.6.0";

// Printer-MIB (RFC 3805) and Host-Resources-MIB
const PRT_GENERAL_SERIAL: &str = "1.3.6.1.2.1.43.5.1.1.17.1"; // prtGeneralSerialNumber
const PRT_CONSOLE_DISPLAY: &str = "1.3.6.1.2.1.43.16.5.1.2.1.1"; // front-panel text
const PRT_MARKER_LIFECOUNT: &str = "1.3.6.1.2.1.43.10.2.1.4.1.1"; // lifetime impressions
const PRT_SUPPLY_DESC: &str = "1.3.6.1.2.1.43.11.1.1.6"; // <idx> -> description
const PRT_SUPPLY_MAX: &str = "1.3.6.1.2.1.43.11.1.1.8"; // <idx> -> max capacity
const PRT_SUPPLY_LEVEL: &str = "1.3.6.1.2.1.43.11.1.1.9"; // <idx> -> current level
const PRT_INPUT_MAX: &str = "1.3.6.1.2.1.43.8.2.1.9"; // <idx> -> tray capacity
const PRT_INPUT_LEVEL: &str = "1.3.6.1.2.1.43.8.2.1.10"; // <idx> -> tray level
const PRT_INPUT_NAME: &str = "1.3.6.1.2.1.43.8.2.1.13"; // <idx> -> tray name
const HR_PRINTER_STATUS: &str = "1.3.6.1.2.1.25.3.5.1.1"; // <idx> -> 1..5

// IF-MIB ifTable
const IF_DESCR: &str = "1.3.6.1.2.1.2.2.1.2";
const IF_OPER_STATUS: &str = "1.3.6.1.2.1.2.2.1.8";
const IF_IN_OCTETS: &str = "1.3.6.1.2.1.2.2.1.10";
const IF_OUT_OCTETS: &str = "1.3.6.1.2.1.2.2.1.16";

// Vendor extras (best-effort).
// Lexmark private serial: the standard prtGeneralSerialNumber returns a wrong
// numeric value on the Xerox B225 (Lexmark engine), so this one wins.
const LEXMARK_SERIAL: &str = "1.3.6.1.4.1.641.2.1.2.1.6.1";
// Xerox usage counters: value and name columns of the same table.
const XEROX_CNT_VALUE: &str = "1.3.6.1.4.1.253.8.53.13.2.1.6.1.20";
const XEROX_CNT_NAME: &str = "1.3.6.1.4.1.253.8.53.13.2.1.8.1.20";

const HR_PRINTER_STATES: [(i64, &str); 5] =
    [(1, "other"), (2, "unknown"), (3, "idle"), (4, "printing"), (5, "warmup")];

const UP_HELP: &str = "1 if the printer answered SNMP this scrape, else 0.";

// ---- Exposition format ----------------------------------------------------

/// Escape a label value: backslash, double quote and newline.
pub fn escape_label(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

struct Family {
    name: &'static str,
    kind: &'static str,
    help: &'static str,
    samples: Vec<String>,
}

/// Samples grouped per metric family, rendered in first-use order so each
/// `# HELP`/`# TYPE` header is followed by all of its series.
#[derive(Default)]
struct Metrics {
    families: Vec<Family>,
}

impl Metrics {
    fn add(
        &mut self,
        name: &'static str,
        kind: &'static str,
        help: &'static str,
        labels: &[(&str, &str)],
        value: impl Display,
    ) {
        let labels = labels
            .iter()
            .map(|(k, v)| format!("{k}=\"{}\"", escape_label(v)))
            .collect::<Vec<_>>()
            .join(",");
        let sample = format!("{name}{{{labels}}} {value}");
        match self.families.iter_mut().find(|f| f.name == name) {
            Some(f) => f.samples.push(sample),
            None => self.families.push(Family { name, kind, help, samples: vec![sample] }),
        }
    }

    fn render(&self) -> String {
        let mut out = String::new();
        for f in &self.families {
            out.push_str(
                &["# HELP ", f.name, " ", f.help, "\n# TYPE ", f.name, " ", f.kind, "\n"].concat(),
            );
            for s in &f.samples {
                out.push_str(s);
                out.push('\n');
            }
        }
        out
    }
}

/// Round to 4 decimals, like the reference's `round(x, 4)`.
fn round4(x: f64) -> f64 {
    (x * 1e4).round() / 1e4
}

/// The body served when the printer cannot be scraped: `printer_up 0`, the
/// reason as a comment, and nothing else.
fn down_body(target: &str, error: &str) -> String {
    format!(
        "# HELP printer_up {UP_HELP}\n# TYPE printer_up gauge\nprinter_up{{target=\"{}\"}} 0\n# scrape error: {}\n",
        escape_label(target),
        error.replace(['\n', '\r'], " "),
    )
}

// ---- SNMP helpers ---------------------------------------------------------

fn oid(s: &str) -> Oid {
    parse_oid(s).expect("built-in OID constants are valid")
}

/// GET that treats any failure as "absent", so one bad OID never sinks the
/// scrape (reachability is decided once, by the sysUpTime probe).
fn get(s: &mut Session, o: &str) -> Option<Value> {
    s.get(&oid(o)).ok().flatten()
}

/// Walk one table column into `(row index suffix, value)` pairs in agent
/// order. The index is whatever follows the column OID, e.g. `1.1`; columns
/// of the same table are joined on it.
fn column(s: &mut Session, o: &str) -> Vec<(String, Value)> {
    let base = oid(o);
    s.walk(&base)
        .unwrap_or_default()
        .into_iter()
        .map(|(row, v)| (oid_to_string(&row[base.len()..]), v))
        .collect()
}

fn column_map(s: &mut Session, o: &str) -> HashMap<String, Value> {
    column(s, o).into_iter().collect()
}

// ---- Collection -----------------------------------------------------------

/// Scrape the printer and return the exposition text. Never fails: any error
/// (and even a panic) becomes `printer_up 0`, so Prometheus sees a
/// successful scrape reporting a down printer rather than an HTTP error.
pub fn collect(client: &Client, target: &str) -> String {
    catch_unwind(AssertUnwindSafe(|| match scrape(client, target) {
        Ok(body) => body,
        Err(e) => down_body(target, &e.to_string()),
    }))
    .unwrap_or_else(|_| down_body(target, "internal error (panic) during collection"))
}

// One linear pass over the MIBs reads better than a dozen tiny helpers.
#[allow(clippy::too_many_lines)]
fn scrape(client: &Client, target: &str) -> Result<String, SnmpError> {
    let start = Instant::now();
    let mut m = Metrics::default();
    let mut s = client.connect()?;
    let t = ("target", target);

    // ---- Reachability probe: sysUpTime is cheap and universal. This is the
    // only request whose failure marks the printer as down.
    let ticks = s
        .get(&oid(SYS_UPTIME))?
        .and_then(|v| v.as_u64())
        .ok_or(SnmpError::Decode("sysUpTime missing or not numeric"))?;
    m.add("printer_up", "gauge", UP_HELP, &[t], 1);

    // ---- Identity
    let text = |s: &mut Session, o: &str| get(s, o).and_then(|v| v.label()).unwrap_or_default();
    let sys_name = text(&mut s, SYS_NAME);
    let sys_descr = text(&mut s, SYS_DESCR);
    let location = text(&mut s, SYS_LOCATION);
    let mut serial = text(&mut s, LEXMARK_SERIAL);
    if serial.is_empty() {
        serial = text(&mut s, PRT_GENERAL_SERIAL);
    }
    m.add(
        "printer_info",
        "gauge",
        "Static printer identity; value is always 1.",
        &[
            t,
            ("sys_name", &sys_name),
            ("sys_descr", &sys_descr),
            ("location", &location),
            ("serial", &serial),
        ],
        1,
    );

    // ---- Uptime: TimeTicks are hundredths of a second.
    m.add(
        "printer_uptime_seconds",
        "gauge",
        "Device uptime (sysUpTime), seconds.",
        &[t],
        ticks as f64 / 100.0,
    );

    // ---- Printer state as a stateset: 1 for the active state, 0 otherwise.
    if let Some((_, raw)) = column(&mut s, HR_PRINTER_STATUS).first() {
        let current = raw.as_i64().unwrap_or(0);
        for (code, state) in HR_PRINTER_STATES {
            m.add(
                "printer_status",
                "gauge",
                "hrPrinterStatus as a stateset (1 marks the active state).",
                &[t, ("state", state)],
                u8::from(code == current),
            );
        }
    }

    // ---- Console message
    if let Some(msg) = get(&mut s, PRT_CONSOLE_DISPLAY).and_then(|v| v.label()) {
        m.add(
            "printer_console_message",
            "gauge",
            "Front-panel display string; value always 1.",
            &[t, ("message", &msg)],
            1,
        );
    }

    // ---- Page / impression counter
    if let Some(life) = get(&mut s, PRT_MARKER_LIFECOUNT).and_then(|v| v.as_u64()) {
        m.add(
            "printer_marker_life_count_total",
            "counter",
            "Lifetime marker impressions (prtMarkerLifeCount).",
            &[t],
            life,
        );
    }

    // ---- Supplies (toner, imaging unit, ...). Levels may be sentinels:
    // -2 = unknown, -3 = some remaining; the ratio is only meaningful for
    // real values.
    let names = column_map(&mut s, PRT_SUPPLY_DESC);
    let maxes = column_map(&mut s, PRT_SUPPLY_MAX);
    for (idx, level) in column(&mut s, PRT_SUPPLY_LEVEL) {
        let Some(level) = level.as_i64() else { continue };
        let name =
            names.get(&idx).and_then(Value::label).unwrap_or_else(|| format!("supply-{idx}"));
        let labels = [t, ("supply", name.as_str())];
        m.add(
            "printer_supply_level_units",
            "gauge",
            "Current supply level in the device's native units.",
            &labels,
            level,
        );
        let Some(max) = maxes.get(&idx).and_then(Value::as_i64) else { continue };
        m.add(
            "printer_supply_max_units",
            "gauge",
            "Maximum supply capacity in native units (-2 = unknown).",
            &labels,
            max,
        );
        if max > 0 && level >= 0 {
            m.add(
                "printer_supply_level_ratio",
                "gauge",
                "Supply remaining as a 0..1 ratio (only when max > 0).",
                &labels,
                round4(level as f64 / max as f64),
            );
        }
    }

    // ---- Input trays
    let names = column_map(&mut s, PRT_INPUT_NAME);
    let maxes = column_map(&mut s, PRT_INPUT_MAX);
    for (idx, level) in column(&mut s, PRT_INPUT_LEVEL) {
        let name = names.get(&idx).and_then(Value::label).unwrap_or_else(|| format!("tray-{idx}"));
        let labels = [t, ("tray", name.as_str())];
        if let Some(level) = level.as_i64() {
            m.add(
                "printer_input_tray_level_sheets",
                "gauge",
                "Sheets currently in the input tray (-3 = at least one).",
                &labels,
                level,
            );
        }
        if let Some(max) = maxes.get(&idx).and_then(Value::as_i64) {
            m.add(
                "printer_input_tray_max_sheets",
                "gauge",
                "Input tray maximum capacity in sheets.",
                &labels,
                max,
            );
        }
    }

    // ---- Network interfaces
    let interfaces = column(&mut s, IF_DESCR);
    if !interfaces.is_empty() {
        let rx = column_map(&mut s, IF_IN_OCTETS);
        let tx = column_map(&mut s, IF_OUT_OCTETS);
        let oper = column_map(&mut s, IF_OPER_STATUS);
        for (idx, name) in interfaces {
            let name = name.label().unwrap_or_else(|| format!("if-{idx}"));
            let labels = [t, ("interface", name.as_str())];
            if let Some(v) = rx.get(&idx).and_then(Value::as_u64) {
                m.add(
                    "printer_network_receive_bytes_total",
                    "counter",
                    "Interface ifInOctets.",
                    &labels,
                    v,
                );
            }
            if let Some(v) = tx.get(&idx).and_then(Value::as_u64) {
                m.add(
                    "printer_network_transmit_bytes_total",
                    "counter",
                    "Interface ifOutOctets.",
                    &labels,
                    v,
                );
            }
            if let Some(v) = oper.get(&idx).and_then(Value::as_i64) {
                m.add(
                    "printer_network_interface_up",
                    "gauge",
                    "1 if ifOperStatus is up(1), else 0.",
                    &labels,
                    u8::from(v == 1),
                );
            }
        }
    }

    // ---- Vendor extra: Xerox usage counters (skipped silently if empty)
    let names = column_map(&mut s, XEROX_CNT_NAME);
    for (idx, value) in column(&mut s, XEROX_CNT_VALUE) {
        let Some(value) = value.as_u64() else { continue };
        let name =
            names.get(&idx).and_then(Value::label).unwrap_or_else(|| format!("counter-{idx}"));
        m.add(
            "printer_usage_counter_total",
            "counter",
            "Vendor usage counter (Xerox/Lexmark impressions table).",
            &[t, ("counter", &name)],
            value,
        );
    }

    // ---- Scrape self-metric
    m.add(
        "printer_scrape_duration_seconds",
        "gauge",
        "Time taken to collect metrics from the printer.",
        &[t],
        round4(start.elapsed().as_secs_f64()),
    );
    Ok(m.render())
}

// ---- Tests ----------------------------------------------------------------

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::snmp::testutil::*;
    use crate::snmp::{TAG_COUNTER32, TAG_TIMETICKS};
    use std::time::Duration;

    pub fn client(port: u16) -> Client {
        Client {
            host: "127.0.0.1".into(),
            port,
            community: "public".into(),
            timeout: Duration::from_millis(500),
            budget: Duration::from_secs(30),
        }
    }

    /// A MIB shaped like a real Xerox B225 (identifiers are made up).
    pub fn sample_mib() -> Mib {
        let mut mib = Mib::new();
        let mut put = |o: &str, v| {
            mib.insert(parse_oid(o).unwrap(), v);
        };
        put(
            SYS_DESCR,
            text("Xerox(R) B225 MFP; SS MXLSG.230.513, kernel 5.4.254-yocto-standard, All-N-1"),
        );
        put(SYS_UPTIME, uint(TAG_TIMETICKS, 308_112_257));
        put(SYS_NAME, text("printer01"));
        put(SYS_LOCATION, text("Office"));
        put(PRT_GENERAL_SERIAL, text("1234567890")); // the wrong, numeric one
        put(LEXMARK_SERIAL, text("SN0123456789A"));
        put(&format!("{HR_PRINTER_STATUS}.1"), int(3));
        put(PRT_CONSOLE_DISPLAY, text("Ready"));
        put(PRT_MARKER_LIFECOUNT, uint(TAG_COUNTER32, 156));
        // Supplies: a real level, and one with sentinel values.
        put(&format!("{PRT_SUPPLY_DESC}.1.1"), text("Black Cartridge CRU;SN0000000001"));
        put(&format!("{PRT_SUPPLY_MAX}.1.1"), int(1200));
        put(&format!("{PRT_SUPPLY_LEVEL}.1.1"), int(1044));
        put(&format!("{PRT_SUPPLY_DESC}.1.2"), text("Imaging \"Unit\""));
        put(&format!("{PRT_SUPPLY_MAX}.1.2"), int(-2));
        put(&format!("{PRT_SUPPLY_LEVEL}.1.2"), int(-3));
        put(&format!("{PRT_INPUT_MAX}.1.1"), int(250));
        put(&format!("{PRT_INPUT_LEVEL}.1.1"), int(250));
        put(&format!("{PRT_INPUT_NAME}.1.1"), text("Tray 1"));
        put(&format!("{IF_DESCR}.1"), text("lo"));
        put(&format!("{IF_DESCR}.2"), text("wlan0"));
        put(&format!("{IF_OPER_STATUS}.1"), int(1));
        put(&format!("{IF_OPER_STATUS}.2"), int(2));
        put(&format!("{IF_IN_OCTETS}.1"), uint(TAG_COUNTER32, 1000));
        put(&format!("{IF_IN_OCTETS}.2"), uint(TAG_COUNTER32, 31_010_146));
        put(&format!("{IF_OUT_OCTETS}.1"), uint(TAG_COUNTER32, 1000));
        put(&format!("{IF_OUT_OCTETS}.2"), uint(TAG_COUNTER32, 4_000_000_000));
        put(&format!("{XEROX_CNT_VALUE}.1"), int(156));
        put(&format!("{XEROX_CNT_NAME}.1"), text("Total Impressions"));
        mib
    }

    #[test]
    fn full_scrape_matches_expected_shape() {
        let out = collect(&client(spawn_agent(sample_mib())), "192.0.2.10");
        let expected = [
            r#"printer_up{target="192.0.2.10"} 1"#,
            r#"printer_info{target="192.0.2.10",sys_name="printer01",sys_descr="Xerox(R) B225 MFP; SS MXLSG.230.513, kernel 5.4.254-yocto-standard, All-N-1",location="Office",serial="SN0123456789A"} 1"#,
            r#"printer_uptime_seconds{target="192.0.2.10"} 3081122.57"#,
            r#"printer_status{target="192.0.2.10",state="other"} 0"#,
            r#"printer_status{target="192.0.2.10",state="idle"} 1"#,
            r#"printer_status{target="192.0.2.10",state="warmup"} 0"#,
            r#"printer_console_message{target="192.0.2.10",message="Ready"} 1"#,
            r#"printer_marker_life_count_total{target="192.0.2.10"} 156"#,
            r#"printer_supply_level_units{target="192.0.2.10",supply="Black Cartridge CRU;SN0000000001"} 1044"#,
            r#"printer_supply_max_units{target="192.0.2.10",supply="Black Cartridge CRU;SN0000000001"} 1200"#,
            r#"printer_supply_level_ratio{target="192.0.2.10",supply="Black Cartridge CRU;SN0000000001"} 0.87"#,
            r#"printer_supply_level_units{target="192.0.2.10",supply="Imaging \"Unit\""} -3"#,
            r#"printer_supply_max_units{target="192.0.2.10",supply="Imaging \"Unit\""} -2"#,
            r#"printer_input_tray_level_sheets{target="192.0.2.10",tray="Tray 1"} 250"#,
            r#"printer_input_tray_max_sheets{target="192.0.2.10",tray="Tray 1"} 250"#,
            r#"printer_network_receive_bytes_total{target="192.0.2.10",interface="wlan0"} 31010146"#,
            r#"printer_network_transmit_bytes_total{target="192.0.2.10",interface="wlan0"} 4000000000"#,
            r#"printer_network_interface_up{target="192.0.2.10",interface="lo"} 1"#,
            r#"printer_network_interface_up{target="192.0.2.10",interface="wlan0"} 0"#,
            r#"printer_usage_counter_total{target="192.0.2.10",counter="Total Impressions"} 156"#,
            "# TYPE printer_marker_life_count_total counter",
            "# TYPE printer_network_receive_bytes_total counter",
            "# TYPE printer_usage_counter_total counter",
            "# TYPE printer_status gauge",
        ];
        let lines: Vec<&str> = out.lines().collect();
        for want in expected {
            assert!(lines.contains(&want), "missing line:\n{want}\n\nin output:\n{out}");
        }
        // Sentinel supply levels must not produce a ratio.
        assert_eq!(
            lines.iter().filter(|l| l.starts_with("printer_supply_level_ratio{")).count(),
            1
        );
        assert!(out.contains("printer_scrape_duration_seconds{target=\"192.0.2.10\"} "));
        assert!(out.ends_with('\n'));

        // Exposition hygiene: one HELP/TYPE per family, families contiguous.
        let mut seen = Vec::new();
        for l in lines.iter().filter(|l| !l.starts_with('#')) {
            let name = l.split('{').next().unwrap();
            if seen.last() != Some(&name) {
                assert!(!seen.contains(&name), "family {name} is not contiguous");
                seen.push(name);
            }
        }
        assert_eq!(out.matches("# TYPE ").count(), seen.len());
    }

    #[test]
    fn serial_falls_back_to_standard_oid() {
        let mut mib = sample_mib();
        mib.remove(&parse_oid(LEXMARK_SERIAL).unwrap());
        let out = collect(&client(spawn_agent(mib)), "p");
        assert!(out.contains(r#"serial="1234567890""#), "{out}");
    }

    #[test]
    fn minimal_agent_emits_only_what_exists() {
        // Only sysUpTime: up, info (empty labels), uptime, duration.
        let mut mib = Mib::new();
        mib.insert(parse_oid(SYS_UPTIME).unwrap(), uint(TAG_TIMETICKS, 100));
        let out = collect(&client(spawn_agent(mib)), "p");
        let names: Vec<&str> = out
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(|l| l.split('{').next().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "printer_up",
                "printer_info",
                "printer_uptime_seconds",
                "printer_scrape_duration_seconds"
            ]
        );
        assert!(out.contains("printer_uptime_seconds{target=\"p\"} 1\n"));
    }

    #[test]
    fn unreachable_printer_reports_up_zero_only() {
        // A bound socket nobody reads from: every request times out.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut c = client(silent.local_addr().unwrap().port());
        c.timeout = Duration::from_millis(100);
        let out = collect(&c, "printer \"x\"");
        let series: Vec<&str> = out.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(series, [r#"printer_up{target="printer \"x\""} 0"#]);
        assert!(out.contains("# scrape error: SNMP request timed out"), "{out}");
    }

    #[test]
    fn unresolvable_host_reports_up_zero() {
        let mut c = client(161);
        c.host = "no-such-host.invalid".into();
        let out = collect(&c, "no-such-host.invalid");
        assert!(out.contains("printer_up{target=\"no-such-host.invalid\"} 0\n"), "{out}");
        assert!(out.contains("# scrape error: "));
    }

    #[test]
    fn label_escaping() {
        assert_eq!(escape_label("a\\b\"c\nd"), "a\\\\b\\\"c\\nd");
        assert_eq!(escape_label("plain ünï"), "plain ünï");
    }
}

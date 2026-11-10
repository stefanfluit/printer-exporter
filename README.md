# printer_exporter

A Prometheus exporter for network printers, speaking SNMP v2c. It is a Rust
port of `printer_exporter.py` with the same metric names, labels and types.

- Scrapes the printer live on every `GET /metrics`.
- Read-only: issues SNMP GET and GETNEXT only. It never sets a value, prints or scans.
- Never fails a scrape: if the printer does not answer, the response is still
  HTTP 200 with `printer_up{target="..."} 0` and a `# scrape error:` comment.
- No dependencies. SNMP/BER, the HTTP server and flag parsing are hand-rolled
  on the standard library (`src/snmp.rs`, `src/http.rs`, `src/main.rs`).
- Ships as a static binary and as a `FROM scratch` container image that runs
  as an unprivileged user.

Built and verified against a Xerox(R) B225 MFP (Lexmark engine, firmware
`MXLSG.230.513`). It targets the standard Printer-MIB (RFC 3805),
Host-Resources-MIB and IF-MIB, so it should work with most network printers;
Xerox/Lexmark private OIDs are collected when present and skipped otherwise.

## Install

### Container image

Images for amd64 and arm64 are published to the GitHub Container Registry:

```sh
podman run -d --name printer-exporter \
    --read-only --cap-drop=ALL --security-opt=no-new-privileges \
    -p 9109:9109 \
    -e PRINTER_TARGET=192.0.2.10 \
    ghcr.io/stefanfluit/printer-exporter:latest
```

`docker run` takes the same arguments. The image is built `FROM scratch`: it
contains the exporter binary and nothing else (no shell, no libc, no package
manager). It runs as UID/GID 65534, listens on an unprivileged port, needs no
capabilities and no writable filesystem, so the flags above cost nothing.
Pin a version tag (or a digest) rather than `latest` for anything long-lived.

### Binary

Static Linux binaries for amd64 and arm64 are attached to each
[release](https://github.com/stefanfluit/printer-exporter/releases), with a
`SHA256SUMS` file and a build provenance attestation:

```sh
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify printer_exporter-*-linux-amd64.tar.gz --repo stefanfluit/printer-exporter
```

### From source

Requires Rust (the version is pinned in `rust-toolchain.toml`).

```sh
cargo build --release      # binary: target/release/printer_exporter
cargo test
```

To build the container image yourself:

```sh
podman build -t printer-exporter .
docker build -f Containerfile -t printer-exporter .
```

## Run

```sh
# Serve http://0.0.0.0:9109/metrics
printer_exporter --target 192.0.2.10

# Collect once, print to stdout, exit (testing / CI)
printer_exporter --target 192.0.2.10 --once
```

## Configuration

Each flag defaults to its environment variable, then to the built-in default.
Flags accept `--flag value` and `--flag=value`.

| Flag | Environment variable | Default | Meaning |
|---|---|---|---|
| `--target` | `PRINTER_TARGET` | `127.0.0.1` | Printer IP or host name |
| `--community` | `PRINTER_COMMUNITY` | `public` | SNMP v2c community |
| `--snmp-port` | `PRINTER_SNMP_PORT` | `161` | SNMP UDP port |
| `--listen-addr` | `EXPORTER_ADDR` | `0.0.0.0` | HTTP listen address |
| `--listen-port` | `EXPORTER_PORT` | `9109` | HTTP listen port |
| `--timeout` | `SNMP_TIMEOUT` | `2.0` | Per-request SNMP timeout, seconds |
| `--once` | | off | Collect once, print to stdout, exit |
| `--healthcheck` | | off | Exit 0 if the exporter's own HTTP listener answers (used by the container `HEALTHCHECK`; does not query the printer) |

## Metrics

Every series carries a `target` label with the value of `--target`.

| Metric | Type | Extra labels | Source |
|---|---|---|---|
| `printer_up` | gauge | | 1 if `sysUpTime` was answered |
| `printer_info` | gauge (always 1) | `sys_name`, `sys_descr`, `location`, `serial` | system group, serial number |
| `printer_uptime_seconds` | gauge | | `sysUpTime` |
| `printer_status` | gauge (stateset) | `state`: other, unknown, idle, printing, warmup | `hrPrinterStatus` |
| `printer_console_message` | gauge (always 1) | `message` | `prtConsoleDisplayBufferText` |
| `printer_marker_life_count_total` | counter | | `prtMarkerLifeCount` |
| `printer_supply_level_units` | gauge | `supply` | `prtMarkerSuppliesLevel` |
| `printer_supply_max_units` | gauge | `supply` | `prtMarkerSuppliesMaxCapacity` |
| `printer_supply_level_ratio` | gauge | `supply` | level / max, only when max > 0 and level >= 0 |
| `printer_input_tray_level_sheets` | gauge | `tray` | `prtInputCurrentLevel` |
| `printer_input_tray_max_sheets` | gauge | `tray` | `prtInputMaxCapacity` |
| `printer_network_receive_bytes_total` | counter | `interface` | `ifInOctets` |
| `printer_network_transmit_bytes_total` | counter | `interface` | `ifOutOctets` |
| `printer_network_interface_up` | gauge | `interface` | 1 if `ifOperStatus` is up(1) |
| `printer_usage_counter_total` | counter | `counter` | Xerox usage counter table (vendor extra) |
| `printer_scrape_duration_seconds` | gauge | | time spent talking to the printer |

Notes:

- Supply and tray levels can be Printer-MIB sentinels: `-2` means unknown and
  `-3` means "some remaining". They are exported as-is; no ratio is computed
  for them.
- `serial` is read from the Lexmark private OID `1.3.6.1.4.1.641.2.1.2.1.6.1`
  first, because the standard `prtGeneralSerialNumber` returns a wrong numeric
  value on the B225. The standard OID is the fallback.
- Octet strings that are not printable UTF-8 are exported as lowercase hex.

### Differences from the Python reference

- `serial` is the real serial number (see above).
- When the printer is down, only `printer_up 0` is emitted. The reference also
  emitted `printer_scrape_duration_seconds`.
- `/` is a landing page. The reference served metrics there by accident.
- All samples of a metric follow its `# HELP`/`# TYPE` header. The reference
  interleaved the supply, tray and interface metrics.
- Newlines in label values are escaped as `\n` rather than replaced by a space.
- Whole-valued floats print without a trailing `.0` (`1` rather than `1.0`).

## Prometheus

```yaml
scrape_configs:
  - job_name: printer
    scrape_interval: 60s
    scrape_timeout: 30s
    static_configs:
      - targets: ["localhost:9109"]
```

The scrape timeout is generous on purpose. The B225 takes about 0.3 s per
request on the Xerox usage counter table, so a full scrape takes 6 to 7 s
there (0.8 s without the vendor table). Check
`printer_scrape_duration_seconds` on your device and size the timeout to it.

Example alerts:

```yaml
- alert: PrinterDown
  expr: printer_up == 0
  for: 10m
- alert: PrinterTonerLow
  expr: printer_supply_level_ratio < 0.10
```

## systemd

`/etc/systemd/system/printer-exporter.service`:

```ini
[Unit]
Description=Prometheus SNMP printer exporter
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/printer_exporter
Environment=PRINTER_TARGET=192.0.2.10
Environment=PRINTER_COMMUNITY=public
Environment=EXPORTER_ADDR=127.0.0.1
Environment=EXPORTER_PORT=9109
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```sh
sudo install -m 0755 target/release/printer_exporter /usr/local/bin/
sudo systemctl daemon-reload
sudo systemctl enable --now printer-exporter
curl -s localhost:9109/metrics | head
```

## Security

- The exporter only ever sends SNMP GET and GETNEXT. It has no code path that
  can change the printer.
- `/metrics` has no authentication or TLS, like most exporters. It exposes
  the printer's name, location, serial number and counters. Bind it to
  loopback (`EXPORTER_ADDR=127.0.0.1`) or a monitoring network, or publish
  the container port on a specific address (`-p 127.0.0.1:9109:9109`).
- SNMP v2c sends the community string in clear text. Use a read-only
  community, and pass it with `PRINTER_COMMUNITY` rather than `--community`,
  because command-line flags are visible to other local users in `ps`.
- Resource use is bounded so the listener can face untrusted clients: at most
  16 concurrent connections, a 5 s deadline and 8 KiB limit on the request
  head, one SNMP scrape at a time, and a 60 s cap on a whole scrape.
- Everything the printer sends is treated as untrusted. The BER decoder is
  bounds-checked (and tested against corrupted input), the crate forbids
  `unsafe`, and device strings are escaped before they reach the output.
- The build is pinned: no third-party crates, base image by digest, GitHub
  Actions by commit SHA. The container build runs without network access.

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## Layout

| File | Contents |
|---|---|
| `src/snmp.rs` | BER encode/decode, SNMP v2c GET and walk over UDP, test agent |
| `src/metrics.rs` | OIDs, table joins, Prometheus text rendering |
| `src/http.rs` | `/metrics` and `/` over `std::net::TcpListener` |
| `src/main.rs` | Flags, environment variables, startup |
| `Containerfile` | Multi-stage build to a rootless `FROM scratch` image |
| `printer_exporter.py` | The original Python implementation, kept for reference |

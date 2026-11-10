//! Minimal HTTP/1.1 server on std: `GET /metrics` and a landing page.
//!
//! One short-lived thread per connection, `Connection: close` on every
//! response. That is all a Prometheus scrape target needs, and it keeps the
//! exporter free of an HTTP dependency.
//!
//! The listener may be reachable by untrusted hosts, so resource use is
//! bounded: a fixed number of concurrent connections, a deadline and size
//! limit on the request head, and one SNMP scrape at a time so HTTP clients
//! cannot use the exporter to flood the printer.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::metrics::collect;
use crate::snmp::Client;

/// Connections served at once; further ones get an immediate 503.
const MAX_CONNECTIONS: usize = 16;
/// Total time a client gets to send its request head (slowloris guard).
const HEAD_DEADLINE: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST_HEAD: usize = 8 * 1024;

const TEXT: &str = "text/plain; charset=utf-8";
const LANDING_PAGE: &str = "<html><head><title>printer_exporter</title></head>\
<body><h1>printer_exporter</h1>\
<p><a href=\"/metrics\">Metrics</a></p></body></html>\n";

struct Shared {
    client: Client,
    target: String,
    /// Serialises scrapes: the printer sees one walk at a time no matter how
    /// many HTTP clients ask.
    scrape: Mutex<()>,
    active: AtomicUsize,
}

/// Releases a connection slot when the handler thread ends, panic or not.
struct Slot(Arc<Shared>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Accept connections forever.
pub fn serve(listener: &TcpListener, client: Client, target: String) {
    let shared =
        Arc::new(Shared { client, target, scrape: Mutex::new(()), active: AtomicUsize::new(0) });
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else {
            // e.g. out of file descriptors: back off instead of spinning.
            thread::sleep(Duration::from_millis(50));
            continue;
        };
        if shared.active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
            shared.active.fetch_sub(1, Ordering::AcqRel);
            // A few bytes into an empty send buffer: cannot block the loop.
            let _ = respond(&mut stream, "503 Service Unavailable", TEXT, "busy\n", false);
            continue;
        }
        let slot = Slot(Arc::clone(&shared));
        let spawned = thread::Builder::new().name("http".into()).spawn(move || {
            // A client hanging up mid-response is not worth logging.
            let _ = handle(stream, &slot.0);
        });
        if spawned.is_err() {
            // Thread limit reached; the closure (and its slot) was dropped.
            thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Read the request head, up to the blank line. `None` means the client was
/// too slow or sent too much. GET and HEAD carry no body.
fn read_head(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let deadline = Instant::now() + HEAD_DEADLINE;
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || head.len() > MAX_REQUEST_HEAD {
            return Ok(None);
        }
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => head.extend_from_slice(&chunk[..n]),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(Some(head))
}

fn handle(mut stream: TcpStream, shared: &Shared) -> io::Result<()> {
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let Some(head) = read_head(&mut stream)? else {
        return respond(
            &mut stream,
            "408 Request Timeout",
            TEXT,
            "request too slow or too large\n",
            false,
        );
    };

    // Request line: METHOD SP request-target SP HTTP-version
    let head = String::from_utf8_lossy(&head);
    let mut parts = head.lines().next().unwrap_or("").split_whitespace();
    let (Some(method), Some(uri)) = (parts.next(), parts.next()) else {
        return respond(&mut stream, "400 Bad Request", TEXT, "bad request\n", false);
    };
    let head_only = method == "HEAD";
    if method != "GET" && !head_only {
        return respond(&mut stream, "405 Method Not Allowed", TEXT, "method not allowed\n", false);
    }

    match uri.split(['?', '#']).next().unwrap_or("") {
        // Always 200: collect() reports failures as `printer_up 0`.
        "/metrics" | "/metrics/" => {
            let body = if head_only {
                String::new()
            } else {
                // The guard protects no data, so a poisoned lock is harmless.
                let _one_at_a_time = shared.scrape.lock().unwrap_or_else(PoisonError::into_inner);
                collect(&shared.client, &shared.target)
            };
            respond(
                &mut stream,
                "200 OK",
                "text/plain; version=0.0.4; charset=utf-8",
                &body,
                head_only,
            )
        }
        "/" => respond(&mut stream, "200 OK", "text/html; charset=utf-8", LANDING_PAGE, head_only),
        _ => respond(&mut stream, "404 Not Found", TEXT, "not found\n", head_only),
    }
}

fn respond(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
    head_only: bool,
) -> io::Result<()> {
    // nosniff: label values come from the device, so make sure no browser
    // ever decides the metrics page is HTML.
    let mut out = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    if !head_only {
        out.extend_from_slice(body.as_bytes());
    }
    stream.write_all(&out)?;
    stream.flush()?;
    stream.shutdown(Shutdown::Write)
}

/// Liveness probe for container runtimes: does the exporter's own listener
/// answer `GET /`? Deliberately does not touch the printer; a printer that is
/// switched off is reported by `printer_up`, not by restarting the exporter.
pub fn healthcheck(listen_addr: &str, port: u16) -> bool {
    const TIMEOUT: Duration = Duration::from_secs(2);
    // A wildcard listen address is reachable through loopback.
    let host = match listen_addr {
        "0.0.0.0" => "127.0.0.1",
        "::" | "[::]" => "::1",
        other => other,
    };
    let probe = || -> io::Result<bool> {
        let addr = (host, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address"))?;
        let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
        let mut status = [0u8; 12];
        stream.read_exact(&mut status)?;
        Ok(&status == b"HTTP/1.1 200")
    };
    probe().unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::tests::{client, sample_mib};
    use crate::snmp::testutil::spawn_agent;

    /// Start the server against `snmp_port` and return its HTTP port.
    fn start(snmp_port: u16) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut c = client(snmp_port);
        c.timeout = Duration::from_millis(200);
        thread::spawn(move || serve(&listener, c, "test-printer".into()));
        port
    }

    fn request(port: u16, raw: &str) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(raw.as_bytes()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    }

    fn get(port: u16, path: &str) -> String {
        request(port, &format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n"))
    }

    #[test]
    fn serves_metrics_landing_page_and_404() {
        let port = start(spawn_agent(sample_mib()));

        let metrics = get(port, "/metrics");
        assert!(metrics.starts_with("HTTP/1.1 200 OK\r\n"), "{metrics}");
        assert!(metrics.contains("Content-Type: text/plain; version=0.0.4"));
        assert!(metrics.contains("X-Content-Type-Options: nosniff"));
        assert!(metrics.contains("printer_up{target=\"test-printer\"} 1\n"));
        assert!(metrics.contains("serial=\"SN0123456789A\""));

        // Content-Length must match the body exactly.
        let (head, body) = metrics.split_once("\r\n\r\n").unwrap();
        let len: usize =
            head.lines().find_map(|l| l.strip_prefix("Content-Length: ")).unwrap().parse().unwrap();
        assert_eq!(len, body.len());

        assert!(get(port, "/metrics?x=1").starts_with("HTTP/1.1 200 OK\r\n"));

        let landing = get(port, "/");
        assert!(landing.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(landing.contains("<a href=\"/metrics\">"));

        assert!(get(port, "/nope").starts_with("HTTP/1.1 404 "));
        assert!(request(port, "POST /metrics HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 405 "));
        assert!(request(port, "\r\n\r\n").starts_with("HTTP/1.1 400 "));

        let head = request(port, "HEAD /metrics HTTP/1.1\r\n\r\n");
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n") && head.ends_with("\r\n\r\n"));
    }

    #[test]
    fn dead_printer_is_still_http_200() {
        // Nothing answers SNMP on this port.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = start(silent.local_addr().unwrap().port());
        let resp = get(port, "/metrics");
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
        assert!(resp.contains("printer_up{target=\"test-printer\"} 0\n"));
        assert!(resp.contains("# scrape error: "));
        assert!(!resp.contains("printer_info"));
    }

    #[test]
    fn healthcheck_reflects_listener_state() {
        let port = start(1);
        assert!(healthcheck("127.0.0.1", port));
        // A port nothing listens on.
        let free = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        assert!(!healthcheck("127.0.0.1", free));
    }

    #[test]
    fn oversized_request_head_is_rejected() {
        let port = start(1);
        let resp =
            request(port, &format!("GET /{} HTTP/1.1\r\n", "a".repeat(2 * MAX_REQUEST_HEAD)));
        assert!(resp.starts_with("HTTP/1.1 408 "), "{resp}");
    }

    #[test]
    fn connection_limit_sheds_load_and_recovers() {
        let port = start(1);
        // Idle connections that never send a request occupy every slot...
        let idle: Vec<TcpStream> = (0..MAX_CONNECTIONS)
            .map(|_| TcpStream::connect(("127.0.0.1", port)).unwrap())
            .collect();
        thread::sleep(Duration::from_millis(200));
        assert!(get(port, "/").starts_with("HTTP/1.1 503 "));
        // ...and free them again once they go away.
        drop(idle);
        thread::sleep(Duration::from_millis(200));
        assert!(get(port, "/").starts_with("HTTP/1.1 200 OK\r\n"));
    }
}

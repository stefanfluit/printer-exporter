//! Minimal SNMP v2c client (GET + GETNEXT) over UDP with hand-rolled BER.
//!
//! Design choice: BER is hand-rolled rather than pulled in from a crate. The
//! subset an exporter needs (one varbind per request, a handful of value
//! types) is ~250 lines, has no transitive dependencies, and mirrors the
//! Python reference implementation one-to-one, which makes diffing behaviour
//! easy. The client is strictly read-only: it can only build `GetRequest` and
//! `GetNextRequest` PDUs.
//!
//! Wire format refresher (everything is a TLV: tag, length, value):
//!
//! ```text
//! SEQUENCE {                          0x30
//!   INTEGER version (1 = v2c)         0x02
//!   OCTET STRING community            0x04
//!   PDU {                             0xA0 Get / 0xA1 GetNext / 0xA2 Response
//!     INTEGER request-id
//!     INTEGER error-status
//!     INTEGER error-index
//!     SEQUENCE {                      varbind list
//!       SEQUENCE { OID name, <value> }
//!     }
//!   }
//! }
//! ```

use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

// ---- ASN.1 / SNMP tags ----------------------------------------------------

pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_NULL: u8 = 0x05;
pub const TAG_OID: u8 = 0x06;
pub const TAG_SEQUENCE: u8 = 0x30;
pub const TAG_IP_ADDRESS: u8 = 0x40;
pub const TAG_COUNTER32: u8 = 0x41;
pub const TAG_GAUGE32: u8 = 0x42;
pub const TAG_TIMETICKS: u8 = 0x43;
pub const TAG_COUNTER64: u8 = 0x46;
/// v2c per-varbind exceptions (context-specific, primitive, empty value).
pub const TAG_NO_SUCH_OBJECT: u8 = 0x80;
pub const TAG_NO_SUCH_INSTANCE: u8 = 0x81;
pub const TAG_END_OF_MIB_VIEW: u8 = 0x82;

pub const PDU_GET: u8 = 0xA0;
pub const PDU_GETNEXT: u8 = 0xA1;
pub const PDU_RESPONSE: u8 = 0xA2;

/// Safety cap on rows returned by a single walk.
const MAX_WALK_ROWS: usize = 10_000;
/// Largest UDP payload.
const MAX_DATAGRAM: usize = 65_535;

// ---- Errors ---------------------------------------------------------------

#[derive(Debug)]
pub enum SnmpError {
    Io(io::Error),
    Timeout,
    /// The target host name did not resolve to any address.
    Resolve(String),
    /// Malformed or unexpected BER in a response.
    Decode(&'static str),
    /// The agent answered with a non-zero error-status.
    ErrorStatus(i64),
    BadOid(String),
}

impl fmt::Display for SnmpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnmpError::Io(e) => write!(f, "I/O error: {e}"),
            SnmpError::Timeout => write!(f, "SNMP request timed out"),
            SnmpError::Resolve(h) => write!(f, "cannot resolve host {h:?}"),
            SnmpError::Decode(what) => write!(f, "malformed SNMP response: {what}"),
            SnmpError::ErrorStatus(s) => write!(f, "SNMP error-status {s}"),
            SnmpError::BadOid(s) => write!(f, "invalid OID {s:?}"),
        }
    }
}

impl From<io::Error> for SnmpError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            // Unix reports a receive timeout as WouldBlock, Windows as TimedOut.
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => SnmpError::Timeout,
            _ => SnmpError::Io(e),
        }
    }
}

// ---- OIDs -----------------------------------------------------------------

/// An OID as its numeric arcs. `Vec<u32>` ordering is exactly MIB ordering.
pub type Oid = Vec<u32>;

pub fn parse_oid(s: &str) -> Result<Oid, SnmpError> {
    let bad = || SnmpError::BadOid(s.to_string());
    let arcs = s
        .trim_matches('.')
        .split('.')
        .map(|p| p.parse::<u32>().map_err(|_| bad()))
        .collect::<Result<Oid, _>>()?;
    // The first two arcs share one sub-identifier (40*a + b), so both must
    // exist and be in range.
    if arcs.len() < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39) || arcs[1] > u32::MAX - 80 {
        return Err(bad());
    }
    Ok(arcs)
}

pub fn oid_to_string(oid: &[u32]) -> String {
    oid.iter().map(u32::to_string).collect::<Vec<_>>().join(".")
}

// ---- Decoded values -------------------------------------------------------

/// A decoded varbind value, collapsed to what an exporter cares about.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// INTEGER (signed).
    Int(i64),
    /// Counter32, Gauge32, `TimeTicks`, Counter64 (unsigned).
    Uint(u64),
    /// OCTET STRING (printable UTF-8, otherwise lowercase hex), `IpAddress`
    /// (dotted quad), OID (dotted), or an unknown type (hex).
    Str(String),
    Null,
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}

impl Value {
    /// Numeric view, like Python's `int(v)`: numbers directly, strings parsed.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Uint(u) => i64::try_from(*u).ok(),
            Value::Str(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    /// Unsigned view for counters (Counter64 may exceed i64).
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Int(i) => u64::try_from(*i).ok(),
            Value::Uint(u) => Some(*u),
            Value::Str(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    /// Text view for use as a label value; `None` for null/exception values.
    pub fn label(&self) -> Option<String> {
        match self {
            Value::Int(i) => Some(i.to_string()),
            Value::Uint(u) => Some(u.to_string()),
            Value::Str(s) => Some(s.clone()),
            _ => None,
        }
    }

    /// True for values that mean "nothing here".
    fn is_absent(&self) -> bool {
        matches!(
            self,
            Value::Null | Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView
        )
    }
}

// ---- BER encoding ---------------------------------------------------------

/// Definite length: short form below 128, else 0x80|n followed by n bytes.
fn encode_len(n: usize, out: &mut Vec<u8>) {
    let bytes = n.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    let significant = &bytes[skip..];
    if n < 0x80 {
        out.push(bytes[bytes.len() - 1]);
    } else {
        // At most size_of::<usize>() = 8 length bytes, so this fits 7 bits.
        out.push(0x80 | u8::try_from(significant.len()).expect("usize is at most 8 bytes"));
        out.extend_from_slice(significant);
    }
}

pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 4);
    out.push(tag);
    encode_len(value.len(), &mut out);
    out.extend_from_slice(value);
    out
}

/// Minimal-length two's-complement integer contents (no tag/length).
pub fn int_bytes(i: i64) -> Vec<u8> {
    let b = i.to_be_bytes();
    let mut start = 0;
    // Drop a leading byte while it is pure sign extension of the next one.
    while start < b.len() - 1
        && ((b[start] == 0x00 && b[start + 1] & 0x80 == 0)
            || (b[start] == 0xFF && b[start + 1] & 0x80 != 0))
    {
        start += 1;
    }
    b[start..].to_vec()
}

/// Base-128 sub-identifier, most significant group first, high bit set on
/// every byte except the last.
fn encode_subid(mut x: u32, out: &mut Vec<u8>) {
    let mut stack = [0u8; 5];
    let mut n = 0;
    loop {
        stack[n] = (x & 0x7F) as u8 | if n == 0 { 0 } else { 0x80 };
        n += 1;
        x >>= 7;
        if x == 0 {
            break;
        }
    }
    out.extend(stack[..n].iter().rev());
}

/// OID contents (no tag/length). `oid` must have at least two arcs, which
/// `parse_oid` guarantees.
pub fn oid_bytes(oid: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(oid.len() + 2);
    encode_subid(oid[0] * 40 + oid[1], &mut out);
    for &arc in &oid[2..] {
        encode_subid(arc, &mut out);
    }
    out
}

/// Build a complete v2c message. Each varbind is (name, value tag, raw value
/// contents); requests use `(oid, TAG_NULL, [])`.
pub fn encode_message(
    community: &[u8],
    pdu_type: u8,
    request_id: i32,
    varbinds: &[(Oid, u8, Vec<u8>)],
) -> Vec<u8> {
    let mut vbl = Vec::new();
    for (oid, tag, raw) in varbinds {
        let mut vb = tlv(TAG_OID, &oid_bytes(oid));
        vb.extend(tlv(*tag, raw));
        vbl.extend(tlv(TAG_SEQUENCE, &vb));
    }
    let mut pdu = tlv(TAG_INTEGER, &int_bytes(request_id.into()));
    pdu.extend(tlv(TAG_INTEGER, &[0])); // error-status
    pdu.extend(tlv(TAG_INTEGER, &[0])); // error-index
    pdu.extend(tlv(TAG_SEQUENCE, &vbl));

    let mut msg = tlv(TAG_INTEGER, &[1]); // version: 1 = SNMPv2c
    msg.extend(tlv(TAG_OCTET_STRING, community));
    msg.extend(tlv(pdu_type, &pdu));
    tlv(TAG_SEQUENCE, &msg)
}

// ---- BER decoding ---------------------------------------------------------

/// Cursor over a byte slice that hands out one TLV at a time. Every access is
/// bounds-checked: a truncated or hostile datagram yields `Decode`, never a
/// panic.
struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf }
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], SnmpError> {
        if n > self.buf.len() {
            return Err(SnmpError::Decode("truncated data"));
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Ok(head)
    }

    /// Read the next (tag, contents).
    fn tlv(&mut self) -> Result<(u8, &'a [u8]), SnmpError> {
        let tag = self.take(1)?[0];
        let first = self.take(1)?[0];
        let len = if first & 0x80 == 0 {
            first as usize
        } else {
            // Long form: low 7 bits give the number of length bytes.
            let n = (first & 0x7F) as usize;
            if n == 0 || n > 4 {
                return Err(SnmpError::Decode("unsupported length encoding"));
            }
            self.take(n)?.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize)
        };
        Ok((tag, self.take(len)?))
    }

    /// Read the next TLV and require a specific tag.
    fn expect(&mut self, tag: u8, what: &'static str) -> Result<&'a [u8], SnmpError> {
        let (t, v) = self.tlv()?;
        if t == tag {
            Ok(v)
        } else {
            Err(SnmpError::Decode(what))
        }
    }
}

/// Signed big-endian two's complement (INTEGER). Empty decodes as 0.
fn decode_int(raw: &[u8]) -> Result<i64, SnmpError> {
    if raw.len() > 8 {
        return Err(SnmpError::Decode("integer too large"));
    }
    let seed: i64 = if raw.first().is_some_and(|b| b & 0x80 != 0) { -1 } else { 0 };
    Ok(raw.iter().fold(seed, |acc, b| (acc << 8) | i64::from(*b)))
}

/// Unsigned big-endian (Counter32/64, Gauge32, `TimeTicks`). A Counter64 with
/// its top bit set arrives as 9 bytes with a leading 0x00, so strip zeros
/// before checking the width.
fn decode_uint(raw: &[u8]) -> Result<u64, SnmpError> {
    let skip = raw.iter().take_while(|b| **b == 0).count();
    let raw = &raw[skip..];
    if raw.len() > 8 {
        return Err(SnmpError::Decode("unsigned integer too large"));
    }
    Ok(raw.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
}

fn decode_oid(raw: &[u8]) -> Result<Oid, SnmpError> {
    let mut subids = Vec::with_capacity(raw.len() + 1);
    let mut x: u32 = 0;
    for (i, &c) in raw.iter().enumerate() {
        if x > (u32::MAX >> 7) {
            return Err(SnmpError::Decode("OID arc overflow"));
        }
        x = (x << 7) | u32::from(c & 0x7F);
        if c & 0x80 == 0 {
            subids.push(x);
            x = 0;
        } else if i == raw.len() - 1 {
            return Err(SnmpError::Decode("truncated OID"));
        }
    }
    let Some(&first) = subids.first() else {
        return Err(SnmpError::Decode("empty OID"));
    };
    // Undo the 40*a + b packing of the first two arcs (a is 0, 1 or 2).
    let a = (first / 40).min(2);
    let mut oid = vec![a, first - a * 40];
    oid.extend_from_slice(&subids[1..]);
    Ok(oid)
}

fn hex(raw: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(raw.len() * 2);
    for b in raw {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0F)]));
    }
    out
}

/// Approximation of Python's `str.isprintable()`, which the reference uses to
/// decide between text and hex: reject control characters and the non-ASCII
/// separators/format characters.
fn is_printable(c: char) -> bool {
    !(c.is_control()
        || (c.is_whitespace() && c != ' ')
        || matches!(c, '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{FEFF}'))
}

/// OCTET STRING to text: printable UTF-8 as-is, anything else (binary data
/// such as MAC addresses, or text with control characters) as lowercase hex.
fn decode_octets(raw: &[u8]) -> String {
    match std::str::from_utf8(raw) {
        Ok(s) if s.chars().all(is_printable) => s.to_string(),
        _ => hex(raw),
    }
}

pub fn decode_value(tag: u8, raw: &[u8]) -> Result<Value, SnmpError> {
    Ok(match tag {
        TAG_INTEGER => Value::Int(decode_int(raw)?),
        TAG_COUNTER32 | TAG_GAUGE32 | TAG_TIMETICKS | TAG_COUNTER64 => {
            Value::Uint(decode_uint(raw)?)
        }
        TAG_OCTET_STRING => Value::Str(decode_octets(raw)),
        TAG_OID => Value::Str(oid_to_string(&decode_oid(raw)?)),
        TAG_IP_ADDRESS => Value::Str(raw.iter().map(u8::to_string).collect::<Vec<_>>().join(".")),
        TAG_NULL => Value::Null,
        TAG_NO_SUCH_OBJECT => Value::NoSuchObject,
        TAG_NO_SUCH_INSTANCE => Value::NoSuchInstance,
        TAG_END_OF_MIB_VIEW => Value::EndOfMibView,
        _ => Value::Str(hex(raw)), // Opaque etc.: keep something inspectable
    })
}

/// The parts of a decoded message the client (and the test agent) need.
#[derive(Debug)]
pub struct Message {
    pub pdu_type: u8,
    pub request_id: i64,
    pub error_status: i64,
    pub varbinds: Vec<(Oid, Value)>,
}

pub fn decode_message(data: &[u8]) -> Result<Message, SnmpError> {
    let mut msg = Reader::new(Reader::new(data).expect(TAG_SEQUENCE, "message is not a SEQUENCE")?);
    msg.expect(TAG_INTEGER, "missing version")?;
    msg.expect(TAG_OCTET_STRING, "missing community")?;
    let (pdu_type, pdu) = msg.tlv()?;

    let mut pdu = Reader::new(pdu);
    let request_id = decode_int(pdu.expect(TAG_INTEGER, "missing request-id")?)?;
    let error_status = decode_int(pdu.expect(TAG_INTEGER, "missing error-status")?)?;
    pdu.expect(TAG_INTEGER, "missing error-index")?;

    let mut list = Reader::new(pdu.expect(TAG_SEQUENCE, "missing varbind list")?);
    let mut varbinds = Vec::new();
    while !list.is_empty() {
        let mut vb = Reader::new(list.expect(TAG_SEQUENCE, "varbind is not a SEQUENCE")?);
        let oid = decode_oid(vb.expect(TAG_OID, "varbind name is not an OID")?)?;
        let (tag, raw) = vb.tlv()?;
        varbinds.push((oid, decode_value(tag, raw)?));
    }
    Ok(Message { pdu_type, request_id, error_status, varbinds })
}

// ---- Client ---------------------------------------------------------------

/// Connection parameters. Cheap to share; each scrape opens its own
/// [`Session`] so concurrent scrapes never see each other's replies.
#[derive(Debug, Clone)]
pub struct Client {
    pub host: String,
    pub port: u16,
    pub community: String,
    /// How long to wait for the reply to one request.
    pub timeout: Duration,
    /// Upper bound on one whole scrape. Without it a slow, buggy or hostile
    /// agent could keep a walk (and the HTTP request behind it) busy for
    /// hours, one in-time reply after another.
    pub budget: Duration,
}

impl Client {
    /// Resolve the host and open a UDP socket for one scrape.
    pub fn connect(&self) -> Result<Session, SnmpError> {
        let addr = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|_| SnmpError::Resolve(self.host.clone()))?
            .next()
            .ok_or_else(|| SnmpError::Resolve(self.host.clone()))?;
        let socket = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })?;
        // connect() makes the kernel drop datagrams from any other peer.
        socket.connect(addr)?;
        // Start request-ids at an unpredictable value so an off-path host
        // cannot easily forge a reply. std has no RNG API, but every
        // `RandomState` is keyed from OS randomness.
        let seed = RandomState::new().build_hasher().finish();
        Ok(Session {
            socket,
            community: self.community.clone().into_bytes(),
            timeout: self.timeout,
            deadline: Instant::now() + self.budget,
            request_id: i32::try_from(seed & 0x7FFF_FFFF).unwrap_or(0),
            buf: vec![0; MAX_DATAGRAM],
        })
    }
}

pub struct Session {
    socket: UdpSocket,
    community: Vec<u8>,
    timeout: Duration,
    /// End of the scrape budget; requests after this fail immediately.
    deadline: Instant,
    request_id: i32,
    /// Receive buffer, sized for the largest possible UDP datagram.
    buf: Vec<u8>,
}

impl Session {
    /// Send one single-varbind request and return the first response varbind.
    fn request(&mut self, pdu_type: u8, oid: &[u32]) -> Result<(Oid, Value), SnmpError> {
        self.request_id = (self.request_id.wrapping_add(1)) & 0x7FFF_FFFF;
        let msg = encode_message(
            &self.community,
            pdu_type,
            self.request_id,
            &[(oid.to_vec(), TAG_NULL, Vec::new())],
        );
        self.socket.send(&msg)?;

        // Whichever comes first: this request's timeout or the scrape budget.
        let deadline = (Instant::now() + self.timeout).min(self.deadline);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SnmpError::Timeout);
            }
            self.socket.set_read_timeout(Some(remaining))?;
            let n = self.socket.recv(&mut self.buf)?;
            let resp = decode_message(&self.buf[..n])?;
            // A late reply to an earlier, timed-out request: keep waiting.
            if resp.request_id != i64::from(self.request_id) {
                continue;
            }
            if resp.pdu_type != PDU_RESPONSE {
                return Err(SnmpError::Decode("unexpected PDU type"));
            }
            if resp.error_status != 0 {
                return Err(SnmpError::ErrorStatus(resp.error_status));
            }
            return resp.varbinds.into_iter().next().ok_or(SnmpError::Decode("empty varbind list"));
        }
    }

    /// Value of exactly `oid`, or `None` if the agent does not have it.
    pub fn get(&mut self, oid: &[u32]) -> Result<Option<Value>, SnmpError> {
        let (ret_oid, value) = self.request(PDU_GET, oid)?;
        if ret_oid != oid || value.is_absent() {
            return Ok(None);
        }
        Ok(Some(value))
    }

    /// Every (oid, value) leaf under `root`, via repeated GETNEXT.
    pub fn walk(&mut self, root: &[u32]) -> Result<Vec<(Oid, Value)>, SnmpError> {
        let mut rows = Vec::new();
        let mut cursor = root.to_vec();
        while rows.len() < MAX_WALK_ROWS {
            let (ret_oid, value) = self.request(PDU_GETNEXT, &cursor)?;
            if value == Value::EndOfMibView
                || !ret_oid.starts_with(root) // left the subtree: walk complete
                || ret_oid <= cursor
            // not advancing: a buggy agent would loop forever
            {
                break;
            }
            cursor.clone_from(&ret_oid);
            rows.push((ret_oid, value));
        }
        Ok(rows)
    }
}

// ---- Tests ----------------------------------------------------------------

#[cfg(test)]
pub mod testutil {
    //! A tiny in-process SNMP agent so the whole client/collector stack can be
    //! exercised over real UDP without a printer.

    use super::*;
    use std::collections::BTreeMap;
    use std::ops::Bound;

    pub type Mib = BTreeMap<Oid, (u8, Vec<u8>)>;

    pub fn int(i: i64) -> (u8, Vec<u8>) {
        (TAG_INTEGER, int_bytes(i))
    }

    pub fn uint(tag: u8, u: u64) -> (u8, Vec<u8>) {
        // Unsigned types are encoded like non-negative INTEGERs.
        let mut b = u.to_be_bytes().to_vec();
        while b.len() > 1 && b[0] == 0 && b[1] & 0x80 == 0 {
            b.remove(0);
        }
        if b[0] & 0x80 != 0 {
            b.insert(0, 0);
        }
        (tag, b)
    }

    pub fn text(s: &str) -> (u8, Vec<u8>) {
        (TAG_OCTET_STRING, s.as_bytes().to_vec())
    }

    /// Serve `mib` on an ephemeral localhost UDP port; returns the port. The
    /// agent thread lives until the test process exits.
    pub fn spawn_agent(mib: Mib) -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                let Ok((n, peer)) = socket.recv_from(&mut buf) else { return };
                let Ok(req) = decode_message(&buf[..n]) else { continue };
                let Some((oid, _)) = req.varbinds.into_iter().next() else { continue };
                let varbind = match req.pdu_type {
                    PDU_GET => match mib.get(&oid) {
                        Some((tag, raw)) => (oid, *tag, raw.clone()),
                        None => (oid, TAG_NO_SUCH_INSTANCE, Vec::new()),
                    },
                    PDU_GETNEXT => {
                        match mib.range((Bound::Excluded(oid.clone()), Bound::Unbounded)).next() {
                            Some((next, (tag, raw))) => (next.clone(), *tag, raw.clone()),
                            None => (oid, TAG_END_OF_MIB_VIEW, Vec::new()),
                        }
                    }
                    _ => continue, // read-only agent, like the exporter
                };
                let resp = encode_message(
                    b"public",
                    PDU_RESPONSE,
                    i32::try_from(req.request_id).unwrap(),
                    &[varbind],
                );
                let _ = socket.send_to(&resp, peer);
            }
        });
        port
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    fn oid(s: &str) -> Oid {
        parse_oid(s).unwrap()
    }

    #[test]
    fn oid_roundtrip_including_multibyte_arcs() {
        for s in [
            "1.3.6.1.2.1.1.3.0",
            "1.3.6.1.4.1.641.2.1.2.1.6.1",
            "2.999.4294967295",
            "2.4294967215",
            "0.0",
        ] {
            let o = oid(s);
            assert_eq!(decode_oid(&oid_bytes(&o)).unwrap(), o, "{s}");
            assert_eq!(oid_to_string(&o), s);
        }
        // 641 = 5*128 + 1 -> 0x85 0x01 in base-128
        assert_eq!(oid_bytes(&oid("1.3.6.1.4.1.641")), [0x2b, 6, 1, 4, 1, 0x85, 0x01]);
        assert_eq!(oid(".1.3.6."), vec![1, 3, 6]);
    }

    #[test]
    fn rejects_bad_oids() {
        for s in ["", "1", "1.x.3", "3.1", "1.40", "1.3.-1", "2.4294967216"] {
            assert!(parse_oid(s).is_err(), "{s:?}");
        }
    }

    #[test]
    fn integer_encoding_is_minimal_twos_complement() {
        assert_eq!(int_bytes(0), [0]);
        assert_eq!(int_bytes(127), [0x7F]);
        assert_eq!(int_bytes(128), [0x00, 0x80]);
        assert_eq!(int_bytes(-1), [0xFF]);
        assert_eq!(int_bytes(-129), [0xFF, 0x7F]);
        for i in [0, 1, -1, 127, 128, -128, -129, 65535, i64::MAX, i64::MIN] {
            assert_eq!(decode_int(&int_bytes(i)).unwrap(), i);
        }
    }

    #[test]
    fn decodes_every_required_value_type() {
        let v = |tag, raw: &[u8]| decode_value(tag, raw).unwrap();
        assert_eq!(v(TAG_INTEGER, &[0xFE]), Value::Int(-2)); // "unknown" sentinel
        assert_eq!(v(TAG_INTEGER, &[0xFD]), Value::Int(-3)); // "some remaining"
        assert_eq!(v(TAG_OCTET_STRING, b"Ready"), Value::Str("Ready".into()));
        assert_eq!(v(TAG_OCTET_STRING, b""), Value::Str(String::new()));
        // Binary (a MAC address) and control characters fall back to hex.
        assert_eq!(v(TAG_OCTET_STRING, &[0x00, 0x1b, 0xff]), Value::Str("001bff".into()));
        assert_eq!(v(TAG_OCTET_STRING, b"a\nb"), Value::Str("610a62".into()));
        assert_eq!(
            v(TAG_OID, &[0x2b, 6, 1, 4, 1, 0x85, 0x01]),
            Value::Str("1.3.6.1.4.1.641".into())
        );
        assert_eq!(v(TAG_COUNTER32, &[0x01, 0xD9, 0x2E, 0xA2]), Value::Uint(31_010_466));
        assert_eq!(
            v(TAG_GAUGE32, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF]),
            Value::Uint(u64::from(u32::MAX))
        );
        assert_eq!(v(TAG_TIMETICKS, &[0x12, 0x5D, 0x8B, 0x01]), Value::Uint(308_120_321));
        assert_eq!(
            v(TAG_COUNTER64, &[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            Value::Uint(u64::MAX)
        );
        assert_eq!(v(TAG_IP_ADDRESS, &[172, 16, 10, 29]), Value::Str("172.16.10.29".into()));
        assert_eq!(v(TAG_NULL, &[]), Value::Null);
        assert_eq!(v(TAG_NO_SUCH_OBJECT, &[]), Value::NoSuchObject);
        assert_eq!(v(TAG_NO_SUCH_INSTANCE, &[]), Value::NoSuchInstance);
        assert_eq!(v(TAG_END_OF_MIB_VIEW, &[]), Value::EndOfMibView);
    }

    /// A `GetResponse` for sysUpTime.0 written out byte by byte, as an agent
    /// puts it on the wire.
    #[test]
    fn decodes_wire_format_response() {
        #[rustfmt::skip]
        let wire: &[u8] = &[
            0x30, 0x2b,                                     // SEQUENCE, 43 bytes
              0x02, 0x01, 0x01,                             // version = 1 (v2c)
              0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c',
              0xa2, 0x1e,                                   // GetResponse, 30 bytes
                0x02, 0x04, 0x12, 0x34, 0x56, 0x78,         // request-id
                0x02, 0x01, 0x00,                           // error-status
                0x02, 0x01, 0x00,                           // error-index
                0x30, 0x10,                                 // varbind list
                  0x30, 0x0e,                               // varbind
                    0x06, 0x08, 0x2b, 6, 1, 2, 1, 1, 3, 0,  // 1.3.6.1.2.1.1.3.0
                    0x43, 0x02, 0x30, 0x39,                 // TimeTicks 12345
        ];
        let msg = decode_message(wire).unwrap();
        assert_eq!(msg.pdu_type, PDU_RESPONSE);
        assert_eq!(msg.request_id, 0x1234_5678);
        assert_eq!(msg.error_status, 0);
        assert_eq!(msg.varbinds, vec![(oid("1.3.6.1.2.1.1.3.0"), Value::Uint(12345))]);
    }

    #[test]
    fn request_encoding_matches_reference_bytes() {
        // Same bytes the Python reference emits for GET sysUpTime.0, rid 1.
        let msg =
            encode_message(b"public", PDU_GET, 1, &[(oid("1.3.6.1.2.1.1.3.0"), TAG_NULL, vec![])]);
        #[rustfmt::skip]
        assert_eq!(msg, [
            0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c',
            0xa0, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
            0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 6, 1, 2, 1, 1, 3, 0, 0x05, 0x00,
        ]);
    }

    #[test]
    fn long_form_lengths_roundtrip() {
        let long = "x".repeat(300);
        let msg = encode_message(
            b"public",
            PDU_RESPONSE,
            7,
            &[(oid("1.3.6.1"), TAG_OCTET_STRING, long.clone().into_bytes())],
        );
        let decoded = decode_message(&msg).unwrap();
        assert_eq!(decoded.varbinds[0].1, Value::Str(long));
    }

    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        let good = encode_message(
            b"public",
            PDU_RESPONSE,
            7,
            &[(oid("1.3.6.1.2.1.1.3.0"), TAG_TIMETICKS, vec![1, 2])],
        );
        // Every truncation of a valid message must fail cleanly.
        for n in 0..good.len() {
            assert!(decode_message(&good[..n]).is_err(), "prefix of {n} bytes");
        }
        assert!(decode_message(&[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]).is_err());
        assert!(decode_message(&[0x30, 0x80]).is_err());
        assert!(decode_message(&[0xFF; 64]).is_err());
    }

    #[test]
    fn get_and_walk_against_agent() {
        let mut mib = Mib::new();
        mib.insert(oid("1.3.6.1.2.1.1.3.0"), uint(TAG_TIMETICKS, 4200));
        mib.insert(oid("1.3.6.1.2.1.43.11.1.1.9.1.1"), int(1044));
        mib.insert(oid("1.3.6.1.2.1.43.11.1.1.9.1.2"), int(-3));
        mib.insert(oid("1.3.6.1.2.1.43.12.1"), text("next table"));
        let client = Client {
            host: "127.0.0.1".into(),
            port: spawn_agent(mib),
            community: "public".into(),
            timeout: Duration::from_secs(2),
            budget: Duration::from_secs(30),
        };
        let mut s = client.connect().unwrap();

        assert_eq!(s.get(&oid("1.3.6.1.2.1.1.3.0")).unwrap(), Some(Value::Uint(4200)));
        assert_eq!(s.get(&oid("1.3.6.1.2.1.1.9.0")).unwrap(), None); // noSuchInstance

        // Stops at the subtree boundary rather than running into 43.12.
        let rows = s.walk(&oid("1.3.6.1.2.1.43.11.1.1.9")).unwrap();
        assert_eq!(
            rows,
            vec![
                (oid("1.3.6.1.2.1.43.11.1.1.9.1.1"), Value::Int(1044)),
                (oid("1.3.6.1.2.1.43.11.1.1.9.1.2"), Value::Int(-3)),
            ]
        );
        // Walk that runs off the end of the MIB (endOfMibView) and an empty one.
        assert_eq!(s.walk(&oid("1.3.6.1.2.1.43.12")).unwrap().len(), 1);
        assert!(s.walk(&oid("1.3.6.1.4.1.253")).unwrap().is_empty());
    }

    #[test]
    fn silent_target_times_out() {
        // Bound but never answered: the request must give up after `timeout`.
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = Client {
            host: "127.0.0.1".into(),
            port: silent.local_addr().unwrap().port(),
            community: "public".into(),
            timeout: Duration::from_millis(150),
            budget: Duration::from_secs(30),
        };
        let started = Instant::now();
        let err = client.connect().unwrap().get(&oid("1.3.6.1.2.1.1.3.0")).unwrap_err();
        assert!(matches!(err, SnmpError::Timeout), "{err}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// An agent whose table never ends: GETNEXT always returns the next row.
    fn spawn_endless_agent() -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            loop {
                let Ok((n, peer)) = socket.recv_from(&mut buf) else { return };
                let Ok(req) = decode_message(&buf[..n]) else { continue };
                let Some((mut next, _)) = req.varbinds.into_iter().next() else { continue };
                // Stay inside the walked column (11 arcs): descend once,
                // then count up forever.
                let in_table = next.len() > 11;
                match next.last_mut() {
                    Some(last) if in_table => *last += 1,
                    _ => next.push(1),
                }
                std::thread::sleep(Duration::from_millis(2));
                let id = i32::try_from(req.request_id).unwrap();
                let resp =
                    encode_message(b"public", PDU_RESPONSE, id, &[(next, TAG_INTEGER, vec![1])]);
                let _ = socket.send_to(&resp, peer);
            }
        });
        port
    }

    #[test]
    fn scrape_budget_stops_an_endless_walk() {
        let client = Client {
            host: "127.0.0.1".into(),
            port: spawn_endless_agent(),
            community: "public".into(),
            timeout: Duration::from_secs(2),
            budget: Duration::from_millis(200),
        };
        let started = Instant::now();
        let mut s = client.connect().unwrap();
        let err = s.walk(&oid("1.3.6.1.2.1.43.11.1.1.9")).unwrap_err();
        assert!(matches!(err, SnmpError::Timeout), "{err}");
        // Once the budget is spent, further requests fail without waiting.
        assert!(matches!(s.get(&oid("1.3.6.1.2.1.1.3.0")), Err(SnmpError::Timeout)));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// Feed the decoder a few hundred thousand corrupted messages. Whatever
    /// a device (or someone spoofing it) sends must produce `Ok` or `Err`,
    /// never a panic, hang or out-of-bounds read.
    #[test]
    fn decoder_survives_corrupted_messages() {
        let seeds = [
            encode_message(
                b"public",
                PDU_RESPONSE,
                7,
                &[(oid("1.3.6.1.2.1.1.3.0"), TAG_TIMETICKS, vec![1, 2])],
            ),
            encode_message(
                b"public",
                PDU_RESPONSE,
                -1,
                &[(oid("1.3.6.1.4.1.641.2.1"), TAG_OCTET_STRING, b"Ready".to_vec())],
            ),
            encode_message(
                b"p",
                PDU_RESPONSE,
                i32::MAX,
                &[(oid("2.999.1"), TAG_COUNTER64, vec![0xFF; 9])],
            ),
        ];
        // xorshift64: deterministic, so a failure is reproducible.
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..300_000 {
            let mut data = seeds[round % seeds.len()].clone();
            for _ in 0..=(next() % 4) {
                let r = next();
                let pos = usize::try_from(r >> 16).unwrap() % data.len();
                match r % 3 {
                    0 => data[pos] = r.to_le_bytes()[1],
                    1 => data.truncate(pos),
                    _ => data.insert(pos, r.to_le_bytes()[1]),
                }
                if data.is_empty() {
                    break;
                }
            }
            let _ = decode_message(&data);
        }
    }
}

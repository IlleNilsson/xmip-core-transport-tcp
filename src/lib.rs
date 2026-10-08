#![forbid(unsafe_code)]

//! Streams that arrive over a TCP connection. One connection is one Stream.
//!
//! The pushed case: a caller connects, so a transport-level identity exists —
//! at minimum the peer address, which ADR-0019 clause 8 calls an *inferred*
//! identity rather than an absent one.
//!
//! **Acceptance is at-most-once here.** Raw TCP frames a Stream by the
//! connection itself, closed to end it, and has no application-level reply:
//! the sender's write completed when its kernel took the bytes, so there is
//! nobody left to tell the verdict. The body is the connection, read to its
//! end as the runtime asks.

use std::io::Write;
use std::net::TcpListener;
use std::time::Duration;

use transport::Acknowledgement;
use transport::ArrivalIdentity;
use transport::Arrived;
use transport::Configured;
use transport::Directions;
use transport::Transport;
use transport::error::{Result, classify};
use transport::kept::Kept;
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::taken::Taken;
use xcore::settings::{Applies, Kind, Presence, Setting, Settings};

/// Why a TCP arrival cannot be acknowledged after the receive cycle.
pub const AT_MOST_ONCE: &str = "raw TCP has no reply: the sender's write completed when its \
                                kernel took the bytes, and closing the connection ends the Stream";

#[derive(Clone)]
pub struct TcpTransport {
    bind: String,
    accept_timeout: Option<Duration>,
    /// The listener the first receive binds, and every receive takes from.
    receiving: Kept<TcpListener>,
}

impl TcpTransport {
    #[must_use]
    pub fn new(bind: impl Into<String>) -> Self {
        Self {
            bind: bind.into(),
            accept_timeout: None,
            receiving: Kept::new(),
        }
    }

    /// Give up on a connection that stops sending.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.accept_timeout = Some(timeout);
        self
    }

    /// Bind and report the address actually assigned.
    ///
    /// Binding to port 0 lets the operating system choose, which is what a test
    /// wants and what an operator never does.
    ///
    /// # Errors
    ///
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&self.bind)
    }

    /// Take one connection from an already-bound listener. Its body is the
    /// connection itself, read to its end as the runtime asks, never whole in
    /// memory; acceptance is at-most-once ([`AT_MOST_ONCE`]).
    ///
    /// # Errors
    ///
    /// Where the connection could not be accepted.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Arrived> {
        // Through the capability's helper, so the wait for the connection is
        // bounded as well as the reads. This did its own `accept` until
        // 2026-09-20 and blocked in it for good when nothing connected.
        let (stream, peer) = socket::accept_tcp(listener, self.accept_timeout)?;
        Ok(Arrived::new(
            format!("tcp://{peer}"),
            stream,
            Acknowledgement::at_most_once(AT_MOST_ONCE),
        )
        .from_peer(peer))
    }
}

impl Transport for TcpTransport {
    fn name(&self) -> &'static str {
        "tcp"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Unordered("each connection is a Stream of its own")
    }

    /// One connection, from the listener the first receive bound and kept,
    /// read to its end by the runtime. Acceptance is at-most-once here: raw
    /// TCP has no reply to defer ([`AT_MOST_ONCE`]).
    fn receive(&self) -> Result<Vec<Arrived>> {
        let listener = self.receiving.bound(|| self.bind())?;
        Ok(vec![self.accept_one(listener)?])
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        // Through the capability's helper, so the connect is bounded like the
        // accept. This used `TcpStream::connect` bare until 2026-09-20 and
        // waited on the operating system's schedule, which is not a timeout.
        let mut stream = socket::connect_tcp(target, self.accept_timeout)?;

        stream
            .write_all(bytes)
            .map_err(|e| classify("writing to the peer", &e))?;

        stream
            .flush()
            .map_err(|e| classify("flushing to the peer", &e))
    }
}

impl Configured for TcpTransport {
    /// The address is where a Receive Location listens and where a Send
    /// Location connects; the one setting bounds the wait for either.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[Setting {
            name: "timeout",
            kind: Kind::Duration,
            presence: Presence::Optional,
            meaning: "How long a connection is waited for, accepted or opened, and how long \
                      one that stops sending is waited on; unbounded when left out.",
            applies: Applies::Both,
        }],
    };

    fn configured(address: &str, settings: &xcore::settings::Read) -> Result<Self> {
        let transport = Self::new(address);
        Ok(match settings.optional_duration("timeout") {
            Some(timeout) => transport.timing_out_after(timeout),
            None => transport,
        })
    }
}

impl TcpTransport {
    /// Both ends on this machine: an ephemeral local port, the loopback
    /// timeout on the accept.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0").timing_out_after(LOOPBACK_TIMEOUT)
    }
}

impl Accepting for TcpTransport {
    fn take_one(self, listener: &TcpListener) -> Result<Taken> {
        self.accept_one(listener)?.taken()
    }
}

impl Loopback for TcpTransport {
    fn arrival_identity(&self) -> ArrivalIdentity {
        ArrivalIdentity::PEER
    }

    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        Ok(Box::new(Listening::new(self.clone(), self.bind()?)))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        Self::new("127.0.0.1:0").send(address, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xcore::settings::Given;

    #[test]
    fn tcp_declares_its_settings_and_reads_through_them() {
        assert_eq!(TcpTransport::SETTINGS.problems(), Vec::<String>::new());
        let given = [("timeout".to_string(), Given::Text("250ms".to_string()))];
        let transport =
            TcpTransport::open("127.0.0.1:0", Applies::Receive, &given).expect("configured");
        assert_eq!(transport.accept_timeout, Some(Duration::from_millis(250)));
        assert!(TcpTransport::open("127.0.0.1:0", Applies::Send, &[]).is_ok());
    }

    #[test]
    fn tcp_round_trip_carries_bytes_and_peer() {
        let receiver = TcpTransport::new("127.0.0.1:0");
        let (listener, address) = receiver.bind().expect("binding");

        let sender = std::thread::spawn(move || {
            TcpTransport::new("127.0.0.1:0")
                .send(&address, b"hello over tcp")
                .expect("sending");
        });

        let arrived = receiver.accept_one(&listener).expect("accepting");
        assert!(!arrived.defers(), "raw TCP is at-most-once");
        let arrived = arrived.taken().expect("read to its end");
        sender.join().expect("the sending thread panicked");

        assert_eq!(arrived.bytes, b"hello over tcp");
        assert!(arrived.origin_uri.starts_with("tcp://127.0.0.1:"));
        ArrivalIdentity::PEER
            .check(&arrived)
            .expect("the peer, as the gates read it");
        let (_, peer) = arrived.observed.first().expect("observed");
        assert_eq!(format!("tcp://{peer}"), arrived.origin_uri);
    }

    #[test]
    fn every_receive_takes_from_the_listener_the_first_bound() {
        // Every send lands before any receive: queued on the kept listener,
        // not refused, and taken in order by receives that bind nothing.
        let receiver = TcpTransport::loopback();
        receiver.receiving.bound(|| receiver.bind()).expect("bound");
        let address = receiver.receiving.address().expect("address");
        for round in 0..5u8 {
            TcpTransport::loopback()
                .send(address, &[round])
                .expect("sent");
        }
        for round in 0..5u8 {
            let mut arrived = receiver.receive().expect("received");
            let taken = arrived.remove(0).taken().expect("taken");
            assert_eq!(taken.bytes, [round]);
        }
    }

    #[test]
    fn a_listening_socket_has_no_artefact_to_claim() {
        // ADR-0024. `None` rather than NoNativeClaim: the two are different
        // answers — no artefact at all, versus an artefact the protocol cannot
        // lock.
        assert!(TcpTransport::new("127.0.0.1:0").claims().is_none());
    }

    #[test]
    fn a_round_hands_the_arrival_who_sent_it() {
        // `Loopback::round` holds the far end's arrival to what
        // `arrival_identity` says it carries.
        let taken = TcpTransport::loopback()
            .round(b"who sent this")
            .expect("a round");
        assert_eq!(taken.bytes, b"who sent this");
        assert!(!taken.observed.is_empty(), "{taken:?}");
    }
}

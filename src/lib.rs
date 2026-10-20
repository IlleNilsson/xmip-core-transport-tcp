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
//!
//! **TLS, where the Location says so.** A Receive Location whose `tls`
//! setting is `true` terminates TLS on every connection with the guard the
//! node hands it (`transport::Guard`): the node's `receive` certificate,
//! and the client's verified against the anchors the node was given. The
//! handshake finishes before a byte of content is read, and what it proved
//! of the client — its certificate's subject, issuer and fingerprint, and
//! that it verified them — is written on the arrival for the identity gates
//! (ADR-0033, amendment 2026-10-19). A client the handshake refuses is
//! refused there, and the Location takes the next.

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
use xcore::settings::{Applies, Fixed, Kind, Presence, Setting, Settings};

/// Why a TCP arrival cannot be acknowledged after the receive cycle.
pub const AT_MOST_ONCE: &str = "raw TCP has no reply: the sender's write completed when its \
                                kernel took the bytes, and closing the connection ends the Stream";

/// Why a Location asking for TLS is refused where the node presents no
/// certificate on receive.
pub const NO_RECEIVE_CERTIFICATE: &str = "the Location terminates TLS (tls = true) and the node \
     has no receive certificate to present: give it [provision.receive]";

#[derive(Clone)]
pub struct TcpTransport {
    bind: String,
    accept_timeout: Option<Duration>,
    /// Whether a receive terminates TLS: the Location's `tls` setting.
    tls: bool,
    /// What it terminates TLS with, as the node handed it.
    #[cfg(feature = "tls")]
    guard: Option<transport::Guard>,
    /// The listener the first receive binds, and every receive takes from.
    receiving: Kept<TcpListener>,
}

impl TcpTransport {
    #[must_use]
    pub fn new(bind: impl Into<String>) -> Self {
        Self {
            bind: bind.into(),
            accept_timeout: None,
            tls: false,
            #[cfg(feature = "tls")]
            guard: None,
            receiving: Kept::new(),
        }
    }

    /// Terminate TLS on every connection received, with `guard`.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn guarding(mut self, guard: transport::Guard) -> Self {
        self.tls = true;
        self.guard = Some(guard);
        self
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
        let origin = format!("tcp://{peer}");
        let acknowledgement = Acknowledgement::at_most_once(AT_MOST_ONCE);
        // A build without TLS never holds `tls = true`: `configured`
        // refuses it.
        #[cfg(feature = "tls")]
        if self.tls {
            return self.guarded(stream).map(|(guarded, observed)| {
                Arrived::new(origin, guarded, acknowledgement)
                    .from_peer(peer)
                    .observing_all(observed)
            });
        }
        Ok(Arrived::new(origin, stream, acknowledgement).from_peer(peer))
    }

    /// `stream` answered in TLS by the guard the node handed it: the
    /// guarded connection and what its handshake proved of the client.
    #[cfg(feature = "tls")]
    fn guarded(
        &self,
        stream: std::net::TcpStream,
    ) -> Result<(tls::GuardedServer, Vec<(String, String)>)> {
        let guard = self
            .guard
            .as_ref()
            .ok_or_else(|| transport::TransportError::permanent(NO_RECEIVE_CERTIFICATE))?;
        guard.answer(stream)
    }
}

/// Why `tls = true` is refused by a build without TLS.
#[cfg(not(feature = "tls"))]
const NO_TLS: &str = "the Location terminates TLS (tls = true) and this build has no tls \
                      feature compiled in";

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

    fn waiting(&self) -> transport::Waiting {
        transport::Waiting::Waits("the accept waits for a connection")
    }

    /// One connection, from the listener the first receive bound and kept,
    /// read to its end by the runtime. Acceptance is at-most-once here: raw
    /// TCP has no reply to defer ([`AT_MOST_ONCE`]).
    fn receive_up_to(&self, _most: usize) -> Result<Vec<Arrived>> {
        let listener = self.receiving.bound(|| self.bind())?;
        Ok(vec![self.accept_one(listener)?])
    }

    fn sending(&self) -> transport::Sending {
        transport::Sending::Streamed("the connection carries the body as it is read")
    }

    fn send_from(&self, target: &str, outgoing: transport::Outgoing<'_>) -> Result<()> {
        // Through the capability's helper, so the connect is bounded like the
        // accept. This used `TcpStream::connect` bare until 2026-09-20 and
        // waited on the operating system's schedule, which is not a timeout.
        let mut stream = socket::connect_tcp(target, self.accept_timeout)?;

        // Written as it is read from the Ledger, never whole here.
        outgoing.write_to(&mut stream)?;

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
        settings: &[
            Setting {
                name: "timeout",
                kind: Kind::Duration,
                presence: Presence::Optional,
                meaning: "How long a connection is waited for, accepted or opened, and how \
                          long one that stops sending is waited on; unbounded when left out.",
                applies: Applies::Both,
            },
            Setting {
                name: "tls",
                kind: Kind::Boolean,
                presence: Presence::Default(Fixed::Boolean(false)),
                meaning: "Terminate TLS on every connection: present the node's receive \
                          certificate, [provision.receive], and verify the client's against \
                          the anchors given there.",
                applies: Applies::Receive,
            },
        ],
    };

    fn configured(address: &str, settings: &xcore::settings::Read) -> Result<Self> {
        let mut transport = Self::new(address);
        if let Some(timeout) = settings.optional_duration("timeout") {
            transport = transport.timing_out_after(timeout);
        }
        transport.tls = settings.optional_boolean("tls").unwrap_or(false);
        #[cfg(not(feature = "tls"))]
        if transport.tls {
            return Err(transport::TransportError::permanent(NO_TLS));
        }
        Ok(transport)
    }

    /// Kept where the Location terminates TLS, and refused there without
    /// one; a Location in the clear keeps nothing.
    #[cfg(feature = "tls")]
    fn guarded_by(mut self, guard: Option<&transport::Guard>) -> Result<Self> {
        if self.tls {
            let guard = guard
                .ok_or_else(|| transport::TransportError::permanent(NO_RECEIVE_CERTIFICATE))?;
            self.guard = Some(guard.clone());
        }
        Ok(self)
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
    fn a_listening_socket_has_no_artifact_to_claim() {
        // ADR-0024. `None` rather than NoNativeClaim: the two are different
        // answers — no artifact at all, versus an artifact the protocol cannot
        // lock.
        assert!(TcpTransport::new("127.0.0.1:0").claims().is_none());
    }

    #[test]
    fn tls_is_a_receive_setting_off_unless_said() {
        let given = [("tls".to_string(), Given::Boolean(true))];
        let refused = TcpTransport::open("127.0.0.1:0", Applies::Send, &given);
        assert!(refused.is_err(), "a Send Location takes no tls");
        let plain = TcpTransport::open("127.0.0.1:0", Applies::Receive, &[]).expect("plain");
        assert!(!plain.tls);
        let asked = TcpTransport::open("127.0.0.1:0", Applies::Receive, &given);
        #[cfg(feature = "tls")]
        {
            let asked = asked.expect("read");
            assert!(asked.tls);
            let failure = asked.guarded_by(None).err().expect("no certificate");
            assert_eq!(failure.message, NO_RECEIVE_CERTIFICATE);
        }
        #[cfg(not(feature = "tls"))]
        assert_eq!(asked.err().expect("no tls").message, NO_TLS);
    }

    /// A test authority's PEM and signing half, and an identity
    /// `CN=<name>` it issued, trusting it.
    #[cfg(feature = "tls")]
    mod issued {
        pub(super) struct Authority(rcgen::Certificate, rcgen::KeyPair);

        impl Authority {
            pub(super) fn new() -> Self {
                let mut params =
                    rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
                params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                let key = rcgen::KeyPair::generate().expect("a key");
                Self(params.self_signed(&key).expect("signed"), key)
            }

            pub(super) fn identity(&self, name: &str) -> tls::Identity {
                let key = rcgen::KeyPair::generate().expect("a key");
                let mut params =
                    rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
                params.distinguished_name = rcgen::DistinguishedName::new();
                params
                    .distinguished_name
                    .push(rcgen::DnType::CommonName, name);
                let leaf = params.signed_by(&key, &self.0, &self.1).expect("issued");
                tls::Identity::from_pem(
                    leaf.pem().as_bytes(),
                    key.serialize_pem().as_bytes(),
                    self.0.pem().as_bytes(),
                )
                .expect("an identity")
            }
        }
    }

    /// `client` sends `payload` to `address` in TLS, ends it as TLS ends a
    /// Stream, and reads to the server's close.
    #[cfg(feature = "tls")]
    fn send_guarded(address: &str, client: tls::ClientConfig, payload: &'static [u8]) {
        use std::io::Read;
        let tcp = std::net::TcpStream::connect(address).expect("connect");
        let Ok(mut stream) = tls::client_with("localhost", tcp, std::sync::Arc::new(client)) else {
            return;
        };
        let _ = stream.write_all(payload);
        stream.conn.send_close_notify();
        let _ = stream.flush();
        let _ = stream.read_to_end(&mut Vec::new());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn a_guarded_receive_names_the_verified_client_and_refuses_a_stranger() {
        use context::property::{TLS_HANDSHAKE_VERIFIED, TLS_PEER_SUBJECT, TLS_PEER_VERIFIED};
        use std::sync::Arc;

        let ours = issued::Authority::new();
        let server = ours.identity("localhost").server().expect("a server");
        let receiver = TcpTransport::new("127.0.0.1:0")
            .timing_out_after(LOOPBACK_TIMEOUT)
            .guarding(transport::Guard::new(Arc::new(server)));
        let (listener, address) = receiver.bind().expect("binding");

        let to = address.clone();
        let client = ours.identity("party-x.example").client().expect("a client");
        let sender = std::thread::spawn(move || send_guarded(&to, client, b"order"));
        let arrived = receiver.accept_one(&listener).expect("accepted");
        let taken = arrived.taken().expect("read to its end");
        sender.join().expect("the sender");

        assert_eq!(taken.bytes, b"order");
        let observed = |name: &str| {
            taken
                .observed
                .iter()
                .find(|(written, _)| written == name)
                .map(|(_, value)| value.clone())
        };
        assert_eq!(
            observed(TLS_PEER_SUBJECT).as_deref(),
            Some("CN=party-x.example")
        );
        assert_eq!(
            observed(TLS_PEER_VERIFIED).as_deref(),
            Some(TLS_HANDSHAKE_VERIFIED)
        );
        ArrivalIdentity::PEER.check(&taken).expect("the peer, too");

        let theirs = issued::Authority::new();
        let stranger = theirs
            .identity("party-y.example")
            .client()
            .expect("a client");
        let to = address.clone();
        let sender = std::thread::spawn(move || send_guarded(&to, stranger, b"order"));
        let refused = receiver.accept_one(&listener).expect_err("a stranger");
        sender.join().expect("the sender");
        assert!(refused.retryable, "the next client is taken: {refused:?}");
        assert!(refused.message.contains("handshake"), "{refused:?}");
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

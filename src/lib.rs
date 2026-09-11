#![forbid(unsafe_code)]

//! Streams that arrive over a TCP connection. One connection is one Stream.
//!
//! The pushed case: a caller connects, so a transport-level identity exists —
//! at minimum the peer address, which ADR-0019 clause 8 calls an *inferred*
//! identity rather than an absent one.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use transport::Arrived;
use transport::Directions;
use transport::Transport;
use transport::error::{Result, classify};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;

#[derive(Clone)]
pub struct TcpTransport {
    bind: String,
    accept_timeout: Option<Duration>,
}

impl TcpTransport {
    #[must_use]
    pub fn new(bind: impl Into<String>) -> Self {
        Self {
            bind: bind.into(),
            accept_timeout: None,
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

    /// Take one connection from an already-bound listener.
    ///
    /// # Errors
    ///
    /// Where the connection could not be accepted or read to its end.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Arrived> {
        let (mut stream, peer) = listener
            .accept()
            .map_err(|e| classify("accepting a connection", &e))?;

        if let Some(timeout) = self.accept_timeout {
            stream
                .set_read_timeout(Some(timeout))
                .map_err(|e| classify("setting the read timeout", &e))?;
        }

        let mut bytes = Vec::new();
        stream
            .read_to_end(&mut bytes)
            .map_err(|e| classify("reading the connection", &e))?;

        Ok(Arrived::new(format!("tcp://{peer}"), bytes))
    }
}

impl Transport for TcpTransport {
    fn name(&self) -> &'static str {
        "tcp"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn receive(&self) -> Result<Vec<Arrived>> {
        let (listener, _) = self.bind()?;

        Ok(vec![self.accept_one(&listener)?])
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let mut stream =
            TcpStream::connect(target).map_err(|e| classify("connecting to the peer", &e))?;

        stream
            .write_all(bytes)
            .map_err(|e| classify("writing to the peer", &e))?;

        stream
            .flush()
            .map_err(|e| classify("flushing to the peer", &e))
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

/// A bound listener waiting for its one connection.
struct Listening {
    transport: TcpTransport,
    listener: TcpListener,
    address: String,
}

impl FarEnd for Listening {
    fn address(&self) -> &str {
        &self.address
    }

    fn take_one(self: Box<Self>) -> Result<Arrived> {
        self.transport.accept_one(&self.listener)
    }
}

impl Loopback for TcpTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let (listener, address) = self.bind()?;
        Ok(Box::new(Listening {
            transport: self.clone(),
            listener,
            address,
        }))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        Self::new("127.0.0.1:0").send(address, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        sender.join().expect("the sending thread panicked");

        assert_eq!(arrived.bytes, b"hello over tcp");
        assert!(arrived.origin_uri.starts_with("tcp://127.0.0.1:"));
    }

    #[test]
    fn a_listening_socket_has_no_artefact_to_claim() {
        // ADR-0024. `None` rather than NoNativeClaim: the two are different
        // answers — no artefact at all, versus an artefact the protocol cannot
        // lock.
        assert!(TcpTransport::new("127.0.0.1:0").claims().is_none());
    }
}

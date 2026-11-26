//! What a Location of this technology is configured with: its declaration,
//! which `Configured` reads, built with the crate's `declaration` feature
//! alone and the code behind the default (ADR-0064, amendments 2026-10-22
//! and 2026-11-26), for the library the surfaces load to carry (open
//! problem 48).

use xcore::settings::{Applies, Fixed, Kind, Presence, Setting, Settings};

/// Every setting a Location takes beyond its address, which is where a
/// Receive Location listens and where a Send Location connects: the wait
/// for either, and whether a receive terminates TLS.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[
        transport::configured::timeout(
            Applies::Both,
            None,
            "How long a connection is waited for, accepted or opened, and how \
             long one that stops sending is waited on; unbounded when left out.",
        ),
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

/// The schemes a Location's address is entered with to choose this technology.
pub const SCHEMES: &[&str] = &["tcp"];

//! This technology's declaration: the transport guide's "The declaration",
//! `module/core/capability/transport/doc/adding-a-transport.md`.

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

/// This technology's schemes, as [`transport::Configured::SCHEMES`] defines
/// them.
pub const SCHEMES: &[&str] = &["tcp"];

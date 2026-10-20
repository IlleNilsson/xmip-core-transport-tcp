# xmip-core-transport-tcp

TCP transport: one connection is one Stream. A technology of
[xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport), which
owns the direction-neutral `Transport` trait this crate implements (ADR-0010).

Lifted out of the capability crate on 2026-09-07, where it had lived as
`src/tcp` since 2026-08-27 waiting for this repository. The capability keeps
the trait, the error vocabulary and the shared wire helpers; nothing in it names
a protocol.

A Receive Location keeps its listener, bound on the first receive (`transport::kept::Kept`): a peer that connects between two receives is queued and taken by the next, where until 2026-09-27 each receive bound a listener of its own and a peer between receives was refused.

A send writes the Message to its connection as it is read from the Ledger, a
piece at a time, never whole in memory (`Sending::Streamed`, 2026-10-19).

## TLS

A Receive Location whose settings say `tls = true` terminates TLS on every
connection, with the guard the node hands every transport it builds
(`transport::Guard`): the node's `[provision.receive]` certificate, and the
client's verified against the anchors given there. The handshake finishes
before a byte of content is read, and what it proved — the client
certificate's subject, issuer and fingerprint, and that it verified them —
is written on the arrival under `context::property`'s `tls.peer.*` names,
for the identity gates to claim and record as `mutual-tls`. A client the
handshake refuses is that client's failure alone, and the Location takes the
next. A Location asking for TLS on a node with no `receive` certificate is
refused as it is built, and a build without the `tls` feature refuses
`tls = true` in words (ADR-0033, amendment 2026-10-19). The handshake is
read under the guard's own bound, the node's `[tuning] receive_handshake`,
and the Location's `timeout` is put back for the content, so a client
slower than the Location's wait between its handshake messages is answered
and one whose content stalls is still let go after that wait (ADR-0033,
amendment 2026-10-20). Sending over TLS is not built.

## Acknowledgement

Acceptance is at-most-once here. Raw TCP frames a Stream by the connection
itself, closed to end it, and has no application-level reply: the sender's
write completed when its kernel took the bytes, so there is nobody left to
tell how the receive cycle ended. The body is the connection, read to its end
as the runtime asks, never whole in memory. Because the sender is done
already, a node's stop drains what is queued in the listener's backlog
before it closes it (`xmip-core-runtime`'s `receiving::drain`; ADR-0018,
amendment 2026-10-15).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.

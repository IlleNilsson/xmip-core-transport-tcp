# xmip-core-transport-tcp

TCP transport: one connection is one Stream. A technology of
[xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport), which
owns the direction-neutral `Transport` trait this crate implements (ADR-0010).

Lifted out of the capability crate on 2026-09-07, where it had lived as
`src/tcp` since 2026-08-27 waiting for this repository. The capability keeps
the trait, the error vocabulary and the shared wire helpers; nothing in it names
a protocol.

A Receive Location keeps its listener, bound on the first receive (`transport::kept::Kept`): a peer that connects between two receives is queued and taken by the next, where until 2026-09-27 each receive bound a listener of its own and a peer between receives was refused.

## Acknowledgement

Acceptance is at-most-once here. Raw TCP frames a Stream by the connection
itself, closed to end it, and has no application-level reply: the sender's
write completed when its kernel took the bytes, so there is nobody left to
tell how the receive cycle ended. The body is the connection, read to its end
as the runtime asks, never whole in memory.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.

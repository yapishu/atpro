# Server mode and Ames relay

## Feed Generator

`%atpro-server` is an AT Feed Generator implemented as a Gall agent. This is a
useful, standards-facing server role that fits Eyre well and does not imply
that the ship is already a Personal Data Server.

Its public surface is deliberately small:

- `app.bsky.feed.describeFeedGenerator` describes the configured service DID
  and feed record URI;
- `app.bsky.feed.getFeedSkeleton` returns configured post URIs with bounded,
  numeric cursor pagination;
- `/.well-known/did.json` advertises the `#bsky_fg` service from Eyre's exact
  response cache, avoiding ownership of the broader `/.well-known` route.

Administration is under `/apps/atpro/server` and requires an authenticated
Eyre session. The server is disabled by default. Enabling requires a
`did:web`, HTTPS endpoint, and AT feed record URI.

## PDS boundary

A network-valid PDS includes:

1. repository storage using AT's Merkle Search Tree representation;
2. commit signing with a DID-authorized secp256k1 or P-256 key;
3. CAR export and repository sync endpoints;
4. blob upload, retrieval, reference tracking, and quotas;
5. account/session, handle, DID, and PLC operation lifecycles;
6. sequenced federation events and reliable Relay crawling availability;
7. abuse controls, backups, recovery, and account export/import.

Eyre serves the HTTP endpoints. The PDS implementation proceeds from an
offline repository library and conformance fixtures to read-only sync, then
repository writes and federation service.

## Ames layer

Ames complements rather than replaces the AT network transport. One gateway
ship can consume Tap or Jetstream externally and distribute bounded events to
other ships over `%atpro-relay` Gall subscriptions:

```text
AT Relay -> Tap/Jetstream gateway ship -> Ames/Gall subscriptions -> ships
```

The Ames mark carries only a validated envelope:

```text
[%atpro-event source=@t cursor=@t did=@t collection=@t rkey=@t operation=@t received=@da]
```

Each relay deduplicates by source/cursor and applies a bounded queue. The
gateway's external adapter owns WebSocket reconnection and backpressure. Ships
can use Ames events for notifications, local indexes, or Feed Generator
curation without every ship maintaining an external socket.

Trust is explicit: downstream subscriptions are ship-allowlisted, the public
hook requires a separate Bearer token, and an optional configured upstream is
the only remote `%atpro-relay` watched by a follower. Public AT clients
continue to access server results through HTTPS/XRPC.

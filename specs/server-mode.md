# Server mode and Ames relay

## What exists now

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

## Why this is not yet a PDS

A network-valid PDS needs substantially more than HTTP routing:

1. repository storage using AT's Merkle Search Tree representation;
2. commit signing with a DID-authorized secp256k1 or P-256 key;
3. CAR export and repository sync endpoints;
4. blob upload, retrieval, reference tracking, and quotas;
5. account/session, handle, DID, and PLC operation lifecycles;
6. sequenced federation events and reliable Relay crawling availability;
7. abuse controls, backups, recovery, and migration semantics.

Eyre can serve the HTTP endpoints, so HTTP is not the blocker. Repository and
identity correctness are the actual work. A sensible PDS track would first
implement an offline repository library and conformance fixtures, then expose
read-only sync, and only later accept writes or advertise a production PDS.

## Proposed Ames layer

Ames should complement, not replace, the AT network transport. One gateway
ship can consume Tap or Jetstream externally and distribute bounded events to
other ships over Gall subscriptions:

```text
AT Relay -> Tap/Jetstream gateway ship -> Ames/Gall subscriptions -> ships
```

The first Ames protocol should carry only validated envelopes:

```text
[%at-event source=@t cursor=@t did=@t collection=@t rkey=@t operation=?]
[%curate feed=@t post=@t added=?]
```

Each subscriber persists its last cursor, deduplicates by source/cursor, and
applies a bounded queue. The gateway owns WebSocket reconnection and
backpressure. Ships can then use Ames events for notifications, local indexes,
or Feed Generator curation without every ship maintaining an external socket.

Trust should be explicit: subscriber ships allowlist gateway ships, and feed
owners allowlist ships permitted to send `%curate` messages. Public AT clients
continue to access the result through HTTPS/XRPC.

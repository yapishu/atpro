# Server mode and Ames relay

## Feed Generator

`%atpro-server` is an AT Feed Generator implemented as a Gall agent. It is a
small standards-facing service independent of `%atpro-pds`.

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

## Personal Data Server

`%atpro-pds` provides one account and repository with:

1. repository storage using AT's Merkle Search Tree representation and P-256
   signed commits;
2. full and incremental CAR export, block reads, repository sync, record writes,
   and reference-checked blob storage through the ship's configured
   S3-compatible service;
3. app-password sessions and an OAuth authorization server with PAR,
   ship-authenticated consent, PKCE-S256, ES256 DPoP, and refresh rotation;
4. protected-resource metadata and an `AtprotoPersonalDataServer` service in
   the public `did:web` document;
5. sequenced mutation events retained for the federation edge.
6. private account preferences and migration-oriented repository/blob counts.

Eyre serves all HTTP endpoints. Blob storage enforces 50 MiB per object and
1 GiB per account, tracks record references, gives untethered uploads a 24-hour
grace period, and deletes eligible objects in hourly and authenticated cleanup
batches.
Relay crawling still requires the WebSocket edge described below. Native-app
OAuth clients, backups, account import/export, and abuse controls remain
operational work.

Eyre has one exact `/.well-known/did.json` response per ship endpoint. Enable
either the Feed Generator DID publisher or the PDS DID publisher for a given
hostname, or expose the services through separate Eyre instances.

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

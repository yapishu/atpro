# `%atpro`

`%atpro` is a native AT Protocol client desk for Urbit. It connects to a
Personal Data Server (PDS) over HTTPS/XRPC, keeps session credentials inside a
Gall agent, and serves a small same-origin browser client.

The first working slice supports:

- app-password login against `https://bsky.social` or another HTTPS PDS;
- persisted access and refresh JWTs, never returned to browser JavaScript;
- timeline reads and manual refresh;
- public actor search;
- profile and thread navigation;
- text posts and replies;
- likes, reposts, follows, and notifications;
- local session refresh and disconnect;
- a constrained GET/POST XRPC bridge for authenticated Urbit users.
- an optional AT Feed Generator served publicly through Eyre.

## Architecture

`%atpro` is a normal AT Protocol client, not an AT Relay or PDS. AT Protocol's
network is federated client/server infrastructure; it is not a direct
end-device peer-to-peer protocol.

The `%atpro` Gall agent owns the PDS session and sends outbound HTTPS requests
through `%iris`. The browser calls `/apps/atpro/api` through an authenticated
Eyre session. It can choose only the public AppView or the connected PDS,
GET/POST, and a syntactically valid NSID, so it cannot turn the ship into a
general-purpose HTTP proxy. `%atpro-fileserver` serves `/desk/web` at
`/apps/atpro` using the %fileserver pattern.

## Realtime limitation

Vere does not currently expose a WebSocket client to userspace, while AT
Protocol's Relay firehose and Jetstream live streams are WebSocket services.
The native desk therefore uses ordinary HTTPS and manual refresh. This does
not limit login, reads, writes, repository operations, identity resolution, or
most XRPC calls.

A future realtime adapter should run Tap (or another small external consumer)
and deliver filtered events to an authenticated HTTP webhook on the ship.
Jetstream v2 snapshots are HTTP-accessible but use the `.jss` snapshot format
and are better suited to bulk catch-up than this client MVP.

## Authentication

Use a Bluesky app password, not the account's main password. The password is
sent once to `com.atproto.server.createSession`; returned JWTs are held in
Gall state. Browser status responses contain only service, DID, and handle.

AT Protocol OAuth is intentionally deferred. A conforming implementation
needs PKCE, PAR, DPoP, nonce handling, and asymmetric key support beyond the
RSA-only JOSE primitives currently available in the referenced Urbit desks.
The UI exposes an HTTPS-only preference hook, but labels it as unavailable
until the DPoP signer is implemented; it does not silently downgrade AT OAuth
to ordinary bearer-token OAuth.

## Feed Generator server mode

`%atpro-server` is a real AT Feed Generator service, not a full PDS. It serves:

- `GET /xrpc/app.bsky.feed.describeFeedGenerator`
- `GET /xrpc/app.bsky.feed.getFeedSkeleton`
- `GET /.well-known/did.json` through Eyre's exact-response cache
- authenticated administration at `/apps/atpro/server`

Configure it in the `%serve` screen with a public HTTPS endpoint, matching
`did:web`, and an `app.bsky.feed.generator` record URI in your connected
repository. The UI can publish that record and curate post URIs. Server mode
remains disabled until explicitly configured.

Running it on the public network requires a stable HTTPS hostname that reaches
Eyre. A full PDS remains a later project because it additionally requires
signed repositories/MSTs, CAR sync, blob storage, account and identity
lifecycle, federation ingestion, and operational availability.

## Build and install

The build requires Zig 0.15.2 and Git 2.25 or newer.

```sh
zig build
zig build -Ddesk="$HOME/.urbit/lux/atpro"
```

Commit the mounted desk and install it from the ship:

```hoon
|commit %atpro
|install our %atpro
```

Open `/apps/atpro/` on the ship. During greenfield development, edit
`state-0` directly and nuke/reinstall the affected agent after a schema change;
there are no migration versions in this desk.

## HTTP API

All routes require an authenticated Eyre session.

- `GET /apps/atpro/api/status`
- `POST /apps/atpro/api/login`
- `POST /apps/atpro/api/refresh`
- `POST /apps/atpro/api/logout`
- `POST /apps/atpro/api/rpc`

The RPC body is `{target, method, nsid, query?, body?}`. `target` is `public`
or `pds`, and `method` is `GET` or `POST`.

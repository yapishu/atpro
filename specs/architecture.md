# AT Protocol integration notes

This file records the implementation boundary chosen for `%atpro` after
reviewing the upstream `atproto` repository and the current network docs.

## What Urbit can do natively

AT Protocol control-plane and application calls use HTTPS XRPC. `%iris` can
make those calls directly, so a Gall agent can act as a normal client:

1. create and refresh a PDS session;
2. resolve identities and fetch public AppView data;
3. read feeds, profiles, threads, notifications, and repository records;
4. create records such as posts, likes, follows, and profile updates;
5. upload blobs and perform repository sync/catch-up work over HTTP.

The constrained bridge exposes GET and POST JSON XRPC. Image blobs use a
separate binary-safe upload route, and CAR repository sync uses dedicated PDS
routes rather than passing through the JSON bridge.

## Network model

AT Protocol is a federated network of independently operated services. A
client talks to a user's PDS and often a public AppView; PDS repositories are
aggregated by Relays and indexed by AppViews. Calling it “P2P” can be useful at
the ownership level, but it is not a peer socket protocol between the Urbit
ship and another user's device.

For `%atpro`, the useful mapping is:

| AT component | Urbit role |
| --- | --- |
| PDS | authenticated HTTPS peer used for account reads and writes |
| AppView | fixed public HTTPS peer used for unauthenticated discovery |
| Relay / Jetstream | optional event source, not required for client reads or writes |
| `%atpro` | credential owner, XRPC policy boundary, and client state |
| `%atpro-fileserver` | authenticated static UI delivery from Clay |

## WebSocket boundary

The Relay event stream and Jetstream live stream require a WebSocket client.
Vere does not expose one to ordinary Gall agents, so `%atpro` does not pretend
to offer a native firehose. The UI uses explicit refreshes.

The optional realtime path uses a small adapter:

```text
Relay / Jetstream WebSocket -> Tap filter -> authenticated HTTP webhook -> %atpro-relay -> Gall/Ames
```

`%atpro-relay` deduplicates by source/cursor, persists a bounded queue, and
publishes typed facts to allowlisted subscribers. The adapter owns socket
reconnect, cursor resume, and backpressure.

## Credential boundary

The browser never receives an app password after submitting the login request,
and never receives either JWT. The persisted `state-0` contains the connected
PDS origin, DID, handle, access JWT, and refresh JWT. HTTP status and the scry
surface contain only the origin, DID, and handle.

The RPC bridge accepts two destinations:

- `public` is always `https://public.api.bsky.app` and receives no bearer token;
- `pds` is the HTTPS origin selected during login and receives the access JWT.

The bridge accepts only GET/POST and NSID-shaped method names. Arbitrary
destination URLs are not accepted.

## Authentication

The desk supports both app-password sessions and full AT Protocol
OAuth. OAuth discovery resolves handles and DID documents, validates PDS and
issuer metadata, and uses PKCE, PAR, ES256 DPoP proofs, `ath`, and separate
authorization-server/PDS nonce state. Tokens and the private P-256 key never
cross the Gall/browser boundary.

## Capabilities

- profiles, author feeds, threads, replies, notifications, follows, likes, and
  reposts in the browser client;
- one refresh-and-retry after an authenticated PDS request returns 401;
- explicit public handle/DID publication through Gall scry and one-shot
  discovery across `%pals` and `%contacts`;
- binary-safe image upload and image post composition;
- a bounded token-protected event webhook with allowlisted Ames distribution;
- a separate `state-0` Feed Generator agent with public Eyre XRPC endpoints,
  DID document caching, authenticated configuration, curated posts, and cursor
  pagination;
- a separate `state-0` PDS agent with canonical repository encoding, upstream
  MST vectors, P-256 signed commits, monotonic revisions, CAR snapshots, and
  initial repository and sync XRPC methods.

## Roadmap

1. Add typed client actions for ship-native XRPC callers, sharing the same
   destination and NSID policy as HTTP.
2. Complete PDS record transactions, commit retention, and sync block queries.
3. Add blob storage through the ship's configured `%storage` service, account
   sessions, OAuth provider behavior, and DID service lifecycle.
4. Pair the Eyre sync HTTP surface with a small WebSocket edge for
   `com.atproto.sync.subscribeRepos` federation.

## Upstream references

- <https://atproto.com/specs/xrpc>
- <https://atproto.com/specs/atp>
- <https://atproto.com/specs/oauth>
- <https://docs.bsky.app/docs/advanced-guides/firehose>
- <https://bsky.network/about/faq>
- local upstream checkout: `../atproto`

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

The current implementation deliberately exposes only GET and POST JSON XRPC.
Blob transfers and CAR repository sync need explicit binary-safe routes rather
than being squeezed through this JSON bridge.

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

The preferred future path is an optional Tap companion:

```text
Relay / Jetstream WebSocket -> Tap filter -> authenticated HTTP webhook -> %atpro
```

This keeps the native desk useful without a sidecar, lets Tap handle cursor
resume and backpressure, and delivers only events relevant to the connected
account. Jetstream v2's HTTP snapshot API may later provide bulk catch-up, but
its `.jss` segments and metered access make it a separate ingestion feature.

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

## Authentication phases

The greenfield desk starts with app-password sessions because they fit Urbit's
existing HTTP and JSON capabilities and make the credential boundary easy to
audit.

OAuth should be a separate phase. The AT Protocol profile requires PKCE, PAR,
DPoP proofs and nonce retry behavior. The local OAuth references are useful
for redirect/state plumbing, but their JOSE support does not by itself satisfy
the asymmetric signing profile required by AT Protocol.

## Next implementation slices

1. Add typed Gall actions and marks for ship-native callers, sharing the same
   policy checks as HTTP.
2. Add proactive refresh and one safe refresh-and-retry on expired access JWTs.
3. Add typed clients for notifications, threads, follows, likes, and reposts.
4. Add binary-safe blob upload and image-post composition.
5. Add handle/DID resolution so the PDS origin can be discovered automatically.
6. Add the optional Tap webhook, cursor persistence, deduplication, and a
   bounded event queue.
7. Add OAuth only after suitable P-256 or secp256k1 signing primitives exist.

## Upstream references

- <https://atproto.com/specs/xrpc>
- <https://atproto.com/specs/atp>
- <https://atproto.com/specs/oauth>
- <https://docs.bsky.app/docs/advanced-guides/firehose>
- <https://bsky.network/about/faq>
- local upstream checkout: `../atproto`

# `%atpro`

<img width="1200" height="701" alt="image" src="https://github.com/user-attachments/assets/d94322ec-1c27-4dbd-a4cd-08edd7a0ecf8" />

`%atpro` is a native AT Protocol desk for Urbit. It includes an HTTPS/XRPC
client, a same-origin browser application, a Feed Generator, a bounded event
relay, and a ship-native single-account PDS implementation.

The desk supports:

- app-password login against `https://bsky.social` or another HTTPS PDS;
- AT Protocol OAuth with PKCE, PAR, ES256 DPoP, nonce retry, and refresh;
- persisted access and refresh JWTs, never returned to browser JavaScript;
- timeline reads and manual refresh;
- public actor search;
- profile and thread navigation;
- text posts and replies;
- image blob upload and image posts;
- likes, reposts, follows, and notifications;
- local session refresh and disconnect;
- explicit AT identity publication and one-shot contact discovery;
- a constrained GET/POST XRPC bridge for authenticated Urbit users;
- an optional AT Feed Generator served publicly through Eyre;
- an optional token-protected event webhook and Ames/Gall relay.
- deterministic AT repository blocks, signed commits, CAR exports, and a
  single-account PDS served through Eyre.

## Architecture

AT Protocol's network is federated client/server infrastructure; it is not a
direct end-device peer-to-peer protocol. The main `%atpro` agent is a normal
client. `%atpro-pds` owns a separate repository and exposes PDS XRPC methods.

The `%atpro` Gall agent owns the PDS session and sends outbound HTTPS requests
through `%iris`. The browser calls `/apps/atpro/api` through an authenticated
Eyre session. It can choose only the public AppView or the connected PDS,
GET/POST, and a syntactically valid NSID, so it cannot turn the ship into a
general-purpose HTTP proxy. `%atpro-fileserver` serves `/desk/web` at
`/apps/atpro` using the %fileserver pattern.

## Realtime limitation

Vere does not currently expose a WebSocket client to userspace, while AT
Protocol's Relay firehose and Jetstream live streams are WebSocket services.
The native client therefore uses ordinary HTTPS and explicit refresh. This
does not limit login, reads, writes, repository operations, identity
resolution, or most XRPC calls. `%atpro-relay` provides the WebSocket boundary:
Tap (or another small external consumer) posts filtered events to a
token-protected Eyre hook, and the ship redistributes them to allowlisted ships
through Gall subscriptions.

## Authentication

OAuth is the preferred sign-in mode on public HTTPS origins. `%atpro` performs
handle/DID and authorization-server discovery, PKCE, PAR, P-256 DPoP signing,
nonce retries, token exchange, and refresh. The private DPoP key and both
tokens remain in Gall state.

App-password login remains available as a fallback. Use a Bluesky app
password, not the account's main password. Browser status responses contain
only the service, DID, handle, and authentication mode.

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
Eyre.

## PDS mode

`%atpro-pds` maintains one account and one signed AT repository in `state-0`.
Its repository core provides deterministic DAG-CBOR, CIDv1 text and binary
forms, CAR v1 framing, protocol-compatible Merkle Search Trees, monotonic TIDs,
P-256 commit signing, and `did:key` generation. The MST fixtures match the
empty, trivial, elevated-layer, and multi-node roots in the upstream AT
Protocol implementation.

Authenticated administration is available at `/apps/atpro/pds`. Enabling the
service sets its HTTPS origin, DID, and handle and creates the initial signed
repository commit. Eyre serves `describeRepo`, `getRecord`, `listRecords`,
`createRecord`, `putRecord`, `deleteRecord`, transactional `applyWrites`,
`uploadBlob`, `getLatestCommit`, `getRepoStatus`, `listRepos`, CAR `getRepo`,
CAR `getBlocks`, `getBlob`, and `listBlobs` XRPC methods. Record writes and
blob uploads accept either an authenticated Eyre session or a valid PDS access
token; repository and blob reads are public. The PDS also serves
`describeServer`, `createSession`, `getSession`, `refreshSession`, and
`deleteSession`. Access tokens expire after two hours, refresh tokens expire
after ninety days, refresh rotates both tokens, and deletion revokes the whole
session.

PDS administration accepts a `serviceDid` and optional `appPassword` alongside
the origin, account DID, and handle. The password is stored only as a salted
HMAC-SHA256 digest. The PDS issues standard HS256 AT access and refresh JWTs;
changing the password or hosted identity revokes every active session.

Blob bytes live in the S3-compatible endpoint selected in the ship's
`%storage` settings. `%atpro-pds` reads that endpoint, bucket, region, and
credentials from `%storage`, signs private PUT/GET requests inside Gall, and
persists only CID, MIME type, size, object key, and repository-revision
metadata. Both HTTP and HTTPS self-hosted endpoints are supported. The active
Storage service must expose credentials; browser-only presigned-URL mode does
not provide Gall with the secret needed for server-side blob reads and writes.

The remaining public-service work covers OAuth provider behavior, blob
reference validation and garbage collection, incremental sync ranges, DID
publication, and the WebSocket federation edge.

## Event relay mode

`%atpro-relay` accepts normalized events at `POST /apps/atpro/hook` when the
hook is explicitly enabled and the request has its configured Bearer token.
Configure it in the `%serve` screen. Events are deduplicated by source/cursor,
kept in a bounded queue, and published as `%atpro-event` facts on `/events`.
An allowlist controls downstream Ames subscribers; an optional upstream ship
turns an instance into a follower of another `%atpro-relay` gateway.

## Ship identity discovery

A connected user can explicitly publish the confirmed AT handle/DID pair from
the settings menu. Other ships read the typed public scry at
`/=atpro=/identity/noun`; `/=atpro=/identity-json/json` provides the same
public information as JSON. Disconnecting the AT session does not unpublish
the identity, and the user can unpublish it at any time.

The “scan contacts” action reads the local `%contacts` book once, checks up to
64 ships for the public identity scry, and shows the discovered AT profiles in
the find screen. A ship without Landscape or contacts returns an empty result.
It does not poll or automatically follow accounts.

## Build and install

The build requires Zig 0.15.2 and Git 2.25 or newer.

```sh
zig build
zig build -Ddesk="$HOME/.urbit/PIER/atpro"
```

Commit the mounted desk and install it from the ship:

```hoon
|commit %atpro
|install our %atpro
```

Open `/apps/atpro/` on the ship. During greenfield development, edit
`state-0` directly and nuke/reinstall the affected agent after a schema change.

## HTTP API

Client and administration routes require an authenticated Eyre session. The
OAuth callback and client metadata routes are public by protocol design.

- `GET /apps/atpro/api/status`
- `POST /apps/atpro/api/login`
- `POST /apps/atpro/api/refresh`
- `POST /apps/atpro/api/logout`
- `POST /apps/atpro/api/rpc`
- `POST /apps/atpro/api/blob`
- `POST /apps/atpro/api/oauth/start`
- `GET /apps/atpro/api/oauth/callback`
- `GET /apps/atpro/api/oauth/client-metadata`
- `GET /apps/atpro/api/identity`
- `POST /apps/atpro/api/identity/publish`
- `POST /apps/atpro/api/identity/clear`
- `POST /apps/atpro/api/identity/scan`

The RPC body is `{target, method, nsid, query?, body?}`. `target` is `public`
or `pds`, and `method` is `GET` or `POST`.

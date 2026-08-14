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
- profile and thread navigation, with post/reply feeds and private access to
  the connected account's likes;
- text posts and replies;
- image blob upload and image posts;
- likes, reposts, follows, and notifications;
- local session refresh and disconnect;
- route-aware browser history so hardware back/forward buttons traverse app
  views without leaving the app;
- explicit AT identity publication and one-shot contact discovery;
- a constrained GET/POST XRPC bridge for authenticated Urbit users;
- an optional AT Feed Generator served publicly through Eyre;
- an optional token-protected event webhook and Ames/Gall relay.
- deterministic AT repository blocks, signed commits, CAR exports, and a
  single-account PDS served through Eyre.
- an AT OAuth authorization server with PAR, consent, PKCE, ES256 DPoP,
  rotating refresh tokens, and replay rejection.

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

The browser application is a React/Vite project in `fe/`. API helpers and the
post, profile, and service-control components are separate modules. The root
Zig build runs Vite first and writes fixed Clay-safe `app.js` and `app.css`
assets into `desk/web`; generated desk assets are the distribution rather than
the frontend source of truth.

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

Configure it in the `PDS + services` screen with a public HTTPS endpoint, matching
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
CAR `getBlocks`, `getBlob`, `listBlobs`, and `listMissingBlobs` XRPC methods.
`getRepo?since=` returns only blocks absent from the retained base revision,
rooted at the current commit. `getRecord` returns a current-rooted CAR that
proves record existence or non-existence. Record writes and
blob uploads accept either an authenticated Eyre session or a valid PDS access
token; repository and blob reads are public. The PDS also serves
`describeServer`, `createSession`, `getSession`, `refreshSession`, and
`deleteSession`, private `getPreferences`/`putPreferences`, and
`checkAccountStatus` migration metrics. Authenticated clients can request
method-bound ES256 `getServiceAuth` JWTs for DID audiences. Access tokens expire after two hours, refresh tokens expire
after ninety days, refresh rotates both tokens, and deletion revokes the whole
session.

The browser exposes this administration as `PDS + services` in the sidebar and
as `open ship PDS control` on the disconnected screen. Configuring the local
PDS does not require connecting an external AT account.

PDS administration accepts a `serviceDid` and optional `appPassword` alongside
the origin, account DID, and handle. The password is stored only as a salted
HMAC-SHA256 digest. The PDS issues standard HS256 AT access and refresh JWTs;
changing the password revokes every app-password session, while changing the
hosted identity revokes app-password and OAuth sessions.

The same service is an OAuth authorization server and protected resource. It
publishes `/.well-known/oauth-protected-resource`,
`/.well-known/oauth-authorization-server`, and `/.well-known/did.json`; accepts
pushed authorization requests at `/oauth/par`; presents ship-authenticated
consent at `/oauth/authorize`; and exchanges or refreshes grants at
`/oauth/token`. Authorization codes are one-use and PKCE-S256-bound. OAuth
access tokens are bound to the client's P-256 key, and protected XRPC requests
must include an ES256 DPoP proof with the correct method, URL, access-token
hash, time window, and unused `jti`. Access and refresh lifetimes are two hours
and ninety days, and refresh rotates the whole OAuth session.

The provider accepts public web clients whose HTTPS redirect URI has the same
origin as the URL-valued client ID. This secure web-client profile covers
hosted browser clients without turning the authorization endpoint into an open
redirect. Remote client-metadata retrieval and native-app redirect schemes are
not part of the accepted client profile.

Blob bytes live in the S3-compatible endpoint selected in the ship's
`%storage` settings. `%atpro-pds` reads that endpoint, bucket, region, and
credentials from `%storage`, signs private PUT/GET/DELETE requests inside Gall,
and persists only CID, MIME type, size, object key, upload time, and
record-reference metadata. Standard blob references become DAG-CBOR links only
after their CID, MIME type, and size match a stored object. A single upload is
limited to 50 MiB and the account blob quota is 1 GiB. Newly uploaded objects
have a 24-hour untethered grace period; objects whose final record reference is
removed are immediately eligible for cleanup. Gall runs the same bounded
cleanup every hour, and the authenticated `clean blobs` control runs it on
demand. Each pass schedules up to 50 eligible deletions and keeps failed
objects available for retry. Both HTTP and HTTPS self-hosted endpoints are supported. The active
Storage service must expose credentials; browser-only presigned-URL mode does
not provide Gall with the secret needed for server-side blob reads and writes.

The remaining public-service work covers remote client-metadata validation,
native-app OAuth redirects, account lifecycle and
import/export operations, backups, abuse controls, and the WebSocket federation
edge.

## Event relay mode

`%atpro-relay` accepts normalized events at `POST /apps/atpro/hook` when the
hook is explicitly enabled and the request has its configured Bearer token.
Configure it in the `PDS + services` screen. Events are deduplicated by source/cursor,
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
cd fe && npm install && cd ..
zig build
zig build -Ddesk="$HOME/.urbit/PIER/atpro"
```

For frontend development, `npm run dev --prefix fe` starts Vite and proxies
`/apps/atpro` and `/xrpc` requests to local Eyre.

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

PDS administration is at `GET /apps/atpro/pds/status` and
`POST /apps/atpro/pds/configure`. Public PDS discovery and authorization use
`/.well-known/oauth-protected-resource`,
`/.well-known/oauth-authorization-server`, `/.well-known/did.json`,
`/oauth/par`, `/oauth/authorize`, and `/oauth/token`. XRPC remains under
`/xrpc/<nsid>`.

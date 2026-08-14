# `%atpro`

## `|install ~matwet %atpro`

<img width="1200" height="701" alt="%atpro" src="https://github.com/user-attachments/assets/d94322ec-1c27-4dbd-a4cd-08edd7a0ecf8" />

`%atpro` connects an Urbit ship to the AT Protocol network. It can be used as
a Bluesky client, publish an account's identity to other ships, and host AT
Protocol services through Eyre.

## Client

- Sign in to Bluesky or another PDS with OAuth or an app password.
- Read and refresh the home timeline.
- Search for people and open profiles, threads, followers, and following.
- Browse separate post, reply, and personal-like feeds.
- Write posts and replies, including image uploads.
- Like, repost, follow, and unfollow.
- Read notifications and open the people or posts behind them.
- Navigate app views with browser back/forward buttons.
- Follow the system appearance or select light or dark mode.

Credentials and tokens stay inside the Gall agent. The browser receives only
the connected account's public identity and session status.

## Ship identity discovery

A connected account can publish its confirmed AT handle and DID through a
public Gall scry. Friends can scan their `%contacts` once to find the AT
accounts published by ships they know. Publication is explicit and can be
removed at any time.

## Personal Data Server

The optional single-account PDS hosts an AT repository directly on the ship.
It provides:

- signed AT repository commits and full or incremental CAR exports;
- record creation, updates, deletion, and atomic write batches;
- image and blob storage through the ship's configured `%storage` service;
- app-password sessions and an AT Protocol OAuth authorization server;
- account preferences, repository status, and migration-oriented sync calls;
- public DID, OAuth metadata, repository, sync, and blob endpoints;
- reference-checked blob quotas and automatic hourly cleanup.

PDS setup is available from `PDS + services` or from the disconnected screen.
It does not require connecting a separate AT account. Public operation requires
a stable HTTPS hostname routed to Eyre.

## Feed Generator

The ship can serve an AT Feed Generator through Eyre. Configure its public
endpoint, service DID, and feed record in `PDS + services`, then curate the post
URIs returned by the feed.

## Event relay

`%atpro-relay` accepts a token-protected stream of normalized AT events and can
distribute them to allowlisted ships over Ames/Gall. An external Tap or
Jetstream consumer supplies the WebSocket connection and posts selected events
to the ship.

Vere does not expose WebSockets to Gall agents, so the native client uses HTTPS
and explicit refresh. This does not limit login, profiles, posting, repository
sync, PDS hosting, or the other XRPC features.

## Build and install

The build requires Zig 0.15.2, Git 2.25 or newer, and Node/npm for the React
frontend.

```sh
npm install --prefix fe
zig build -Ddesk="$HOME/.urbit/PIER/atpro"
```

Then commit and install the mounted desk:

```hoon
|commit %atpro
|install our %atpro
```

Open `/apps/atpro/` on the ship. `npm run dev --prefix fe` runs the frontend
development server.

## Technical documentation

Implementation details and the development roadmap live in [`specs/`](specs/),
including the [architecture](specs/architecture.md),
[PDS](specs/pds.md), and [server-mode](specs/server-mode.md) notes.

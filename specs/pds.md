# PDS architecture and roadmap

`%atpro-pds` is the ship-native AT Protocol Personal Data Server. Eyre owns
HTTPS routing; Gall owns accounts, repositories, blobs, sessions, sequencing,
and durable service configuration. An optional edge process exposes the one
federation surface Eyre cannot provide: the
`com.atproto.sync.subscribeRepos` WebSocket event stream.

## Repository core

The repository library is independent of Gall and has deterministic fixtures:

1. canonical DAG-CBOR encoding and decoding for AT data values;
2. CIDv1 creation and parsing with the codecs and multihashes used by AT repos;
3. CAR v1 import/export with block validation;
4. the AT Merkle Search Tree key layout, insertion, deletion, proofs, and
   deterministic root construction;
5. signed commit objects using a DID-authorized P-256 or secp256k1 key;
6. commit diffs and monotonic repository revisions.

Upstream vectors from `../atproto` are the conformance oracle. Every encoded
block, CID, MST root, commit signature, and CAR export is compared byte-for-byte
where the upstream fixtures make that possible.

## PDS state and storage

The Gall state contains service configuration, account metadata, repository
heads, record indexes, blob metadata, session grants, and the federation
sequence cursor. Large CARs and blobs use the ship's configured `%storage`
service and its S3-compatible backend, with ship-local storage available for
small installations. Gall retains hashes, ownership, references, MIME type,
size, quota, and garbage-collection state. The integration follows `%boox`'s
configuration discovery while keeping storage credentials behind the ship
boundary.

Repository mutation is transactional: validate the Lexicon-shaped record,
write referenced blocks, build the new MST, sign one commit, advance the head,
and append one sequenced federation event. A failed step does not expose a new
head.

## HTTP and authentication

Eyre serves the standard PDS surfaces:

- identity, account, session, and OAuth discovery/token endpoints;
- `com.atproto.repo` record and blob operations;
- `com.atproto.sync` repository, block, blob, and status endpoints;
- repository description, preferences, and service configuration endpoints;
- DID documents and protected-resource metadata for the configured HTTPS
  origin.

OAuth uses the same PKCE, PAR, DPoP, and nonce rules as the client, with the
ship acting as authorization server and protected resource. Operators can
also enable app-password sessions.

## Federation edge

Relay crawling needs a WebSocket server for
`com.atproto.sync.subscribeRepos`. The edge process has no repository authority.
It subscribes to a token-protected, cursor-based HTTP stream from `%atpro-pds`,
encodes AT event-stream frames, serves WebSocket clients, and reports delivered
cursors and backpressure. All repository reads, sequence assignment, and event
retention remain ship-side.

The same edge can act as an outbound Jetstream/Tap client for `%atpro-relay`.
That client role and PDS federation role use separate credentials and queues.

## Delivery order

1. repository primitives and upstream conformance vectors;
2. local single-account repository state and signed mutations;
3. CAR/sync reads and blob storage;
4. account sessions plus OAuth provider endpoints;
5. public HTTPS PDS service through Eyre;
6. WebSocket federation edge and Relay interoperability tests;
7. backups, account import/export, quotas, abuse controls, and operational
   health surfaces.

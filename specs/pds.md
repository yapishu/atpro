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
4. the AT Merkle Search Tree key layout and deterministic root construction;
5. signed commit objects using a DID-authorized P-256 or secp256k1 key;
6. commit diffs and monotonic repository revisions.

Upstream vectors from `../atproto` are the conformance oracle. Every encoded
block, CID, MST root, commit signature, and CAR export is compared byte-for-byte
where the upstream fixtures make that possible.

Implementation status:

- deterministic DAG-CBOR encoding, raw CIDv1/DAG-CBOR/SHA-256 identifiers,
  and bounded conformance generators compile and run in Vere;
- strict DAG-CBOR decoding, unsigned varints, and CAR v1 framing use the same
  bounded representation and conformance generators;
- canonical MST reconstruction matches the upstream empty, trivial,
  elevated-layer, and multi-node root fixtures byte-for-byte;
- signed version-3 commits use a generated P-256 key, raw low-S signatures,
  and the matching `did:key` multikey representation;
- monotonic TIDs and atomic record-to-MST-to-commit-to-CAR snapshots compile
  and run in Vere.

## PDS state and storage

The `%atpro-pds` Gall state contains service configuration, the P-256 signing
key, repository head and revision, a record index, current blocks and CAR,
monotonic revision state, and a sequenced mutation log. Its `state-0` is a
single-account model.

The blob-storage checkpoint uses the ship's configured `%storage` service and
its S3-compatible backend. Gall retains hashes, ownership, references, MIME
type, size, quota, and garbage-collection state; storage credentials remain
behind the ship boundary. Configuration discovery follows the `%boox`
integration pattern.

Repository mutation is transactional: validate the Lexicon-shaped record,
write referenced blocks, build the new MST, sign one commit, advance the head,
and append one sequenced federation event. A failed step does not expose a new
head.

## HTTP and authentication

Eyre currently serves:

- authenticated PDS configuration and status at `/apps/atpro/pds`;
- `com.atproto.repo.describeRepo`, `getRecord`, cursor-based `listRecords`,
  `createRecord`, `putRecord`, `deleteRecord`, and atomic `applyWrites`;
- `com.atproto.sync.getLatestCommit`, CAR `getRepo`, and CAR `getBlocks`.

The HTTP/authentication checkpoint extends this surface with:

- identity, account, session, and OAuth discovery/token endpoints;
- remaining `com.atproto.repo` record and blob operations;
- block, blob, cursor, and status endpoints in `com.atproto.sync`;
- repository description, preferences, and service configuration endpoints;
- DID documents and protected-resource metadata for the configured HTTPS
  origin.

The provider uses the same PKCE, PAR, DPoP, and nonce rules as the working
client implementation, with the ship acting as authorization server and
protected resource. Operators can also enable app-password sessions.

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

1. complete record transaction swap guards and commit-history retention;
2. blob storage, reference tracking, and CAR/sync range reads;
3. account sessions plus OAuth provider endpoints;
4. DID document/service publication and public HTTPS interoperability tests;
5. WebSocket federation edge and Relay interoperability tests;
6. backups, account import/export, quotas, abuse controls, and operational
   health surfaces.

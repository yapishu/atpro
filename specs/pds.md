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
retained signed snapshots, referenced and pending-delete blob metadata, salted
app-password digest, HS256
session key, active app-password and OAuth sessions, pending authorization
requests, one-use authorization codes, DPoP replay identifiers, monotonic
revision state, private account preferences, and a sequenced mutation log. Its sole state type is the
single-account `state-0`.

Blob storage uses the ship's configured `%storage` service and its
S3-compatible backend. Configuration discovery follows the `%boox` JSON scry
pattern. Gall reads the configured endpoint, bucket, region, access key, and
secret; signs private S3-compatible PUT/GET/DELETE requests; and retains the
raw CID, MIME type, size, object key, upload time, tether status, current record references,
and last reference revision. Credentials remain behind
the ship/browser boundary. The configured endpoint controls the hostname and
HTTP/HTTPS scheme; no vendor endpoint is substituted.

Repository mutation is transactional: validate the Lexicon-shaped record,
write referenced blocks, build the new MST, sign one commit, advance the head,
and append one sequenced federation event. A failed step does not expose a new
head.

## HTTP and authentication

Eyre currently serves:

- authenticated PDS configuration and status at `/apps/atpro/pds`;
- authenticated blob cleanup at `POST /apps/atpro/pds/cleanup`, in batches of
  at most 50 objects;
- `com.atproto.server.describeServer`, app-password `createSession`, protected
  `getSession`, rotating `refreshSession`, revoking `deleteSession`, and
  migration-oriented `checkAccountStatus`;
- authenticated ES256 `getServiceAuth` JWTs bound to a DID audience, optional
  XRPC method, and an expiration no more than one hour ahead;
- authenticated `app.bsky.actor.getPreferences` and `putPreferences`, with at
  most 100 private preference entries;
- `com.atproto.repo.describeRepo`, `getRecord`, cursor-based `listRecords`,
  `createRecord`, `putRecord`, `deleteRecord`, atomic `applyWrites`, and binary
  `uploadBlob`, plus authenticated `listMissingBlobs` for migration clients;
- `com.atproto.sync.getLatestCommit`, `getRepoStatus`, single-account
  `listRepos`, CAR `getRepo`, record-proof CAR `getRecord`, CAR `getBlocks`, binary `getBlob`, and
  cursor-based `listBlobs`;
- commit and record compare-and-swap guards plus retained signed snapshots for
  historical block lookup, revision validation, and incremental CAR exports;
- protected-resource and authorization-server metadata, a PDS service DID
  document, PAR, ship-authenticated consent, authorization-code exchange, and
  OAuth refresh at the standard well-known and `/oauth` routes.

Repository mutations and blob uploads accept an authenticated Eyre session or
a non-expired PDS access JWT. Refresh and deletion require the matching refresh
JWT. Tokens are HS256 AT JWTs with `sub`, `aud`, `scope`, `jti`, `iat`, and
`exp` claims. Access tokens last two hours and refresh tokens last ninety days.
Rotating or deleting a session immediately invalidates its former access token.
Changing the app password revokes all app-password sessions. Changing the
account DID, handle, or service DID also revokes OAuth sessions and pending
grants.

OAuth authorization codes expire after five minutes, are consumed once, and
require the original redirect URI, client ID, P-256 key thumbprint, and
PKCE-S256 verifier at exchange. Access tokens last two hours; refresh tokens
last ninety days and rotate with the access token. Each protected request
validates the ES256 DPoP signature, `htm`, `htu`, `iat`, an optional `exp`,
`ath`, key thumbprint, and a previously unused `jti`. The accepted client
profile is a URL-valued public HTTPS client ID with a same-origin HTTPS
redirect URI.
Expired requests, codes, sessions, and replay identifiers are removed during
request handling, and pending authorization requests are capped at 256.

Blob writes enforce a 50 MiB object limit and a 1 GiB account quota. Record
mutation recursively checks every typed blob reference against stored CID, MIME,
and size metadata before committing, then updates the reference index. Blob links
are encoded as DAG-CBOR links to the stored raw CID. Untethered uploads receive a
24-hour grace period; a formerly tethered blob becomes cleanup-eligible as soon as
its last reference disappears. Cleanup moves objects to durable pending state,
signs DELETE requests against the exact configured Storage endpoint, removes
successful objects, and restores failed objects for retry.

`com.atproto.sync.getRepo?since=` compares the retained base snapshot with the
current snapshot and returns a current-rooted CAR containing only new blocks.
`listBlobs?since=` returns currently referenced blobs associated after the base
revision. Unknown retained revisions are rejected.

The remaining HTTP/storage work includes:

- automatic periodic blob cleanup and configurable quota policy;
- service configuration and broader account lifecycle endpoints;
- remote OAuth client-metadata validation and native application redirect
  profiles.

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

1. add remote OAuth client metadata and native-app redirect profiles;
2. add account import/export and automatic cleanup;
3. add the WebSocket federation edge and Relay interoperability tests;
4. add backups, configurable quotas, abuse controls, and operational
   health surfaces.

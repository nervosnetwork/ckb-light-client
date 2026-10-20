# Transaction inclusion evidence

This is a proposed additive API; names and the contract require maintainer review.

`getTransactionEvidence(hash)` observes local data. `fetchTransactionEvidence(hash)`
also schedules an existing transaction-proof request if current evidence is missing,
even when transaction bytes are already cached. Neither method broadcasts transactions.
Legacy `getTransaction`, `fetchTransaction` and their response formats are unchanged.

Evidence records are written only after the transaction-proof processor has checked
the requested hashes, header PoW, extra hashes, MMR proof and transaction Merkle proofs.
The transaction, inclusion header and receipt commit in one storage batch. Legacy
unproved storage writes clear the receipt. There is no public receipt-writing service
or WASM endpoint. This trusts the configured chain and local process/database; a receipt
is not a portable cryptographic proof against local database corruption or edits.

| `state` | Guarantee |
|---|---|
| `unknown` | No transaction in the stored snapshot or subsequently observed local pending pool. Not proof of network absence. |
| `local_pending` | Present in the local pending pool. Not inclusion evidence, propagation or peer acceptance. The pending pool is observed separately from the database snapshot. |
| `stored_without_evidence` | Syntactically valid bytes matching the requested raw transaction hash are stored; no usable matching receipt/header was found. Covers legacy data, invalid receipt versions and damaged/missing inclusion headers. |
| `verified_current` | Inclusion was verified at the **exact** `accepted_anchor` hash and height in the database snapshot returned with this observation. Not finality, unspentness, network freshness or independent verification of all witnesses. |
| `verified_other_anchor` | A matching receipt records successful inclusion verification at `proof_anchor_hash` / `proof_anchor_number`, different from the observed accepted tip. Current-chain membership is not asserted; this anchor need not previously have been the locally accepted tip. |
| `observation_changed` | The receipt changed while its header key was being selected. No transaction/evidence assertion is returned; retry with a caller-defined deadline. |

Malformed transaction rows, hash mismatches, invalid/missing accepted-state metadata,
I/O errors and unsupported snapshot backends return errors, not verified results.
The new endpoints reject missing hash prefixes, wrong lengths and non-hexadecimal
digits. Legacy hash parsing is unchanged. Valid raw JSON-RPC number fields are
hexadecimal strings; unavailable metadata and transaction fields are `null`.

The receipt's inclusion hash is checked against the stored header's **computed** hash
and height, and the requested transaction hash is recomputed from transaction bytes.
Number-to-hash cache mappings are not used to infer inclusion. Built-in backends read
transaction, receipt, header and accepted state from one database snapshot. External
`StorageBackend` implementations remain source compatible but must implement atomic
`get_many` before using this API; the default returns an unsupported error.

## Progress, expiry and restart

Fetch responses use the existing statuses: `added` (queued), `fetching` (request
scheduling has begun; not proof of peer receipt), `not_found` (peer reported missing;
requeued as in the legacy fetch API),
and `fetched`. Only a `verified_current` observation qualifies for `fetched` here.
Pending, stored bytes or a stale receipt never qualify. Callers must bound retries.

Every accepted-tip change expires currentness, including an ordinary extension.
Repeated reads at an unchanged anchor reuse the receipt; they do not enqueue another
proof. A late valid response for an old anchor can store stale evidence and replace a
newer receipt, requiring another fetch; it cannot mark old evidence current. No ancestry
optimization or request-scoped header revalidation is implied by this API.

Receipts persist with the database. At restart they are compared with the persisted
accepted anchor. An offline restart can therefore return `verified_current` relative to
that retained anchor, without knowing whether the network has advanced. Missing or
malformed receipts are not retroactively upgraded. Orphan metadata without a stored
transaction cannot establish inclusion. Existing corrupted watched indexes are not
repaired by this feature.

## Retry and metadata policy

Use one in-flight poller per transaction hash, a caller deadline and cancellation.
Poll progress with bounded backoff (for example 1, 2, 4 seconds, then at most 5 seconds
with jitter). Observe with `getTransactionEvidence` when a fresh proof is not needed;
do not run a permanent fetch loop to chase every accepted tip. `not_found` is a peer
report, never proof of absence. `observation_changed` permits a bounded local retry;
repeated storage/malformed-row errors require diagnosis rather than a tight retry loop.
This is scheduling guidance, not a network performance guarantee or runtime timer.
Stopping caller polling does not remove already queued runtime work or cancel peer
retries; the shared legacy scheduler has no per-caller cancellation API here.

Metadata uses `TX_PROOF_V1:` plus transaction hash and an exact 81-byte version-1
payload. Unknown versions/lengths are unusable evidence, not automatic migrations.
No existing data is backfilled or upgraded without a successfully checked proof.
Each transaction batch is atomic; a multi-transaction response is not one batch.
The Rust state enum is non-exhaustive to permit future observation states. JSON/JS
clients should fail closed on unknown states. Evidence names are not finality labels.

Receipt integrity is a local-storage assumption. Format, transaction/header hashes
and heights are checked, but the receipt has no checksum or authentication tag.
These checks do not detect every validly encoded metadata alteration. In particular,
other-anchor metadata is a trusted historical record, not an independently
authenticated historical proof. No state certifies a hostile local database.

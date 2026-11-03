# Watched coverage, positional evidence and restart

A filter match is an expectation, not block membership. At position `i` of a
validated filter page beginning at `start`, retain `(start + i, supplied_hash)`.
The existing filter hash-chain/checkpoint checks authenticate the filter data;
they do not authenticate the accompanying block hash. A subsequent header proof
must establish **both** the saved hash and saved height under a still-current
accepted-chain anchor. The containing body's roots must match that header.

Pending coverage lives in the existing `MATCHED_FILTER_BLOCKS_KEY` record. It
contains the interval, accepted anchor, script-registration revision, ordered
height/hash expectations and an indexed flag per expectation. There is no second
hash-to-height cache that can independently certify completion. Positions are
unique and ordered; hashes are unique. Body/proof response order may differ.

| Stage | Required evidence | Durable effect |
| --- | --- | --- |
| Filter page | Continuous start, checked filter hash chain, valid GCS data and distinct supplied hashes | Pending expectations and filter progress commit atomically |
| Header proof | Existing request identity, PoW/extra-hash/MMR checks, exact saved height/hash | Current membership may be installed; an inconsistent expectation enters refiltering |
| Body indexing | Exact complete body set, current membership, matching roots and recovered creator ordinals | Derived rows, membership and each indexed flag commit together |
| Range completion | Earliest interval, unchanged scope, every expectation indexed and still a member at its saved height | Cursor, pending removal, revision and write-fence removal commit atomically |

An authentic GCS false positive still requires proof/body verification and an
indexed flag, even when no watched transaction row is added. Interval bounds or
equality of unordered hash sets cannot replace these checks.

The active in-memory batch is a disposable cache. If a validated no-match page
leaves the durable pending set empty, discard an old cache left by a lost
completion acknowledgment and advance the verified cursor. Actual persisted
ranges still prevent that advancement.
Idle indexing and filter recovery also reload the earliest durable batch when
cache identities differ. Startup republishes verified no-match progress if its
page commit preceded the cursor update; neither a new block nor another reply
is required to discharge that already verified obligation.

Watched cells, capacity and history queries fail while any pending coverage or
repair fence remains. Query observations include the accepted state and index
revision and are checked again before returning results. Header/transaction
availability alone does not establish complete watched coverage.

## Older or inconsistent pending ranges

An unproved match reported missing by every currently eligible proved peer
also needs a positional recheck: a nonexistent supplied hash cannot produce a
wrong-height proof. The normal filter retry tick uses existing session/anchor
miss hints and its 15-second ask interval to start the same durable recheck.
A single miss cannot trigger this while another eligible peer can serve it;
no available peer is not evidence against the match. Hints expire after the
existing message timeout. A miss never completes coverage or invalidates
canonical membership. Honest refilter/proof/body recovery is required before
the saved obligation and query fence can disappear.

Legacy hash/proved records cannot establish a position. Save their coverage
goals in the existing repair journal before rewinding filter and script cursors.
Keep the unfinished interval until a validated filter page atomically replaces
it. A bounded page retains an ambiguous tail; an existing overlapping tail is
merged without shortening its saved end. Pages stop at existing range boundaries
and can recheck later ranges without overwriting or stalling on them.

The saved goal includes previously downloaded filter progress and script
cursors, not merely the first rechecked page. Replayed creators may temporarily
exist in derived rows, but watched queries remain fenced until the saved goal
and every pending interval have completed. Historical transactions, headers,
scripts and user keys remain intact.

If an ambiguous range has an interrupted `[1]` index write, its already written
derived rows cannot be certified by a header reproof. Resume the existing paged
derived-index repair in place. A new positioned `[1]` range retains direct,
idempotent range replay. Neither path unconditionally clears uncertainty.

## Accepted chain changes

Before acceptance intent is durable, preparatory writes only preserve or enlarge
the old chain's repair goals. Targets shortened for a replacement candidate commit
in the same atomic batch as its acceptance intent and transition fence. A failed
batch therefore retains the old goals; a committed batch gives restart both the
new goals and the candidate needed to replay them. Accepted state publication and
intent/fence removal remain atomic. Existing independent repair goals are not
shortened by this transition.

The accepted rollback journal saves replacement state and coverage goals before
discarding overlapping bindings. Refilter the valid prefix of a range crossing
the fork; membership invalidation begins after the actual fork. A detached proof
cannot fill a new range at the same height. A newly created fork-repair target
does not require nonexistent heights above a shorter replacement tip; independent
pre-existing repair goals remain preserved.

## Format and compatibility

The first eight range bytes remain the little-endian interval count. Positioned
records use a framed, versioned payload whose length is disjoint from the legacy
`count + N * (hash, bool)` layout, including a legacy hash beginning with the new
magic bytes. Rollback and saved-goal readers retain the same count prefix.

`INDEX_RECOVERY_V2 = [2]` identifies readiness under the positional coverage
policy. Older association-only or `[1]` recovery readiness receives an in-place
derived rescan before readiness is restored; existing rows alone cannot prove
that no watched row is missing. The IndexedDB object-store schema and primary
record encodings are unchanged. Downgrading a database with new pending records
to an older binary is unsupported.

`StorageBackend` gains no further required methods. Its snapshot reads and
checked scans from PR #304 are required by these consumers; unsupported defaults
fail explicitly. The existing fallible reader and callback-compatible `Option`
adapter remain. The default positioned-range writer is for trusted local callers
after filter validation, like the other high-level storage writers; it is not a
wire-proof verifier. Acceptance, registration and watched writes use the existing
single-writer discipline and shared matched-block lock, not a general KV compare
and swap for arbitrary external concurrent writers.

The filter hash checkpoint/peer agreement trust model and wire formats are
unchanged. A private request owner does not supply wire freshness: exactly
matching delayed replies remain indistinguishable without an echoed nonce.

# Snapshot reads and checked scans

`StorageBackend` provides two optional, fallible operations in addition to its
existing methods. This is a backend prerequisite; it does not change transaction
membership, watched indexing, database format or existing query consumers.

- `get_many(&[Vec<u8>])` returns exactly one entry per input key, in input order,
  from one database snapshot. Duplicate keys retain their positions; a missing
  key is `None`, an empty value is `Some(vec![])`, and a read failure is `Err`.
- `try_collect_iterator(...)` scans one snapshot, retaining the existing callback
  types. It returns `Err` on a backend, cursor or decoding failure rather than a
  successful partial page. `From` is inclusive; `After` is exclusive even when
  the boundary key no longer exists. A zero limit returns no rows. Limits count
  mapped rows, so intentionally excluded rows do not consume the limit.

The snapshot covers keys/values supplied by the operation. It does not combine
separate method calls into one transaction, and it does not promise that reads
inside a filter callback share that snapshot. A caller needing consistency across
those reads must separately validate its observation. `take_while` must not call
back into storage; `filter_map` may read storage. Callback failures cannot be
represented by `Option`; callers must propagate them separately or use a future
fallible callback interface.

RocksDB uses one snapshot for multi-key reads and constructs checked raw iterators
through that snapshot. The released `ckb-rocksdb` 0.21.2 safe `status()` API
distinguishes normal exhaustion from storage failure. Invalidity is checked after
seek and after every required advance, including after a valid prefix. A failed
scan returns `Err`, discarding accumulated rows. A completed limit or take-while
boundary does not require reading beyond the requested page. Snapshot and iterator
lifetimes are enforced by the upstream borrowing API; no local FFI, raw handles,
manual buffer management or unsafe adapter is needed.

SQLite uses one read transaction for `get_many`. Checked scans select rows from
one SQL statement and materialize the matching prefix before running filter
callbacks, allowing those callbacks to read the non-reentrant connection. As with
the old collector, a large prefix can require substantial memory; the returned
row limit does not bound that materialization. Row decoding errors are propagated,
including errors encountered while materializing the selected prefix.

IndexedDB uses the existing multi-key `Read` command in one read-only transaction.
Checked scans use the appended `CheckedIterator` command and existing callbacks
and response types. The rebuilt legacy collector explicitly uses `LegacyIterator`
to retain its historical prefix on cursor-advance failure if the transaction
commits. `IteratorKey` retains that behavior too. Such a prefix is not a
completeness guarantee. Checked scans discard it and return an error. The original
`Iterator` command remains strict: older #304/#302 clients also used that tag for
checked scans, so changing its meaning would silently weaken them. Open,
key/value decoding and transaction failures remain errors; an aborted transaction
never returns a partial page in either mode. Intentional limits and take-while
boundaries finish the requested page without advancing further.

All collectors use inclusive `From` and strict key-exclusive `After` in either
direction, including empty and absent boundary keys. Legacy RocksDB and SQLite
collectors now omit only an equal key, fixing lost rows when a pagination key was
deleted. Existing-key pagination is unchanged. No persisted cursor format changes.

Deploy rebuilt client/common/worker packages together. Existing command variant
numbers and response types are unchanged; the two explicit modes are appended. The
worker's previously ignored OpenDatabaseResponse payload now advertises byte 2.
Older workers return boolean true, byte 1; the new client rejects checked scans
locally for that capability, without sending an unknown command or falling back
to legacy iteration. Its legacy calls retain the existing `Iterator` path with an
old worker. Existing clients ignore the payload and keep using their original
commands; older checked clients therefore remain strict with a newer worker.
An older pre-#304 legacy client also uses that ambiguous tag and cannot opt into
partial rows on the new worker: rebuild both packages to restore that compatibility
path. A missing/invalid capability fails closed for checked calls.

## Upstream RocksDB status API

[ckb-rocksdb#6](https://github.com/nervosnetwork/ckb-rocksdb/pull/6) added safe
`DBRawIterator::status()` and `DBIterator::status()` methods. Upstream develop's
dependency update (#306) adopts released wrapper 0.21.2 and compatible ckb-db
1.1.2. Its lockfile retains native sys 8.5.4, so replacing the private adapter
does not change the native RocksDB engine. No git override is required.

## External backends

Both methods have explicit unsupported defaults, so a backend implementing only
the previous trait methods can still compile and its old methods keep working.
No production consumer switches to the new operations in this prerequisite.
There is no physical or application database migration in this change.

A third-party backend must implement the new contracts before a later consumer
can rely on them. Do not implement `get_many` as a loop of independently observed
`get` calls, and do not wrap an old collector that may swallow errors in `Ok`.
Unsupported operations should remain errors. Adding default trait methods is not
a binary ABI promise and can require disambiguation if a caller imports another
trait with identically named methods.

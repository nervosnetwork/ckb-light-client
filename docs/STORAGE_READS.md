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

RocksDB uses one snapshot for multi-key reads. Checked iteration uses the pinned
crate's public handles and exported RocksDB C API to distinguish normal exhaustion
from an iterator error, which its Rust iterator does not expose. The private
adapter owns its C iterator, borrows the snapshot, copies row buffers before
advancing, and frees the iterator/error buffers through the matching library API.
It does not inspect private Rust struct layouts or add a dependency.

SQLite uses one read transaction for `get_many`. Checked scans select rows from
one SQL statement and materialize the matching prefix before running filter
callbacks, allowing those callbacks to read the non-reentrant connection. As with
the old collector, a large prefix can require substantial memory; the returned
row limit does not bound that materialization. Row decoding errors are propagated,
including errors encountered while materializing the selected prefix.

IndexedDB uses the existing multi-key `Read` command in one read-only transaction.
The checked scan uses the existing iterator command and worker callbacks. The
worker now propagates cursor/open/decode/transaction errors, handles empty ranges
and zero limits, and applies exclusive bounds through IndexedDB's key range.
Because the old browser collector shares this worker command, it receives these
scan edge-case corrections too; its existing infallible signature still panics
when the worker reports an error. Existing native collectors are unchanged.
Deploy the rebuilt worker with the rebuilt client library: retaining the command
format does not give an old worker the corrected error-handling guarantees.

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

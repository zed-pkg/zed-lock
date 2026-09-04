> **Retired — folded into [`zed-pkg/zed-lib-core`](https://github.com/zed-pkg/zed-lib-core) (2026-09-04).**
> The crate lives on as the `src/rust-lock` slice there, same name, same
> public API, published under the `lock/v{version}` tag namespace. Depend on
> `zed-lock = { git = "https://github.com/zed-pkg/zed-lib-core.git", tag = "lock/v0.1.1" }`
> (or the zed package `zed-pkg/zed-lock`, now a nested target of
> `zed-pkg/zed-lib-core`). This repository is archived; its tags remain valid
> for the versions they named, and its full history is a parent of the
> fold merge commit in zed-lib-core (`MERGE_PROVENANCE.md`, "Third lineage").
> Distributed lease + Postgres advisory composition is not here and never
> was: see [`ORESoftware/ores-locks-and-leases`](https://github.com/ORESoftware/ores-locks-and-leases).

# zed-lock

`zed-lock` is the local locking core for recursive zed-pkg mutations and shared
artifact publication. It keeps descriptor-backed operating-system locking as
the sole local ownership authority while exposing synchronous, timeout, and
runtime-neutral future APIs.

## Design

- Linux and macOS use the blocking descriptor lock provided through `fs2`.
  A contending waiter sleeps in the kernel until the owner releases the
  descriptor or exits.
- Windows uses the corresponding `LockFileEx` implementation through `fs2`.
- Async callers get one bounded dedicated waiter thread and a completion
  `Future`; there is no `try_lock` plus sleep/backoff polling loop.
- Lock files are stable rendezvous points. Their contents are diagnostics only
  and must never be interpreted as ownership.
- The default same-process policy rejects accidental reentrant acquisition.
  Intentional independent tasks may opt into kernel queuing.
- Multi-lock transactions are canonicalized, deduplicated, sorted by lock
  class and path, and released in reverse order.
- Lock rendezvous paths default to a private, fail-closed policy: Unix
  directories are `0700`, lock files are `0600`, the final path component is
  opened with `O_NOFOLLOW`, and foreign ownership or group/other-writable
  parents are rejected. Windows opens the final component without following
  reparse points/junctions, uses non-inheritable handles, and applies a
  user-private DACL. Shared-directory mode is opt-in via
  `PathSecurityPolicy::Shared` / `LockRequest::shared_path()` and still
  refuses symlink and reparse substitution.
- Fiducia is not part of the local path. It remains an optional outer lease and
  fencing layer for genuinely multi-host shared state.

## Example

```rust
use std::time::Duration;

use anyhow::{Context, Result};
use zed_lock::{LockClass, LockManager, LockRequest};

fn mutate() -> Result<()> {
    let request = LockRequest::exclusive(".zed/locks/install.lock")
        .operation("recursive install")
        .class(LockClass::ProjectMutation);

    let guard = LockManager::global()
        .acquire_timeout(request, Duration::from_secs(120))
        .context("waiting for recursive install ownership")?;

    // Revalidate the mutation plan, then commit protected state.
    drop(guard);
    Ok(())
}
```

For an async runtime, `LockManager::acquire` returns a standard-library
`Future<Output = anyhow::Result<LockGuard>>`. The runtime may await it directly
without requiring Tokio inside this crate.

## Timeout and cancellation

On Unix there is no portable cancellation operation for a thread already
blocked inside `flock`. Dropping or timing out a pending waiter therefore
cancels delivery, not the syscall. If the detached waiter later acquires the
lock, failed delivery immediately drops the guard. The manager limits the
number of such waiter threads to provide backpressure.

## Formal verification

The bounded Quint model in [`formal/waiter_lifecycle.qnt`](formal/waiter_lifecycle.qnt)
checks exclusive ownership, detached grant-and-release, unique timeout versus
cancellation outcomes, waiter-cap enforcement, same-process rejection,
ownership transfer, and reverse partial lock-set unwind. Its schema-v1
[`formal/fm.toml`](formal/fm.toml) manifest runs 10,000 simulated traces and
exhaustive TLC verification in CI.

Concrete JSON Schema 2020-12 cases under [`protocol/`](protocol/) replay the
model's publish-versus-release decision through production Rust code. See
[`formal/README.md`](formal/README.md) for the exact finite proof boundary and
the properties intentionally left to real cross-platform process tests.

## Source provenance

This standalone repository was initially extracted from
`zed-pkg/zed-cli@fd3b08eb1ac170518cb795e662318ae2714b1176`. Subsequent changes are
reviewed and tested here directly.

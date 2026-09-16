# Changelog

## Unreleased

## 0.1.2 — 2026-09-15

Release the hardened current locking implementation as a valid Zed source package.

- Keep the whole-repository Rust target free of a target-level native registry route; crates.io remains an independent native release surface.
- Carry the fail-closed path-security hardening for Unix and Windows lock files and rendezvous directories.
- Carry the bounded formal-model/replay coverage for waiter cancellation, timeout, ownership transfer, waiter caps, and ordered lock-set unwind.
- Preserve the single-terminal-reason timeout behavior and reverse-order cleanup of partial lock sets.
- Preserve Windows nonblocking contention parity for `ERROR_LOCK_VIOLATION`.
- Publish this patch version so `^0.1.1` Zed consumers can resolve a modern, valid package without rewriting the immutable `v0.1.1` tag.

## 0.1.1 — 2026-08-05

Repository and release-contract hardening for the standalone locking crate.

- Declare Rust 1.88 as the actual minimum supported compiler for the extracted
  let-chain implementation.
- Correct the Zed native registry identifier to `crates-io`.
- Remove the empty `.zpkg.lock` placeholder; the package currently has no Zed
  dependencies.
- Add fail-closed Cargo/Zed metadata, extraction-provenance, descriptor-lock,
  and production no-polling checks.
- Add negative package-contract tests.
- Run formatting, tests, strict Clippy, and process conformance on Ubuntu 24.04,
  macOS 15, and Windows Server 2025.
- Package a distinct `zed-lock-0.1.1.crate` and SHA-256 review artifact only
  after the complete platform matrix succeeds.
- Remove automatic release creation from ordinary default-branch pushes.

The locking API and extracted runtime implementation remain compatible with
0.1.0. Consumers should pin the immutable 0.1.1 merge/release commit rather
than retargeting the existing 0.1.0 tag.

## 0.1.0 — 2026-08-05

Initial standalone extraction of the kernel-backed, event-driven locking crate
from `zed-pkg/zed-cli` source commit
`fd3b08eb1ac170518cb795e662318ae2714b1176`.

The GitHub release targets commit
`0fc100afc3cd60b5ce091b4207f910bf08f2cfb7` and includes the original crate and
checksum assets.

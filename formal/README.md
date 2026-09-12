# Formal waiter and ownership lifecycle

This directory defines an executable safety model for the concurrency boundary
that is hardest to exercise deterministically in `zed-lock`: a caller can stop
waiting while its native descriptor-lock request remains blocked in the kernel.
The later grant must be released without ever becoming an observable guard.

`formal/fm.toml` uses the shared schema-v1 `fmctl` contract and pins Quint
0.32.0. `formal/waiter_lifecycle.qnt` models three immutable waiter identities,
at most two active native workers, one canonical descriptor-lock identity, and
a two-lock ordered transaction. The operating system's grant is deliberately
nondeterministic.

GitHub Actions builds `fmctl` from reviewed `opto-sync/opto-sync-clients`
revision `c2146ef9f054d24e1488c216547852aa148285cf`. The workflow cross-checks the
repository manifest's exact Rust version against that pinned fmctl checkout's
`rust-toolchain.toml`, installs only the matching patch release, verifies the
active compiler, validates the manifest, records `fmctl doctor` evidence, and
then runs the configured check/simulation/verification pipeline. The resulting
JSON and model inputs are retained as workflow artifacts.

## Safety properties

The composed `waiter_lifecycle_safety` invariant checks that:

1. at most one pending or published result owns the descriptor lock;
2. cancelled and timed-out receivers never receive a later guard;
3. a detached native grant is released immediately;
4. the active waiter count never exceeds the configured finite cap;
5. timeout and cancellation are disjoint terminal reasons; and
6. a partial ordered lock-set acquisition releases the lower lock before
   returning its error, while completed sets release in reverse order.

Simulation must reach cancellation before grant, timeout before grant, detached
grant-and-release, successful ownership transfer, waiter-cap rejection,
same-process rejection, and partial lock-set unwind. These witnesses prevent a
green invariant caused by disabling the fault or contention paths.

The first 10,000-trace run reached all seven witnesses. Exhaustive TLC explored
the complete declared graph: 123,505 generated states, 15,635 distinct states,
depth 18, zero states left on the queue, and zero invariant violations.

## Implementation refinement and findings

`protocol/formal-waiter-lifecycle.schema.json` defines the JSON Schema 2020-12
contract for concrete refinement cases. The adjacent corpus covers the worker's
publish-versus-release decision, unique timeout/cancellation events, and
reverse-order partial unwind. Rust tests replay it through the production-owned
`settle_waiter_completion` decision.

Building the model exposed two implementation gaps that ordinary success-path
tests did not state precisely:

- `acquire_timeout` emitted both `TimedOut` and the generic `Cancelled` callback
  for one deadline outcome. It now suppresses the cancellation callback after
  recording the timeout, while still abandoning delivery safely.
- a failure during `acquire_many_blocking` relied on implicit `Vec` destruction
  for already acquired guards. It now performs the API's promised reverse-order
  unwind explicitly before returning the acquisition error.

Focused Rust regressions cover both behaviors. Existing process conformance
continues to exercise the real OS descriptor locks.

## Run locally

With a schema-v1-compatible `fmctl`, Node.js 22, Java 17 or newer, and Rust
1.88 or newer:

```sh
fmctl validate
fmctl doctor
fmctl check
fmctl simulate
fmctl verify

npx --yes ajv-cli@5.0.0 validate --spec=draft2020 \
  -s protocol/formal-waiter-lifecycle.schema.json \
  -d protocol/formal-waiter-lifecycle.json

cargo test --all-targets
```

## Proof boundary

The exhaustive claim applies only to the declared finite abstraction: three
waiter identities, two active worker permits, one local lock identity, and one
two-lock ordered transaction. The model does not prove kernel FIFO fairness,
eventual grant, portable cancellation of a blocked Unix syscall, filesystem or
network-filesystem durability, crash behavior outside descriptor-close
semantics, or arbitrary numbers of waiters and lock identities. It treats lock
diagnostic contents as non-authoritative and makes no distributed/Fiducia
claim. Cross-platform process tests remain the evidence for the real OS layer.

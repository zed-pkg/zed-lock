use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use zed_lock::{LockClass, LockEvent, LockEventKind, LockManager, LockRequest, LockWaiter};

fn event_log() -> (Arc<Mutex<Vec<LockEvent>>>, impl Fn(&LockEvent) + Send + Sync + 'static) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink_events = Arc::clone(&events);
    let sink = move |event: &LockEvent| {
        sink_events.lock().unwrap().push(event.clone());
    };
    (events, sink)
}

fn events_for(events: &Arc<Mutex<Vec<LockEvent>>>, operation: &str) -> Vec<LockEvent> {
    events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.operation == operation)
        .cloned()
        .collect()
}

fn wait_for_no_waiters(manager: &LockManager) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while manager.active_waiters() != 0 && Instant::now() < deadline {
        thread::yield_now();
    }
    assert_eq!(manager.active_waiters(), 0, "waiter permit leaked");
}

#[test]
fn task01_successful_try_acquire_emits_acquired_without_waiting() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (events, sink) = event_log();
    let manager = LockManager::builder().event_sink(sink).build();
    let guard = manager
        .try_acquire(LockRequest::exclusive(temp.path().join("one.lock")).operation("task01"))?
        .expect("uncontended try_acquire must win");
    let observed = events_for(&events, "task01");
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].kind, LockEventKind::Acquired);
    drop(guard);
    Ok(())
}

#[test]
fn task02_contended_try_acquire_emits_only_contended_for_loser() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("two.lock");
    let (events, sink) = event_log();
    let manager = LockManager::builder().event_sink(sink).build();
    let owner = manager.acquire_blocking(
        LockRequest::exclusive(&path)
            .operation("task02-owner")
            .queue_same_process(),
    )?;
    let loser = manager.try_acquire(
        LockRequest::exclusive(&path)
            .operation("task02-loser")
            .queue_same_process(),
    )?;
    assert!(loser.is_none());
    let kinds = events_for(&events, "task02-loser")
        .into_iter()
        .map(|event| event.kind)
        .collect::<Vec<_>>();
    assert_eq!(kinds, vec![LockEventKind::Contended]);
    drop(owner);
    Ok(())
}

#[test]
fn task03_try_acquire_never_consumes_waiter_budget() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("three.lock");
    let manager = LockManager::builder().max_waiters(1).build();
    let owner = manager
        .try_acquire(LockRequest::exclusive(&path).operation("task03-owner"))?
        .expect("initial try_acquire wins");
    assert_eq!(manager.active_waiters(), 0);
    let contender = manager.try_acquire(
        LockRequest::exclusive(&path)
            .operation("task03-contender")
            .queue_same_process(),
    )?;
    assert!(contender.is_none());
    assert_eq!(manager.active_waiters(), 0);
    drop(owner);
    Ok(())
}

#[test]
fn task04_zero_waiter_capacity_clamps_to_one() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("four.lock");
    let manager = LockManager::builder().max_waiters(0).build();
    assert_eq!(manager.max_waiters(), 1);
    let owner = manager.acquire_blocking(
        LockRequest::exclusive(&path)
            .operation("task04-owner")
            .queue_same_process(),
    )?;
    let waiter = manager.acquire(
        LockRequest::exclusive(&path)
            .operation("task04-first")
            .queue_same_process(),
    )?;
    assert_eq!(manager.active_waiters(), 1);
    let error = match manager.acquire(
        LockRequest::exclusive(temp.path().join("four-other.lock")).operation("task04-over-cap"),
    ) {
        Ok(_) => panic!("second background waiter must be rejected"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("waiter limit reached"));
    drop(waiter);
    drop(owner);
    wait_for_no_waiters(&manager);
    Ok(())
}

#[test]
fn task05_waiter_panic_becomes_structured_error() -> Result<()> {
    let waiter = LockWaiter::<u8>::spawn("task05-panic", || -> Result<u8> {
        panic!("synthetic acquisition panic");
    })?;
    let error = waiter.wait().expect_err("panic must be converted to Err");
    let text = format!("{error:#}");
    assert!(text.contains("background lock waiter"));
    assert!(text.contains("synthetic acquisition panic"));
    Ok(())
}

#[test]
fn task06_completed_waiter_rejects_second_observation() -> Result<()> {
    let mut waiter = LockWaiter::spawn("task06-completed", || Ok(6_u8))?;
    assert_eq!(waiter.wait_timeout(Duration::from_secs(1))?, Some(6));
    let error = waiter
        .wait_timeout(Duration::ZERO)
        .expect_err("completed waiter must reject a second observation");
    assert!(format!("{error:#}").contains("already completed"));
    Ok(())
}

#[test]
fn task07_zero_duration_retries_keep_one_worker() -> Result<()> {
    let attempts = Arc::new(AtomicUsize::new(0));
    let worker_attempts = Arc::clone(&attempts);
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let mut waiter = LockWaiter::spawn("task07-zero", move || {
        worker_attempts.fetch_add(1, Ordering::SeqCst);
        started_tx.send(()).map_err(|_| anyhow!("start receiver closed"))?;
        release_rx.recv().map_err(|_| anyhow!("release sender closed"))?;
        Ok(7_u8)
    })?;
    started_rx.recv_timeout(Duration::from_secs(1))?;
    for _ in 0..8 {
        assert_eq!(waiter.wait_timeout(Duration::ZERO)?, None);
    }
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    release_tx.send(())?;
    assert_eq!(waiter.wait_timeout(Duration::from_secs(1))?, Some(7));
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn task08_zero_acquire_timeout_has_one_terminal_reason_and_no_leak() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("eight.lock");
    let (events, sink) = event_log();
    let manager = LockManager::builder().event_sink(sink).build();
    let owner = manager.acquire_blocking(
        LockRequest::exclusive(&path)
            .operation("task08-owner")
            .queue_same_process(),
    )?;
    let error = manager
        .acquire_timeout(
            LockRequest::exclusive(&path)
                .operation("task08-timeout")
                .queue_same_process(),
            Duration::ZERO,
        )
        .expect_err("zero deadline must time out while contended");
    assert!(format!("{error:#}").contains("timed out"));
    let observed = events_for(&events, "task08-timeout");
    assert_eq!(
        observed
            .iter()
            .filter(|event| event.kind == LockEventKind::TimedOut)
            .count(),
        1
    );
    assert!(!observed.iter().any(|event| event.kind == LockEventKind::Cancelled));
    drop(owner);
    wait_for_no_waiters(&manager);
    let guard = manager
        .try_acquire(LockRequest::exclusive(&path).operation("task08-reuse"))?
        .expect("timed-out request must not leak ownership");
    drop(guard);
    Ok(())
}

#[test]
fn task09_explicit_release_emits_exactly_one_release() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (events, sink) = event_log();
    let manager = LockManager::builder().event_sink(sink).build();
    let guard = manager.acquire_blocking(
        LockRequest::exclusive(temp.path().join("nine.lock")).operation("task09"),
    )?;
    guard.release()?;
    let observed = events_for(&events, "task09");
    assert_eq!(
        observed
            .iter()
            .filter(|event| event.kind == LockEventKind::Released)
            .count(),
        1
    );
    Ok(())
}

#[test]
fn task10_drop_release_preserves_owner_identity() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (events, sink) = event_log();
    let manager = LockManager::builder().event_sink(sink).build();
    let guard = manager.acquire_blocking(
        LockRequest::exclusive(temp.path().join("ten.lock")).operation("task10"),
    )?;
    drop(guard);
    let observed = events_for(&events, "task10");
    let acquired = observed
        .iter()
        .find(|event| event.kind == LockEventKind::Acquired)
        .and_then(|event| event.owner.as_ref())
        .expect("acquired owner");
    let released = observed
        .iter()
        .find(|event| event.kind == LockEventKind::Released)
        .and_then(|event| event.owner.as_ref())
        .expect("released owner");
    assert_eq!(acquired.pid, released.pid);
    assert_eq!(acquired.operation, released.operation);
    assert_eq!(released.operation, "task10");
    assert_eq!(
        observed
            .iter()
            .filter(|event| event.kind == LockEventKind::Released)
            .count(),
        1
    );
    Ok(())
}

#[test]
fn task11_same_process_rejection_does_not_poison_reservation() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("eleven.lock");
    let manager = LockManager::default();
    let owner = manager.acquire_blocking(
        LockRequest::exclusive(&path).operation("task11-owner"),
    )?;
    let error = match manager.try_acquire(
        LockRequest::exclusive(&path).operation("task11-rejected"),
    ) {
        Ok(_) => panic!("same-process reentry must reject"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("same process already owns"));
    drop(owner);
    let guard = manager
        .try_acquire(LockRequest::exclusive(&path).operation("task11-reuse"))?
        .expect("reservation must clear after owner drop");
    drop(guard);
    Ok(())
}

#[test]
fn task12_queued_try_contention_then_reuse_succeeds() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("twelve.lock");
    let manager = LockManager::default();
    let owner = manager.acquire_blocking(
        LockRequest::exclusive(&path)
            .operation("task12-owner")
            .queue_same_process(),
    )?;
    assert!(
        manager
            .try_acquire(
                LockRequest::exclusive(&path)
                    .operation("task12-contender")
                    .queue_same_process(),
            )?
            .is_none()
    );
    drop(owner);
    let guard = manager
        .try_acquire(
            LockRequest::exclusive(&path)
                .operation("task12-reuse")
                .queue_same_process(),
        )?
        .expect("same rendezvous must become reusable after release");
    drop(guard);
    Ok(())
}

#[test]
fn task13_duplicate_lockset_fails_before_ownership_and_leaves_reusable() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("thirteen.lock");
    let (events, sink) = event_log();
    let manager = LockManager::builder().event_sink(sink).build();
    let error = match manager.acquire_many_blocking([
        LockRequest::exclusive(&path).operation("task13-a"),
        LockRequest::exclusive(&path).operation("task13-b"),
    ]) {
        Ok(_) => panic!("duplicate canonical identity must fail"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("duplicate canonical lock identity"));
    assert!(
        events
            .lock()
            .unwrap()
            .iter()
            .all(|event| event.kind != LockEventKind::Acquired),
        "duplicate preflight unexpectedly acquired a lock"
    );
    let guard = manager
        .try_acquire(LockRequest::exclusive(&path).operation("task13-reuse"))?
        .expect("duplicate preflight must not retain ownership");
    drop(guard);
    Ok(())
}

#[test]
fn task14_partial_lockset_failure_unwinds_prior_guard() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let first = temp.path().join("a-first.lock");
    let blocked = temp.path().join("z-blocked.lock");
    let manager = LockManager::default();
    let owner_manager = manager.clone();
    let blocked_for_owner = blocked.clone();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let owner = thread::spawn(move || -> Result<()> {
        let guard = owner_manager.acquire_blocking(
            LockRequest::exclusive(&blocked_for_owner)
                .operation("task14-owner")
                .class(LockClass::Build),
        )?;
        ready_tx.send(()).map_err(|_| anyhow!("ready receiver closed"))?;
        release_rx.recv().map_err(|_| anyhow!("release sender closed"))?;
        drop(guard);
        Ok(())
    });
    ready_rx.recv_timeout(Duration::from_secs(2))?;

    let error = match manager.acquire_many_blocking([
        LockRequest::exclusive(&first)
            .operation("task14-first")
            .class(LockClass::ProjectMutation),
        LockRequest::exclusive(&blocked)
            .operation("task14-blocked")
            .class(LockClass::Build),
    ]) {
        Ok(_) => panic!("second reservation must fail while held by this manager"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("same process already owns"));
    let first_guard = manager
        .try_acquire(
            LockRequest::exclusive(&first)
                .operation("task14-reuse-first")
                .class(LockClass::ProjectMutation),
        )?
        .expect("first guard must have been unwound after later failure");
    drop(first_guard);
    release_tx.send(())?;
    owner.join().map_err(|_| anyhow!("owner thread panicked"))??;
    Ok(())
}

#[test]
fn task15_lockset_explicit_release_is_reverse_acquisition_order() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (events, sink) = event_log();
    let manager = LockManager::builder().event_sink(sink).build();
    let set = manager.acquire_many_blocking([
        LockRequest::exclusive(temp.path().join("c.lock"))
            .operation("task15-c")
            .class(LockClass::Build),
        LockRequest::exclusive(temp.path().join("a.lock"))
            .operation("task15-a")
            .class(LockClass::ProjectMutation),
        LockRequest::exclusive(temp.path().join("b.lock"))
            .operation("task15-b")
            .class(LockClass::Artifact),
    ])?;
    let acquired = events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.kind == LockEventKind::Acquired)
        .map(|event| event.path.clone())
        .collect::<Vec<_>>();
    assert_eq!(acquired.len(), 3);
    set.release()?;
    let released = events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.kind == LockEventKind::Released)
        .map(|event| event.path.clone())
        .collect::<Vec<_>>();
    let expected = acquired.into_iter().rev().collect::<Vec<_>>();
    assert_eq!(released, expected);
    Ok(())
}

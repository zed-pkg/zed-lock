//! Kernel-backed local locking with event-driven completion.
//!
//! `zed-lock` deliberately keeps one authority for local ownership: the
//! operating system's descriptor lock. A blocking acquisition may run on a
//! dedicated, bounded waiter thread, while completion is relayed to the caller
//! through a runtime-neutral [`Future`] and condition variable. There is no
//! lock-file polling, filesystem-watcher protocol, PID-file ownership, or
//! network dependency in the local path.

use std::cell::RefCell;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as AnyhowContext, Result, anyhow, bail};
use fs2::FileExt;

const DEFAULT_MAX_WAITERS: usize = 128;

thread_local! {
    static HELD_LOCK_ORDER: RefCell<Vec<(u16, PathBuf)>> = const { RefCell::new(Vec::new()) };
}

fn check_lock_order(class: LockClass, identity: &Path, operation: &str) -> Result<()> {
    let candidate_rank = class.rank();
    let candidate_path = path_sort_key(identity);
    HELD_LOCK_ORDER.with(|held| {
        if let Some((held_rank, held_path)) = held.borrow().iter().max_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| path_sort_key(&left.1).cmp(&path_sort_key(&right.1)))
        }) {
            let held_path_key = path_sort_key(held_path);
            if (candidate_rank, &candidate_path) < (*held_rank, &held_path_key) {
                bail!(
                    "lock-order inversion while starting `{operation}`: requested class rank {candidate_rank} at {} while this thread already holds class rank {} at {}; acquire locks in ascending class/path order or use acquire_many_blocking",
                    identity.display(),
                    held_rank,
                    held_path.display()
                );
            }
        }
        Ok(())
    })
}

struct HeldOrderRegistration {
    rank: u16,
    path: PathBuf,
}

impl HeldOrderRegistration {
    fn register(class: LockClass, path: &Path) -> Self {
        let registration = Self {
            rank: class.rank(),
            path: path.to_path_buf(),
        };
        HELD_LOCK_ORDER.with(|held| {
            held.borrow_mut()
                .push((registration.rank, registration.path.clone()));
        });
        registration
    }
}

impl Drop for HeldOrderRegistration {
    fn drop(&mut self) {
        HELD_LOCK_ORDER.with(|held| {
            let mut held = held.borrow_mut();
            if let Some(index) = held
                .iter()
                .rposition(|(rank, path)| *rank == self.rank && path == &self.path)
            {
                held.remove(index);
            }
        });
    }
}

/// A deterministic lock hierarchy used when acquiring a set of locks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockClass {
    ProjectMutation,
    Refs,
    Artifact,
    Build,
    Custom(u16),
}

impl LockClass {
    fn rank(self) -> u16 {
        match self {
            Self::ProjectMutation => 10,
            Self::Refs => 20,
            Self::Artifact => 30,
            Self::Build => 40,
            Self::Custom(rank) => rank,
        }
    }
}

/// How a request behaves when the same process already owns or is waiting for
/// the same canonical lock identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameProcessPolicy {
    /// Fail before entering a kernel wait. This is the safe default and avoids
    /// accidental self-deadlock in synchronous code.
    Reject,
    /// Let the operating system queue the independent descriptor request.
    /// Use this only when separate tasks in one process intentionally contend.
    Queue,
}

/// Description of one exclusive local lock request.
#[derive(Debug, Clone)]
pub struct LockRequest {
    path: PathBuf,
    operation: String,
    class: LockClass,
    same_process_policy: SameProcessPolicy,
}

impl LockRequest {
    pub fn exclusive(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            operation: "exclusive lock".to_owned(),
            class: LockClass::Custom(100),
            same_process_policy: SameProcessPolicy::Reject,
        }
    }

    pub fn operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = operation.into();
        self
    }

    pub fn class(mut self, class: LockClass) -> Self {
        self.class = class;
        self
    }

    pub fn same_process_policy(mut self, policy: SameProcessPolicy) -> Self {
        self.same_process_policy = policy;
        self
    }

    pub fn queue_same_process(self) -> Self {
        self.same_process_policy(SameProcessPolicy::Queue)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn operation_name(&self) -> &str {
        &self.operation
    }

    pub fn lock_class(&self) -> LockClass {
        self.class
    }
}

/// Non-authoritative diagnostics describing the process that most recently
/// acquired a lock. Descriptor ownership, never this metadata, is authoritative.
#[derive(Debug, Clone)]
pub struct OwnerInfo {
    pub pid: u32,
    pub hostname: Option<String>,
    pub executable: Option<String>,
    pub thread: Option<String>,
    pub operation: String,
    pub acquired_at: SystemTime,
}

impl OwnerInfo {
    fn current(operation: &str) -> Self {
        let hostname = std::env::var("HOSTNAME")
            .ok()
            .or_else(|| std::env::var("COMPUTERNAME").ok());
        let executable = std::env::current_exe().ok().and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        });
        let thread = thread::current().name().map(str::to_owned);
        Self {
            pid: std::process::id(),
            hostname,
            executable,
            thread,
            operation: operation.to_owned(),
            acquired_at: SystemTime::now(),
        }
    }

    pub fn acquired_unix_millis(&self) -> u128 {
        self.acquired_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockEventKind {
    Waiting,
    Acquired,
    Contended,
    Released,
    TimedOut,
    Cancelled,
    Failed,
}

/// Structured lifecycle event. Callbacks must be fast and must not attempt to
/// acquire the same lock synchronously.
#[derive(Debug, Clone)]
pub struct LockEvent {
    pub kind: LockEventKind,
    pub path: PathBuf,
    pub operation: String,
    pub class: LockClass,
    pub elapsed: Option<Duration>,
    pub owner: Option<OwnerInfo>,
    pub detail: Option<String>,
}

type EventSink = Arc<dyn Fn(&LockEvent) + Send + Sync + 'static>;

#[derive(Clone)]
pub struct LockManager {
    inner: Arc<ManagerInner>,
}

struct ManagerInner {
    limiter: Arc<WaiterLimiter>,
    event_sink: EventSink,
    reserved_in_process: Mutex<HashSet<PathBuf>>,
}

pub struct LockManagerBuilder {
    max_waiters: usize,
    event_sink: EventSink,
}

impl Default for LockManagerBuilder {
    fn default() -> Self {
        Self {
            max_waiters: DEFAULT_MAX_WAITERS,
            event_sink: Arc::new(|_| {}),
        }
    }
}

impl LockManagerBuilder {
    pub fn max_waiters(mut self, max_waiters: usize) -> Self {
        self.max_waiters = max_waiters.max(1);
        self
    }

    pub fn event_sink<F>(mut self, sink: F) -> Self
    where
        F: Fn(&LockEvent) + Send + Sync + 'static,
    {
        self.event_sink = Arc::new(sink);
        self
    }

    pub fn build(self) -> LockManager {
        LockManager {
            inner: Arc::new(ManagerInner {
                limiter: Arc::new(WaiterLimiter::new(self.max_waiters)),
                event_sink: self.event_sink,
                reserved_in_process: Mutex::new(HashSet::new()),
            }),
        }
    }
}

impl Default for LockManager {
    fn default() -> Self {
        LockManagerBuilder::default().build()
    }
}

fn is_lock_contention(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }

    #[cfg(windows)]
    {
        // LockFileEx reports ordinary nonblocking contention through
        // ERROR_LOCK_VIOLATION (33), which Rust currently classifies as
        // `Other` rather than `WouldBlock`.
        error.raw_os_error() == Some(33)
    }

    #[cfg(not(windows))]
    {
        false
    }
}

impl LockManager {
    pub fn builder() -> LockManagerBuilder {
        LockManagerBuilder::default()
    }

    pub fn global() -> &'static Self {
        static GLOBAL: OnceLock<LockManager> = OnceLock::new();
        GLOBAL.get_or_init(Self::default)
    }

    /// Acquire directly on the calling thread. The operating system sleeps the
    /// caller under contention and wakes it when ownership can be granted.
    pub fn acquire_blocking(&self, request: LockRequest) -> Result<LockGuard> {
        let started = Instant::now();
        self.emit(
            &request,
            LockEventKind::Waiting,
            Some(Duration::ZERO),
            None,
            None,
        );

        let (mut file, identity) = match open_lock_file(&request.path) {
            Ok(opened) => opened,
            Err(error) => {
                self.emit(
                    &request,
                    LockEventKind::Failed,
                    Some(started.elapsed()),
                    None,
                    Some(error.to_string()),
                );
                return Err(error);
            }
        };

        if let Err(error) = check_lock_order(request.class, &identity, &request.operation) {
            self.emit(
                &request,
                LockEventKind::Failed,
                Some(started.elapsed()),
                None,
                Some(error.to_string()),
            );
            return Err(error);
        }

        let reserved = match self.reserve_if_required(&request, &identity) {
            Ok(reserved) => reserved,
            Err(error) => {
                self.emit(
                    &request,
                    LockEventKind::Failed,
                    Some(started.elapsed()),
                    None,
                    Some(error.to_string()),
                );
                return Err(error);
            }
        };

        if let Err(error) = FileExt::lock_exclusive(&file) {
            self.remove_reservation(reserved.as_ref());
            self.emit(
                &request,
                LockEventKind::Failed,
                Some(started.elapsed()),
                None,
                Some(error.to_string()),
            );
            return Err(error).with_context(|| {
                format!(
                    "waiting for `{}` through operating-system lock {}",
                    request.operation,
                    identity.display()
                )
            });
        }

        let order_registration = HeldOrderRegistration::register(request.class, &identity);
        let owner = OwnerInfo::current(&request.operation);
        let _ = write_owner_diagnostics(&mut file, &owner);
        self.emit(
            &request,
            LockEventKind::Acquired,
            Some(started.elapsed()),
            Some(owner.clone()),
            None,
        );

        Ok(LockGuard {
            file: Some(file),
            path: identity,
            operation: request.operation,
            class: request.class,
            owner,
            manager: Arc::clone(&self.inner),
            reservation: reserved,
            order_registration: Some(order_registration),
        })
    }

    /// Attempt acquisition without waiting. `Ok(None)` means another owner is
    /// currently authoritative.
    pub fn try_acquire(&self, request: LockRequest) -> Result<Option<LockGuard>> {
        let started = Instant::now();
        let (mut file, identity) = open_lock_file(&request.path)?;
        check_lock_order(request.class, &identity, &request.operation)?;
        let reserved = self.reserve_if_required(&request, &identity)?;

        match FileExt::try_lock_exclusive(&file) {
            Ok(()) => {
                let order_registration = HeldOrderRegistration::register(request.class, &identity);
                let owner = OwnerInfo::current(&request.operation);
                let _ = write_owner_diagnostics(&mut file, &owner);
                self.emit(
                    &request,
                    LockEventKind::Acquired,
                    Some(started.elapsed()),
                    Some(owner.clone()),
                    None,
                );
                Ok(Some(LockGuard {
                    file: Some(file),
                    path: identity,
                    operation: request.operation,
                    class: request.class,
                    owner,
                    manager: Arc::clone(&self.inner),
                    reservation: reserved,
                    order_registration: Some(order_registration),
                }))
            }
            Err(error) if is_lock_contention(&error) => {
                self.remove_reservation(reserved.as_ref());
                self.emit(
                    &request,
                    LockEventKind::Contended,
                    Some(started.elapsed()),
                    None,
                    None,
                );
                Ok(None)
            }
            Err(error) => {
                self.remove_reservation(reserved.as_ref());
                self.emit(
                    &request,
                    LockEventKind::Failed,
                    Some(started.elapsed()),
                    None,
                    Some(error.to_string()),
                );
                Err(error)
                    .with_context(|| format!("trying operating-system lock {}", identity.display()))
            }
        }
    }

    /// Start one bounded waiter thread and return a runtime-neutral future.
    pub fn acquire(&self, request: LockRequest) -> Result<LockWaiter<LockGuard>> {
        let permit = self
            .inner
            .limiter
            .reserve()
            .with_context(|| format!("starting waiter for `{}`", request.operation))?;
        let manager = self.clone();
        let cancel_manager = self.clone();
        let cancel_request = request.clone();
        let label = request.operation.clone();

        LockWaiter::spawn_with_cancel(
            label,
            move || {
                let _permit = permit;
                manager.acquire_blocking(request)
            },
            move || {
                cancel_manager.emit(
                    &cancel_request,
                    LockEventKind::Cancelled,
                    None,
                    None,
                    Some("caller dropped the pending waiter".to_owned()),
                );
            },
        )
    }

    /// Wait up to a deadline. On Unix, timeout detaches the still-kernel-blocked
    /// worker; if that request is later granted, failed delivery drops the guard
    /// immediately. No ownership can leak past the timeout.
    pub fn acquire_timeout(&self, request: LockRequest, timeout: Duration) -> Result<LockGuard> {
        let started = Instant::now();
        let mut waiter = self.acquire(request.clone())?;
        match waiter.wait_timeout(timeout)? {
            Some(guard) => Ok(guard),
            None => {
                self.emit(
                    &request,
                    LockEventKind::TimedOut,
                    Some(started.elapsed()),
                    None,
                    Some(format!("deadline of {timeout:?} elapsed")),
                );
                drop(waiter);
                bail!(
                    "timed out after {timeout:?} waiting for `{}` at {}",
                    request.operation,
                    request.path.display()
                );
            }
        }
    }

    /// Canonicalize, deduplicate, sort, and acquire a lock set in deterministic
    /// hierarchy order. Guards are released in reverse order.
    pub fn acquire_many_blocking<I>(&self, requests: I) -> Result<LockSetGuard>
    where
        I: IntoIterator<Item = LockRequest>,
    {
        let mut requests = requests.into_iter().collect::<Vec<_>>();
        for request in &mut requests {
            request.path = canonical_lock_path(&request.path)?;
        }
        requests.sort_by(|left, right| {
            left.class
                .rank()
                .cmp(&right.class.rank())
                .then_with(|| path_sort_key(&left.path).cmp(&path_sort_key(&right.path)))
        });

        let mut seen = HashSet::with_capacity(requests.len());
        for request in &requests {
            if !seen.insert(request.path.clone()) {
                bail!(
                    "duplicate canonical lock identity in one lock set: {}",
                    request.path.display()
                );
            }
        }

        let mut guards = Vec::with_capacity(requests.len());
        for request in requests {
            guards.push(self.acquire_blocking(request)?);
        }
        Ok(LockSetGuard { guards })
    }

    pub fn active_waiters(&self) -> usize {
        self.inner.limiter.active()
    }

    pub fn max_waiters(&self) -> usize {
        self.inner.limiter.limit
    }

    fn reserve_if_required(
        &self,
        request: &LockRequest,
        identity: &Path,
    ) -> Result<Option<PathBuf>> {
        if request.same_process_policy == SameProcessPolicy::Queue {
            return Ok(None);
        }
        let mut reserved = lock_unpoison(&self.inner.reserved_in_process);
        if !reserved.insert(identity.to_path_buf()) {
            bail!(
                "same process already owns or is waiting for canonical lock {} while starting `{}`; use SameProcessPolicy::Queue only for intentional independent contention",
                identity.display(),
                request.operation
            );
        }
        Ok(Some(identity.to_path_buf()))
    }

    fn remove_reservation(&self, reservation: Option<&PathBuf>) {
        if let Some(identity) = reservation {
            lock_unpoison(&self.inner.reserved_in_process).remove(identity);
        }
    }

    fn emit(
        &self,
        request: &LockRequest,
        kind: LockEventKind,
        elapsed: Option<Duration>,
        owner: Option<OwnerInfo>,
        detail: Option<String>,
    ) {
        (self.inner.event_sink)(&LockEvent {
            kind,
            path: request.path.clone(),
            operation: request.operation.clone(),
            class: request.class,
            elapsed,
            owner,
            detail,
        });
    }
}

/// RAII ownership of one exclusive descriptor lock.
pub struct LockGuard {
    file: Option<File>,
    path: PathBuf,
    operation: String,
    class: LockClass,
    owner: OwnerInfo,
    manager: Arc<ManagerInner>,
    reservation: Option<PathBuf>,
    order_registration: Option<HeldOrderRegistration>,
}

impl LockGuard {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn operation_name(&self) -> &str {
        &self.operation
    }

    pub fn lock_class(&self) -> LockClass {
        self.class
    }

    pub fn owner_info(&self) -> &OwnerInfo {
        &self.owner
    }

    pub fn release(mut self) -> Result<()> {
        self.release_inner()
    }

    fn release_inner(&mut self) -> Result<()> {
        let Some(file) = self.file.take() else {
            return Ok(());
        };
        let unlock_result = FileExt::unlock(&file)
            .with_context(|| format!("unlocking descriptor lock {}", self.path.display()));
        drop(file);
        self.finish_release();
        unlock_result
    }

    fn finish_release(&mut self) {
        drop(self.order_registration.take());
        if let Some(identity) = self.reservation.take() {
            lock_unpoison(&self.manager.reserved_in_process).remove(&identity);
        }
        (self.manager.event_sink)(&LockEvent {
            kind: LockEventKind::Released,
            path: self.path.clone(),
            operation: self.operation.clone(),
            class: self.class,
            elapsed: None,
            owner: Some(self.owner.clone()),
            detail: None,
        });
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = FileExt::unlock(&file);
            drop(file);
            self.finish_release();
        }
    }
}

/// A deterministically ordered set of guards. Drop and explicit release unwind
/// from the most specific lock to the broadest lock.
pub struct LockSetGuard {
    guards: Vec<LockGuard>,
}

impl LockSetGuard {
    pub fn len(&self) -> usize {
        self.guards.len()
    }

    pub fn is_empty(&self) -> bool {
        self.guards.is_empty()
    }

    pub fn release(mut self) -> Result<()> {
        let mut first_error = None;
        while let Some(guard) = self.guards.pop() {
            if let Err(error) = guard.release()
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for LockSetGuard {
    fn drop(&mut self) {
        while let Some(guard) = self.guards.pop() {
            drop(guard);
        }
    }
}

struct WaiterLimiter {
    limit: usize,
    active: AtomicUsize,
}

impl WaiterLimiter {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            active: AtomicUsize::new(0),
        }
    }

    fn reserve(self: &Arc<Self>) -> Result<WaiterPermit> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.limit {
                bail!(
                    "background lock waiter limit reached ({}/{})",
                    current,
                    self.limit
                );
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(WaiterPermit {
                        limiter: Arc::clone(self),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

struct WaiterPermit {
    limiter: Arc<WaiterLimiter>,
}

impl Drop for WaiterPermit {
    fn drop(&mut self) {
        self.limiter.active.fetch_sub(1, Ordering::AcqRel);
    }
}

struct WaitState<G> {
    result: Option<Result<G>>,
    receiver_alive: bool,
    waker: Option<Waker>,
}

struct SharedWait<G> {
    state: Mutex<WaitState<G>>,
    ready: Condvar,
}

/// A runtime-neutral acquisition future backed by one dedicated blocking
/// thread. It also supports synchronous `wait` and reusable `wait_timeout`.
#[must_use = "dropping a pending waiter cancels delivery, not the kernel syscall"]
pub struct LockWaiter<G> {
    label: String,
    shared: Arc<SharedWait<G>>,
    worker: Option<JoinHandle<()>>,
    completed: bool,
    on_cancel: Option<Box<dyn FnOnce() + Send + 'static>>,
}

impl<G> Unpin for LockWaiter<G> {}

impl<G: Send + 'static> LockWaiter<G> {
    pub fn spawn(
        label: impl Into<String>,
        acquire: impl FnOnce() -> Result<G> + Send + 'static,
    ) -> Result<Self> {
        Self::spawn_internal(label.into(), acquire, None)
    }

    fn spawn_with_cancel(
        label: impl Into<String>,
        acquire: impl FnOnce() -> Result<G> + Send + 'static,
        on_cancel: impl FnOnce() + Send + 'static,
    ) -> Result<Self> {
        Self::spawn_internal(label.into(), acquire, Some(Box::new(on_cancel)))
    }

    fn spawn_internal(
        label: String,
        acquire: impl FnOnce() -> Result<G> + Send + 'static,
        on_cancel: Option<Box<dyn FnOnce() + Send + 'static>>,
    ) -> Result<Self> {
        let shared = Arc::new(SharedWait {
            state: Mutex::new(WaitState {
                result: None,
                receiver_alive: true,
                waker: None,
            }),
            ready: Condvar::new(),
        });
        let worker_shared = Arc::clone(&shared);
        let worker_label = label.clone();
        let thread_name = waiter_thread_name(&label);
        let worker = thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(acquire))
                    .unwrap_or_else(|payload| {
                        Err(anyhow!(
                            "background lock waiter `{worker_label}` panicked: {}",
                            panic_message(payload)
                        ))
                    });
                let waker = {
                    let mut state = lock_unpoison(&worker_shared.state);
                    if !state.receiver_alive {
                        drop(state);
                        drop(result);
                        return;
                    }
                    state.result = Some(result);
                    state.waker.take()
                };
                worker_shared.ready.notify_all();
                if let Some(waker) = waker {
                    waker.wake();
                }
            })
            .with_context(|| format!("spawning background lock waiter for `{label}`"))?;

        Ok(Self {
            label,
            shared,
            worker: Some(worker),
            completed: false,
            on_cancel,
        })
    }

    pub fn wait(mut self) -> Result<G> {
        self.ensure_pending()?;
        let result = {
            let mut state = lock_unpoison(&self.shared.state);
            loop {
                if let Some(result) = state.result.take() {
                    break result;
                }
                state = self
                    .shared
                    .ready
                    .wait(state)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        };
        self.finish(result)
    }

    /// Return `Ok(None)` on timeout while keeping the original native request
    /// alive. Calling this method again observes the same waiter thread.
    pub fn wait_timeout(&mut self, timeout: Duration) -> Result<Option<G>> {
        self.ensure_pending()?;
        let started = Instant::now();
        let mut state = lock_unpoison(&self.shared.state);
        loop {
            if let Some(result) = state.result.take() {
                drop(state);
                return self.finish(result).map(Some);
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Ok(None);
            }
            let (next_state, wait_result) = self
                .shared
                .ready
                .wait_timeout(state, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next_state;
            if wait_result.timed_out() && state.result.is_none() {
                return Ok(None);
            }
        }
    }

    fn ensure_pending(&self) -> Result<()> {
        if self.completed {
            bail!("background lock waiter `{}` already completed", self.label);
        }
        Ok(())
    }

    fn finish(&mut self, result: Result<G>) -> Result<G> {
        self.completed = true;
        self.on_cancel = None;
        self.join_worker()?;
        result
    }

    fn join_worker(&mut self) -> Result<()> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        worker
            .join()
            .map_err(|_| anyhow!("background lock waiter `{}` panicked", self.label))
    }
}

impl<G: Send + 'static> Future for LockWaiter<G> {
    type Output = Result<G>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let Err(error) = this.ensure_pending() {
            return Poll::Ready(Err(error));
        }

        let result = {
            let mut state = lock_unpoison(&this.shared.state);
            match state.result.take() {
                Some(result) => Some(result),
                None => {
                    if state
                        .waker
                        .as_ref()
                        .is_none_or(|waker| !waker.will_wake(context.waker()))
                    {
                        state.waker = Some(context.waker().clone());
                    }
                    None
                }
            }
        };

        match result {
            Some(result) => Poll::Ready(this.finish(result)),
            None => Poll::Pending,
        }
    }
}

impl<G> Drop for LockWaiter<G> {
    fn drop(&mut self) {
        if !self.completed {
            if let Some(on_cancel) = self.on_cancel.take() {
                on_cancel();
            }
            let result = {
                let mut state = lock_unpoison(&self.shared.state);
                state.receiver_alive = false;
                state.waker = None;
                state.result.take()
            };
            drop(result);
        }

        if self.worker.as_ref().is_some_and(JoinHandle::is_finished)
            && let Some(worker) = self.worker.take()
        {
            let _ = worker.join();
        }
    }
}

fn open_lock_file(path: &Path) -> Result<(File, PathBuf)> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating lock directory {}", parent.display()))?;
        harden_lock_root_permissions(parent)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("opening lock file {}", path.display()))?;
    let identity = fs::canonicalize(path)
        .with_context(|| format!("canonicalizing lock identity {}", path.display()))?;
    Ok((file, identity))
}

#[cfg(unix)]
fn harden_lock_root_permissions(parent: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("inspecting lock directory {}", parent.display()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!(
            "lock directory {} is not a real directory",
            parent.display()
        );
    }
    let current = metadata.permissions().mode() & 0o777;
    if current & 0o077 != 0 {
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(parent, permissions).with_context(|| {
            format!(
                "restricting lock directory {} to mode 0700",
                parent.display()
            )
        })?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn harden_lock_root_permissions(_parent: &Path) -> Result<()> {
    Ok(())
}

fn canonical_lock_path(path: &Path) -> Result<PathBuf> {
    let (file, canonical) = open_lock_file(path)?;
    drop(file);
    Ok(canonical)
}

fn path_sort_key(path: &Path) -> String {
    let key = path.to_string_lossy().into_owned();
    if cfg!(windows) {
        key.to_lowercase()
    } else {
        key
    }
}

fn write_owner_diagnostics(file: &mut File, owner: &OwnerInfo) -> std::io::Result<()> {
    let clean = |value: &str| value.replace(['\r', '\n'], " ");
    let hostname = owner.hostname.as_deref().map(clean).unwrap_or_default();
    let executable = owner.executable.as_deref().map(clean).unwrap_or_default();
    let thread = owner.thread.as_deref().map(clean).unwrap_or_default();
    let body = format!(
        "# zed-lock diagnostics only; descriptor ownership is authoritative\npid={}\nhostname={}\nexecutable={}\nthread={}\noperation={}\nacquired_unix_ms={}\n",
        owner.pid,
        hostname,
        executable,
        thread,
        clean(&owner.operation),
        owner.acquired_unix_millis()
    );
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(body.as_bytes())?;
    file.flush()
}

fn waiter_thread_name(label: &str) -> String {
    let suffix: String = label
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .take(32)
        .collect();
    if suffix.is_empty() {
        "zed-lock-waiter".to_owned()
    } else {
        format!("zed-lock-{suffix}")
    }
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

fn lock_unpoison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};

    use anyhow::{Result, anyhow};

    use super::{LockClass, LockEventKind, LockManager, LockRequest, LockWaiter, lock_unpoison};

    #[test]
    fn would_block_is_classified_as_lock_contention() {
        let error = std::io::Error::from(std::io::ErrorKind::WouldBlock);
        assert!(super::is_lock_contention(&error));
    }

    #[test]
    fn unrelated_io_errors_are_not_lock_contention() {
        let error = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert!(!super::is_lock_contention(&error));
    }

    #[cfg(windows)]
    #[test]
    fn windows_lock_violation_is_classified_as_contention() {
        let error = std::io::Error::from_raw_os_error(33);
        assert!(super::is_lock_contention(&error));
    }

    #[test]
    fn repeated_timeouts_keep_one_acquisition_request() -> Result<()> {
        let attempts = Arc::new(AtomicUsize::new(0));
        let worker_attempts = Arc::clone(&attempts);
        let (started_sender, started_receiver) = mpsc::sync_channel(1);
        let (release_sender, release_receiver) = mpsc::sync_channel(0);
        let mut waiter = LockWaiter::spawn("one-native-request", move || {
            worker_attempts.fetch_add(1, Ordering::SeqCst);
            started_sender
                .send(())
                .map_err(|_| anyhow!("start receiver closed"))?;
            release_receiver
                .recv()
                .map_err(|_| anyhow!("release channel closed"))?;
            Ok(42_u8)
        })?;

        started_receiver.recv_timeout(Duration::from_secs(1))?;
        assert!(waiter.wait_timeout(Duration::from_millis(20))?.is_none());
        assert!(waiter.wait_timeout(Duration::from_millis(20))?.is_none());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        release_sender.send(())?;
        assert_eq!(waiter.wait_timeout(Duration::from_secs(1))?, Some(42));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn default_policy_rejects_same_process_reentry() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let manager = LockManager::default();
        let request =
            LockRequest::exclusive(temp.path().join("same.lock")).operation("same-process reentry");
        let _guard = manager.acquire_blocking(request.clone())?;
        let error = match manager.try_acquire(request) {
            Ok(_) => panic!("default same-process policy should reject reentry"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("same process already owns"));
        Ok(())
    }

    #[test]
    fn waiter_cap_applies_backpressure_without_polling() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let manager = LockManager::builder().max_waiters(1).build();
        let path = temp.path().join("hot.lock");
        let owner = manager.acquire_blocking(
            LockRequest::exclusive(&path)
                .operation("owner")
                .queue_same_process(),
        )?;
        let waiter = manager.acquire(
            LockRequest::exclusive(&path)
                .operation("first waiter")
                .queue_same_process(),
        )?;
        let deadline = Instant::now() + Duration::from_secs(1);
        while manager.active_waiters() != 1 && Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(manager.active_waiters(), 1);
        let error = match manager.acquire(
            LockRequest::exclusive(temp.path().join("unrelated.lock")).operation("over-cap waiter"),
        ) {
            Ok(_) => panic!("second waiter should be rejected at the configured cap"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("waiter limit reached"));

        drop(waiter);
        drop(owner);
        let deadline = Instant::now() + Duration::from_secs(2);
        while manager.active_waiters() != 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(manager.active_waiters(), 0);
        Ok(())
    }

    #[test]
    fn lock_sets_follow_class_then_path_order() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let events = Arc::new(Mutex::new(Vec::new()));
        let event_log = Arc::clone(&events);
        let manager = LockManager::builder()
            .event_sink(move |event| {
                if event.kind == LockEventKind::Acquired {
                    lock_unpoison(&event_log).push((event.class, event.path.clone()));
                }
            })
            .build();

        let build_b = LockRequest::exclusive(temp.path().join("b.lock"))
            .operation("build b")
            .class(LockClass::Build);
        let project = LockRequest::exclusive(temp.path().join("project.lock"))
            .operation("project")
            .class(LockClass::ProjectMutation);
        let build_a = LockRequest::exclusive(temp.path().join("a.lock"))
            .operation("build a")
            .class(LockClass::Build);

        let guards = manager.acquire_many_blocking([build_b, project, build_a])?;
        assert_eq!(guards.len(), 3);
        let acquired = lock_unpoison(&events);
        assert_eq!(acquired[0].0, LockClass::ProjectMutation);
        assert_eq!(acquired[1].0, LockClass::Build);
        assert_eq!(acquired[2].0, LockClass::Build);
        assert!(acquired[1].1 < acquired[2].1);
        drop(acquired);
        drop(guards);
        Ok(())
    }

    #[test]
    fn nested_lock_order_rejects_descending_classes() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let manager = LockManager::default();
        let _build = manager.acquire_blocking(
            LockRequest::exclusive(temp.path().join("build.lock"))
                .operation("outer build")
                .class(LockClass::Build),
        )?;
        let error = match manager.try_acquire(
            LockRequest::exclusive(temp.path().join("artifact.lock"))
                .operation("inner artifact")
                .class(LockClass::Artifact),
        ) {
            Ok(_) => panic!("descending lock classes must fail before a kernel wait"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("lock-order inversion"));
        Ok(())
    }

    #[test]
    fn nested_lock_order_rejects_descending_paths_within_a_class() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let manager = LockManager::default();
        let _z = manager.acquire_blocking(
            LockRequest::exclusive(temp.path().join("z.lock"))
                .operation("outer z")
                .class(LockClass::Build),
        )?;
        let error = match manager.try_acquire(
            LockRequest::exclusive(temp.path().join("a.lock"))
                .operation("inner a")
                .class(LockClass::Build),
        ) {
            Ok(_) => panic!("descending paths within one class must fail"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("lock-order inversion"));
        Ok(())
    }

    #[test]
    fn nested_lock_order_allows_ascending_acquisition() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let manager = LockManager::default();
        let _project = manager.acquire_blocking(
            LockRequest::exclusive(temp.path().join("project.lock"))
                .operation("outer project")
                .class(LockClass::ProjectMutation),
        )?;
        let _artifact = manager.acquire_blocking(
            LockRequest::exclusive(temp.path().join("artifact.lock"))
                .operation("inner artifact")
                .class(LockClass::Artifact),
        )?;
        Ok(())
    }

    #[test]
    fn dropped_waiter_releases_an_eventual_guard() -> Result<()> {
        struct DropProbe(mpsc::SyncSender<()>);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }

        let (release_sender, release_receiver) = mpsc::sync_channel(0);
        let (dropped_sender, dropped_receiver) = mpsc::sync_channel(1);
        let waiter = LockWaiter::spawn("detached", move || {
            release_receiver.recv()?;
            Ok(DropProbe(dropped_sender))
        })?;
        drop(waiter);
        release_sender.send(())?;
        dropped_receiver.recv_timeout(Duration::from_secs(1))?;
        Ok(())
    }
}

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use zed_lock::{LockManager, LockRequest};

#[cfg(unix)]
#[test]
fn lock_root_is_private_even_when_seeded_wide() {
    use std::os::unix::fs::PermissionsExt;

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "zed-lock-private-root-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("seed root");
    let mut permissions = fs::metadata(&root).expect("root metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&root, permissions).expect("widen seeded root");

    let path = root.join("install.lock");
    let guard = LockManager::global()
        .acquire_blocking(LockRequest::exclusive(&path).operation("privacy regression"))
        .expect("acquire lock");
    let mode = fs::metadata(&root)
        .expect("root metadata after acquire")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode & 0o077,
        0,
        "lock root remained group/other accessible: {mode:o}"
    );
    drop(guard);
    fs::remove_dir_all(&root).expect("cleanup root");
}

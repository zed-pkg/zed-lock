use std::fs;
use std::path::{Path, PathBuf};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn read(relative: &str) -> String {
    let path = repository_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

#[test]
fn fmctl_workflow_is_exact_head_pinned_and_manifest_owned() {
    let workflow = read(".github/workflows/formal-methods.yml");

    for required in [
        "github.event.pull_request.head.sha || github.sha",
        "c2146ef9f054d24e1488c216547852aa148285cf",
        "formal/fm.toml",
        ".formal-tools/opto-sync-clients/tools/fmctl/rust-toolchain.toml",
        "persist-credentials: false",
        "git rev-parse HEAD",
        "rustup toolchain install \"$fmctl_rust\"",
        "rustup default \"$fmctl_rust\"",
        "rustc --version",
        "test \"$manifest_rust\" = \"$fmctl_rust\"",
        "cargo build --locked --release",
        "\"$FMCTL\" --format json validate",
        "\"$FMCTL\" --format json doctor",
        "\"$FMCTL\" check",
        "\"$FMCTL\" simulate",
        "\"$FMCTL\" verify",
    ] {
        assert!(
            workflow.contains(required),
            "formal-methods workflow lost required provenance/control `{required}`"
        );
    }

    for forbidden in [
        "toolchain: stable",
        "rustup default stable",
        "rustup toolchain install stable",
        "dtolnay/rust-toolchain@",
        "persist-credentials: true",
        "contents: write",
        "java-version: \"21\"",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "formal-methods workflow contains forbidden drift `{forbidden}`"
        );
    }
}

#[test]
fn package_ci_requires_the_same_pinned_formal_proof() {
    let workflow = read(".github/workflows/ci.yml");
    for required in [
        "formal-model:",
        "pinned fmctl finite-model certification",
        "c2146ef9f054d24e1488c216547852aa148285cf",
        "formal/fm.toml",
        ".formal-tools/opto-sync-clients/tools/fmctl/rust-toolchain.toml",
        "test \"$manifest_rust\" = \"$fmctl_rust\"",
        "cargo build --locked --release",
        "\"$FMCTL\" check",
        "\"$FMCTL\" simulate",
        "\"$FMCTL\" verify",
        "needs: [test, formal-model]",
    ] {
        assert!(
            workflow.contains(required),
            "required package CI lost formal proof control `{required}`"
        );
    }

    for forbidden in [
        "toolchain: stable",
        "rustup default stable",
        "rustup toolchain install stable",
        "persist-credentials: true",
        "contents: write",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "required package CI contains forbidden drift `{forbidden}`"
        );
    }
}

#[test]
fn formal_manifest_rust_authority_is_patch_exact() {
    let manifest = read("formal/fm.toml");
    let rust = manifest
        .lines()
        .map(str::trim)
        .find_map(|line| {
            line.strip_prefix("rust = \"")
                .and_then(|value| value.strip_suffix('"'))
        })
        .expect("formal/fm.toml must declare toolchain.rust");

    let parts = rust.split('.').collect::<Vec<_>>();
    assert_eq!(
        parts.len(),
        3,
        "formal Rust authority must be x.y.z exact: {rust}"
    );
    assert!(
        parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit())),
        "formal Rust authority must be numeric x.y.z: {rust}"
    );
}

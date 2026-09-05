//! User-private, symlink/reparse-resistant lock rendezvous opening.
//!
//! Default policy is private and fail-closed. Shared-directory behavior is
//! opt-in and still refuses final-component substitution.

use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as AnyhowContext, Result, bail};

/// How lock directories and files are created and validated.
///
/// Private is the Zed default. Shared remains opt-in for callers that must
/// place a rendezvous in an already-shared directory; it never follows
/// symlinks or Windows reparse points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PathSecurityPolicy {
    /// Owner-only lock directories/files. Foreign ownership, group/other
    /// write on the parent, group/other access on the lock file, and
    /// symlink/reparse substitution are rejected. Existing overly-permissive
    /// lock files are rejected rather than chmod'd.
    #[default]
    Private,
    /// Opt-in weaker mode: the current user must still own the immediate
    /// parent and lock file, but group/other permission bits are allowed.
    /// Final-component symlinks and reparse points remain forbidden.
    Shared,
}

impl PathSecurityPolicy {
    pub const fn is_private(self) -> bool {
        matches!(self, Self::Private)
    }
}

/// Open flags the production path uses for the lock file's final component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalComponentOpenIntent {
    pub no_follow: bool,
    pub create_exclusive_if_absent: bool,
    pub owner_only_create_mode: bool,
}

impl FinalComponentOpenIntent {
    pub const fn for_policy(_policy: PathSecurityPolicy) -> Self {
        Self {
            no_follow: true,
            create_exclusive_if_absent: true,
            owner_only_create_mode: true,
        }
    }

    pub const fn refuses_symlink_substitution(self) -> bool {
        self.no_follow
    }
}

/// Unix file mode is owner-only (`0600` bits; no group/other).
#[cfg_attr(windows, allow(dead_code))]
pub const fn unix_private_file_mode(mode: u32) -> bool {
    mode & 0o077 == 0 && mode & 0o600 == 0o600
}

/// Unix directory mode has no group/other write (`0755` and `0700` both pass).
#[cfg_attr(windows, allow(dead_code))]
pub const fn unix_private_dir_mode(mode: u32) -> bool {
    mode & 0o022 == 0
}

#[cfg_attr(not(windows), allow(dead_code))]
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

#[cfg_attr(not(windows), allow(dead_code))]
pub const fn windows_attributes_indicate_reparse(attributes: u32) -> bool {
    attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Protected DACL granting `FA` only to `sid`.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn user_private_sddl(sid: &str) -> String {
    format!("D:P(A;;FA;;;{sid})")
}

/// Classify a Windows DACL without calling Windows APIs.
///
/// Existing parent directories may safely inherit their ACL, so protection is
/// checked separately from access. This classifier requires an allow ACE that
/// grants full control to the current user or a Windows privileged controller,
/// rejects malformed or unsupported ACEs, and rejects write-capable allow ACEs
/// for broad user groups. Windows local system/administrators are an operating-
/// system trust boundary analogous to Unix root; read and execute inheritance is
/// allowed on parents, matching the Unix no-group/other-write directory policy.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn sddl_is_user_private(sddl: &str, sid: &str) -> bool {
    if sid.is_empty() || sddl.matches('(').count() != sddl.matches(')').count() {
        return false;
    }

    let mut grants_trusted_controller_full_control = false;
    for ace in sddl_aces(sddl) {
        let Some((ace_type, rights, trustee)) = parse_sddl_ace(ace) else {
            return false;
        };
        if ace_type.eq_ignore_ascii_case("D") {
            continue;
        }
        if !ace_type.eq_ignore_ascii_case("A") {
            return false;
        }
        if sddl_trustee_is_broad(trustee) && sddl_rights_can_modify(rights) {
            return false;
        }
        if (sddl_trustee_matches_sid(trustee, sid)
            || sddl_trustee_is_privileged_controller(trustee))
            && sddl_rights_are_full_control(rights)
        {
            grants_trusted_controller_full_control = true;
        }
    }

    grants_trusted_controller_full_control
}

// Retained as a platform-independent classifier for parser tests. Production
// Windows enforcement reads SE_DACL_PROTECTED from the descriptor control bits.
#[allow(dead_code)]
pub fn sddl_is_protected_user_private(sddl: &str, sid: &str) -> bool {
    sddl_has_protected_dacl(sddl) && sddl_is_exclusive_user_private(sddl, sid)
}

#[allow(dead_code)]
fn sddl_is_exclusive_user_private(sddl: &str, sid: &str) -> bool {
    sddl_is_user_private(sddl, sid)
        && sddl_grants_full_control_to_sid(sddl, sid)
        && !sddl_has_broad_allow_ace(sddl)
}

#[cfg_attr(not(windows), allow(dead_code))]
fn sddl_aces(sddl: &str) -> impl Iterator<Item = &str> {
    sddl.split('(')
        .skip(1)
        .filter_map(|tail| tail.split_once(')').map(|(ace, _)| ace))
}

#[cfg_attr(not(windows), allow(dead_code))]
fn parse_sddl_ace(ace: &str) -> Option<(&str, &str, &str)> {
    let mut fields = ace.split(';');
    let ace_type = fields.next()?;
    let _flags = fields.next()?;
    let rights = fields.next()?;
    let _object_guid = fields.next()?;
    let _inherit_object_guid = fields.next()?;
    let trustee = fields.next()?;
    if fields.next().is_some() {
        return None;
    }
    Some((ace_type, rights, trustee))
}

#[cfg_attr(not(windows), allow(dead_code))]
fn sddl_rights_are_full_control(rights: &str) -> bool {
    matches!(
        rights.to_ascii_uppercase().as_str(),
        "FA" | "GA" | "0X1F01FF" | "0X10000000"
    )
}

#[cfg_attr(not(windows), allow(dead_code))]
fn sddl_trustee_matches_sid(trustee: &str, sid: &str) -> bool {
    trustee.eq_ignore_ascii_case(sid)
        || (trustee.eq_ignore_ascii_case("SY") && sid.eq_ignore_ascii_case("S-1-5-18"))
}

#[cfg_attr(not(windows), allow(dead_code))]
fn sddl_trustee_is_privileged_controller(trustee: &str) -> bool {
    matches!(trustee.to_ascii_uppercase().as_str(), "SY" | "BA" | "LA")
}

#[cfg_attr(not(windows), allow(dead_code))]
fn sddl_grants_full_control_to_sid(sddl: &str, sid: &str) -> bool {
    sddl_aces(sddl).any(|ace| {
        parse_sddl_ace(ace).is_some_and(|(ace_type, rights, trustee)| {
            ace_type.eq_ignore_ascii_case("A")
                && sddl_trustee_matches_sid(trustee, sid)
                && sddl_rights_are_full_control(rights)
        })
    })
}

#[cfg_attr(not(windows), allow(dead_code))]
fn sddl_trustee_is_broad(trustee: &str) -> bool {
    matches!(
        trustee.to_ascii_uppercase().as_str(),
        "WD" | "AU" | "BU" | "S-1-1-0" | "S-1-5-11" | "S-1-5-32-545"
    )
}

#[cfg_attr(not(windows), allow(dead_code))]
fn sddl_rights_can_modify(rights: &str) -> bool {
    const MODIFY_MASK: u32 = 0x0000_0002
        | 0x0000_0004
        | 0x0000_0010
        | 0x0000_0040
        | 0x0000_0100
        | 0x0001_0000
        | 0x0004_0000
        | 0x0008_0000
        | 0x1000_0000
        | 0x4000_0000;

    let upper = rights.to_ascii_uppercase();
    if let Some(hex) = upper.strip_prefix("0X") {
        return u32::from_str_radix(hex, 16)
            .map(|mask| mask & MODIFY_MASK != 0)
            .unwrap_or(true);
    }
    if !upper.len().is_multiple_of(2) || !upper.is_ascii() {
        return true;
    }
    upper.as_bytes().chunks_exact(2).any(|token| {
        !matches!(
            token,
            b"FR" | b"FX" | b"GR" | b"GX" | b"RC" | b"LC" | b"RP" | b"LO"
        )
    })
}

#[cfg_attr(not(windows), allow(dead_code))]
fn sddl_has_broad_allow_ace(sddl: &str) -> bool {
    sddl_aces(sddl).any(|ace| {
        parse_sddl_ace(ace).is_some_and(|(ace_type, _rights, trustee)| {
            ace_type.eq_ignore_ascii_case("A") && sddl_trustee_is_broad(trustee)
        })
    })
}

#[allow(dead_code)]
fn sddl_has_protected_dacl(sddl: &str) -> bool {
    let upper = sddl.to_ascii_uppercase();
    upper.contains("D:P(") || upper.contains("D:PAI(") || upper.starts_with("D:P")
}

#[allow(dead_code)]
fn sddl_has_same_dacl_aces(actual: &str, expected: &str) -> bool {
    fn ace_section(sddl: &str) -> Option<&str> {
        let first_ace = sddl.find('(')?;
        sddl[..first_ace]
            .to_ascii_uppercase()
            .starts_with("D:")
            .then_some(&sddl[first_ace..])
    }

    match (ace_section(actual), ace_section(expected)) {
        (Some(actual), Some(expected)) => actual.eq_ignore_ascii_case(expected),
        _ => false,
    }
}

pub fn open_lock_file(path: &Path, policy: PathSecurityPolicy) -> Result<(File, PathBuf)> {
    refuse_parent_dir_components(path)?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_lock_parent(parent, policy)?;
    }
    let file = open_final_component(path, policy)?;
    validate_opened_lock_file(&file, path, policy)?;
    let identity = fs::canonicalize(path)
        .with_context(|| format!("canonicalizing lock identity {}", path.display()))?;
    Ok((file, identity))
}

pub fn canonical_lock_path(path: &Path, policy: PathSecurityPolicy) -> Result<PathBuf> {
    let (file, canonical) = open_lock_file(path, policy)?;
    drop(file);
    Ok(canonical)
}

fn refuse_parent_dir_components(path: &Path) -> Result<()> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        bail!("lock path must not contain `..` components");
    }
    Ok(())
}

fn ensure_lock_parent(parent: &Path, policy: PathSecurityPolicy) -> Result<()> {
    let mut missing = Vec::new();
    let mut cursor = parent.to_path_buf();
    loop {
        match fs::symlink_metadata(&cursor) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    bail!("lock directory is a symlink; refusing substitution");
                }
                if !meta.file_type().is_dir() {
                    bail!("lock parent is not a directory");
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt as _;
                    if windows_attributes_indicate_reparse(meta.file_attributes()) {
                        bail!(
                            "lock directory is a reparse point or junction; refusing substitution"
                        );
                    }
                }
                break;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                missing.push(cursor.clone());
                match cursor.parent() {
                    Some(next) if next != cursor && !next.as_os_str().is_empty() => {
                        cursor = next.to_path_buf();
                    }
                    _ => break,
                }
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspecting lock directory {}", cursor.display()));
            }
        }
    }

    for dir in missing.into_iter().rev() {
        create_lock_directory(&dir)?;
    }
    validate_existing_lock_directory(parent, policy)
}

fn create_lock_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("creating lock directory {}", path.display()));
            }
        }
        let mut options = OpenOptions::new();
        options.read(true);
        options.custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC);
        let dir = options
            .open(path)
            .with_context(|| format!("opening lock directory {}", path.display()))?;
        let mut permissions = dir
            .metadata()
            .with_context(|| format!("stat lock directory {}", path.display()))?
            .permissions();
        permissions.set_mode(0o700);
        dir.set_permissions(permissions)
            .with_context(|| format!("setting lock directory mode {}", path.display()))?;
        Ok(())
    }
    #[cfg(windows)]
    {
        match fs::create_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("creating lock directory {}", path.display()));
            }
        }
        windows_acl::apply_user_private_dacl(path)
            .with_context(|| format!("applying private DACL to {}", path.display()))?;
        windows_acl::require_protected_user_private_dacl(path)?;
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        fs::create_dir(path)
            .with_context(|| format!("creating lock directory {}", path.display()))?;
        Ok(())
    }
}

fn validate_existing_lock_directory(path: &Path, policy: PathSecurityPolicy) -> Result<()> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("stat lock directory {}", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!("lock directory is a symlink; refusing substitution");
    }
    if !meta.file_type().is_dir() {
        bail!("lock parent is not a directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if meta.uid() != unix_euid() {
            bail!("lock directory is not owned by the current user");
        }
        let mode = meta.mode() & 0o777;
        if policy.is_private() && !unix_private_dir_mode(mode) {
            bail!(
                "lock directory is group- or world-writable; refusing under the private path policy"
            );
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if windows_attributes_indicate_reparse(meta.file_attributes()) {
            bail!("lock directory is a reparse point or junction; refusing substitution");
        }
        if policy.is_private() {
            windows_acl::require_user_private_dacl(path)?;
        }
    }
    Ok(())
}

fn open_final_component(path: &Path, policy: PathSecurityPolicy) -> Result<File> {
    let intent = FinalComponentOpenIntent::for_policy(policy);
    debug_assert!(intent.refuses_symlink_substitution());
    loop {
        match try_open_existing(path) {
            Ok(file) => return Ok(file),
            Err(error) if error.kind() == ErrorKind::NotFound => match try_create_exclusive(path) {
                Ok(file) => {
                    tighten_created_lock_file(&file, path)?;
                    return Ok(file);
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(map_substitution_error(error, path)),
            },
            Err(error) => return Err(map_substitution_error(error, path)),
        }
    }
}

fn try_open_existing(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(false).truncate(false);
    apply_final_component_open_flags(&mut options);
    finish_opened_lock_file(options.open(path)?)
}

fn try_create_exclusive(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .truncate(false);
    apply_final_component_open_flags(&mut options);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    finish_opened_lock_file(options.open(path)?)
}

fn apply_final_component_open_flags(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        // `OpenOptionsExt::inherit_handle` landed after MSRV 1.88. Clear
        // HANDLE_FLAG_INHERIT on the opened handle instead.
    }
}

fn finish_opened_lock_file(file: File) -> std::io::Result<File> {
    #[cfg(windows)]
    {
        windows_acl::disable_handle_inheritance(&file)?;
    }
    Ok(file)
}

fn tighten_created_lock_file(file: &File, path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = file
            .metadata()
            .with_context(|| format!("stat created lock file {}", path.display()))?
            .permissions();
        permissions.set_mode(0o600);
        file.set_permissions(permissions)
            .with_context(|| format!("setting lock file mode {}", path.display()))?;
    }
    #[cfg(windows)]
    {
        let _ = file;
        windows_acl::apply_user_private_dacl(path)
            .with_context(|| format!("applying private DACL to {}", path.display()))?;
    }
    Ok(())
}

fn validate_opened_lock_file(file: &File, path: &Path, policy: PathSecurityPolicy) -> Result<()> {
    let meta = file.metadata().context("stat opened lock file")?;
    if !meta.file_type().is_file() {
        bail!("lock path is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if meta.uid() != unix_euid() {
            bail!("lock file is not owned by the current user");
        }
        let mode = meta.mode() & 0o777;
        if policy.is_private() && !unix_private_file_mode(mode) {
            bail!(
                "lock file permissions are not owner-only; refusing to use a group- or world-accessible rendezvous"
            );
        }
        let _ = path;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if windows_attributes_indicate_reparse(meta.file_attributes()) {
            bail!("lock path is a reparse point or junction; refusing substitution");
        }
        if policy.is_private() {
            // Inherited DACLs are the Windows default, not an explicit shared
            // mode, so Private tightens then re-validates rather than rejecting
            // every pre-existing rendezvous.
            windows_acl::apply_user_private_dacl(path)
                .with_context(|| format!("applying private DACL to {}", path.display()))?;
            windows_acl::require_protected_user_private_dacl(path)?;
        }
    }
    Ok(())
}

fn map_substitution_error(error: std::io::Error, path: &Path) -> anyhow::Error {
    #[cfg(unix)]
    {
        if error.raw_os_error() == Some(libc::ELOOP) {
            return anyhow::anyhow!(
                "lock path final component is a symlink; refusing substitution ({})",
                path.display()
            );
        }
    }
    anyhow::Error::new(error).context(format!("opening lock file {}", path.display()))
}

#[cfg(unix)]
fn unix_euid() -> u32 {
    // SAFETY: geteuid is a POSIX query with no preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(windows)]
mod windows_acl {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::null_mut;

    use anyhow::{Result, bail};

    use super::{sddl_is_user_private, user_private_sddl};

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER: u32 = 1;
    const SDDL_REVISION_1: u32 = 1;
    const SE_FILE_OBJECT: u32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
    const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
    const SE_DACL_PROTECTED: u16 = 0x1000;

    type Handle = *mut core::ffi::c_void;
    type Psid = *mut core::ffi::c_void;
    type Pacl = *mut core::ffi::c_void;
    type PsecurityDescriptor = *mut core::ffi::c_void;

    #[repr(C)]
    struct TokenUser {
        user: SidAndAttributes,
    }

    #[repr(C)]
    struct SidAndAttributes {
        sid: Psid,
        attributes: u32,
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
        fn GetTokenInformation(
            token: Handle,
            class: u32,
            info: *mut core::ffi::c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
        fn ConvertSidToStringSidW(sid: Psid, string: *mut *mut u16) -> i32;
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string: *const u16,
            revision: u32,
            sd: *mut PsecurityDescriptor,
            size: *mut u32,
        ) -> i32;
        fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd: PsecurityDescriptor,
            revision: u32,
            security_info: u32,
            string: *mut *mut u16,
            length: *mut u32,
        ) -> i32;
        fn GetSecurityDescriptorDacl(
            sd: PsecurityDescriptor,
            present: *mut i32,
            dacl: *mut Pacl,
            defaulted: *mut i32,
        ) -> i32;
        fn GetSecurityDescriptorControl(
            sd: PsecurityDescriptor,
            control: *mut u16,
            revision: *mut u32,
        ) -> i32;
        fn SetNamedSecurityInfoW(
            object: *mut u16,
            object_type: u32,
            security_info: u32,
            owner: Psid,
            group: Psid,
            dacl: Pacl,
            sacl: Pacl,
        ) -> u32;
        fn GetNamedSecurityInfoW(
            object: *const u16,
            object_type: u32,
            security_info: u32,
            owner: *mut Psid,
            group: *mut Psid,
            dacl: *mut Pacl,
            sacl: *mut Pacl,
            sd: *mut PsecurityDescriptor,
        ) -> u32;
        fn LocalFree(mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn CloseHandle(handle: Handle) -> i32;
        fn SetHandleInformation(handle: Handle, mask: u32, flags: u32) -> i32;
    }

    #[cfg(test)]
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetHandleInformation(handle: Handle, flags: *mut u32) -> i32;
    }

    const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;

    fn wide(path: &Path) -> Vec<u16> {
        OsStr::new(path)
            .encode_wide()
            .chain(core::iter::once(0))
            .collect()
    }

    fn wide_str(value: &str) -> Vec<u16> {
        OsStr::new(value)
            .encode_wide()
            .chain(core::iter::once(0))
            .collect()
    }

    unsafe fn wide_to_string(ptr: *mut u16) -> Result<String> {
        if ptr.is_null() {
            bail!("Windows security API returned a null string");
        }
        // SAFETY: the caller owns a NUL-terminated UTF-16 buffer from a
        // Windows allocator. Edition 2024 does not treat the `unsafe fn`
        // body as an unsafe block.
        unsafe {
            let mut len = 0usize;
            while *ptr.add(len) != 0 {
                len += 1;
            }
            let slice = core::slice::from_raw_parts(ptr, len);
            Ok(String::from_utf16_lossy(slice))
        }
    }

    pub fn disable_handle_inheritance(file: &std::fs::File) -> std::io::Result<()> {
        use std::os::windows::io::AsRawHandle as _;
        // SAFETY: `file` is an open handle we own; clearing HANDLE_FLAG_INHERIT
        // is a documented kernel32 query/set on that handle.
        let ok = unsafe { SetHandleInformation(file.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) };
        if ok == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    pub fn handle_is_inheritable(file: &std::fs::File) -> std::io::Result<bool> {
        use std::os::windows::io::AsRawHandle as _;
        let mut flags = 0u32;
        // SAFETY: `file` is an open handle we own; GetHandleInformation writes
        // into a local DWORD.
        let ok = unsafe { GetHandleInformation(file.as_raw_handle(), &mut flags) };
        if ok == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(flags & HANDLE_FLAG_INHERIT != 0)
        }
    }

    pub fn current_user_sid_string() -> Result<String> {
        unsafe {
            // SAFETY: TOKEN_QUERY on the current process is a well-defined
            // query; the information buffer is sized from the first call.
            let mut token = core::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                bail!("OpenProcessToken failed");
            }
            let mut needed = 0u32;
            GetTokenInformation(token, TOKEN_USER, null_mut(), 0, &mut needed);
            let mut buffer = vec![0u8; needed as usize];
            if GetTokenInformation(
                token,
                TOKEN_USER,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            ) == 0
            {
                CloseHandle(token);
                bail!("GetTokenInformation failed");
            }
            CloseHandle(token);
            let user = &*(buffer.as_ptr() as *const TokenUser);
            let mut sid_string = core::ptr::null_mut();
            if ConvertSidToStringSidW(user.user.sid, &mut sid_string) == 0 {
                bail!("ConvertSidToStringSidW failed");
            }
            let rendered = wide_to_string(sid_string);
            LocalFree(sid_string.cast());
            rendered
        }
    }

    pub fn apply_user_private_dacl(path: &Path) -> Result<()> {
        let sid = current_user_sid_string()?;
        let sddl = user_private_sddl(&sid);
        let sddl_wide = wide_str(&sddl);
        unsafe {
            let mut sd: PsecurityDescriptor = null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_wide.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            ) == 0
            {
                bail!("ConvertStringSecurityDescriptorToSecurityDescriptorW failed");
            }
            let mut present = 0i32;
            let mut defaulted = 0i32;
            let mut dacl: Pacl = null_mut();
            if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0
                || present == 0
            {
                LocalFree(sd);
                bail!("constructed security descriptor has no DACL");
            }
            let mut object = wide(path);
            let status = SetNamedSecurityInfoW(
                object.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null_mut(),
            );
            LocalFree(sd);
            if status != 0 {
                bail!("SetNamedSecurityInfoW failed with {status}");
            }
        }
        Ok(())
    }

    pub fn require_user_private_dacl(path: &Path) -> Result<()> {
        let sid = current_user_sid_string()?;
        let (sddl, _) = read_dacl_sddl_and_control(path)?;
        if !sddl_is_user_private(&sddl, &sid) {
            bail!("lock path DACL is not user-private; refusing under the private path policy");
        }
        Ok(())
    }

    pub fn require_protected_user_private_dacl(path: &Path) -> Result<()> {
        let sid = current_user_sid_string()?;
        let (sddl, descriptor_protected) = read_dacl_sddl_and_control(path)?;
        let canonical_private_sddl = canonical_user_private_sddl(&sid)?;
        let exact_private_aces = super::sddl_has_same_dacl_aces(&sddl, &canonical_private_sddl);
        if !descriptor_protected || !exact_private_aces {
            bail!(
                "lock path DACL is not protected and user-private; refusing under the private path policy (descriptor_protected={descriptor_protected}, exact_private_aces={exact_private_aces})"
            );
        }
        Ok(())
    }

    fn canonical_user_private_sddl(sid: &str) -> Result<String> {
        let sddl = user_private_sddl(sid);
        let sddl_wide = wide_str(&sddl);
        unsafe {
            let mut sd: PsecurityDescriptor = null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_wide.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            ) == 0
            {
                bail!("ConvertStringSecurityDescriptorToSecurityDescriptorW failed");
            }
            let rendered = render_dacl_sddl(sd);
            LocalFree(sd);
            rendered
        }
    }

    unsafe fn render_dacl_sddl(sd: PsecurityDescriptor) -> Result<String> {
        let mut string = core::ptr::null_mut();
        // SAFETY: `sd` points to a live descriptor supplied by the caller and
        // the output buffer is released with LocalFree before returning.
        if unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut string,
                null_mut(),
            )
        } == 0
        {
            bail!("ConvertSecurityDescriptorToStringSecurityDescriptorW failed");
        }
        // SAFETY: the successful conversion returned a NUL-terminated UTF-16
        // buffer owned by the local allocator.
        let rendered = unsafe { wide_to_string(string) };
        unsafe {
            LocalFree(string.cast());
        }
        rendered
    }

    fn read_dacl_sddl_and_control(path: &Path) -> Result<(String, bool)> {
        let object = wide(path);
        unsafe {
            let mut sd: PsecurityDescriptor = null_mut();
            let status = GetNamedSecurityInfoW(
                object.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut sd,
            );
            if status != 0 {
                bail!("GetNamedSecurityInfoW failed with {status}");
            }
            let mut control = 0u16;
            let mut revision = 0u32;
            if GetSecurityDescriptorControl(sd, &mut control, &mut revision) == 0 {
                LocalFree(sd);
                bail!("GetSecurityDescriptorControl failed");
            }
            let rendered = render_dacl_sddl(sd);
            LocalFree(sd);
            rendered.map(|sddl| (sddl, control & SE_DACL_PROTECTED != 0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_is_the_default_fail_closed_policy() {
        assert_eq!(PathSecurityPolicy::default(), PathSecurityPolicy::Private);
        assert!(PathSecurityPolicy::Private.is_private());
        assert!(!PathSecurityPolicy::Shared.is_private());
    }

    #[test]
    fn unix_mode_helpers_reject_group_and_other_access() {
        assert!(unix_private_file_mode(0o600));
        assert!(!unix_private_file_mode(0o640));
        assert!(!unix_private_file_mode(0o666));
        assert!(unix_private_dir_mode(0o700));
        assert!(unix_private_dir_mode(0o755));
        assert!(!unix_private_dir_mode(0o775));
        assert!(!unix_private_dir_mode(0o777));
    }

    #[test]
    fn windows_reparse_attribute_classifier_is_stable() {
        assert!(!windows_attributes_indicate_reparse(0x20));
        assert!(windows_attributes_indicate_reparse(
            FILE_ATTRIBUTE_REPARSE_POINT
        ));
        assert!(windows_attributes_indicate_reparse(
            FILE_ATTRIBUTE_REPARSE_POINT | 0x10
        ));
    }

    #[test]
    fn user_private_sddl_classifier_accepts_safe_inheritance_and_rejects_broad_trustees() {
        let sid = "S-1-5-21-1-2-3-1001";
        let private = user_private_sddl(sid);
        assert!(sddl_is_user_private(&private, sid));
        assert!(sddl_is_protected_user_private(&private, sid));

        let inherited = format!("D:AI(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        assert!(sddl_is_user_private(&inherited, sid));
        assert!(!sddl_is_protected_user_private(&inherited, sid));
        assert!(sddl_is_user_private(
            &format!("D:AI(A;ID;0x1f01ff;;;{sid})"),
            sid
        ));

        let inherited_with_broad_read = format!("D:AI(A;OICI;FA;;;{sid})(A;ID;0x1200a9;;;BU)");
        assert!(sddl_is_user_private(&inherited_with_broad_read, sid));
        assert!(!sddl_is_protected_user_private(
            &inherited_with_broad_read,
            sid
        ));
        assert!(!sddl_is_user_private(
            &format!("D:AI(A;OICI;FA;;;{sid})(A;ID;0x120116;;;BU)"),
            sid
        ));
        let hosted_windows_parent = "D:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;LA)";
        assert!(sddl_is_user_private(hosted_windows_parent, sid));
        assert!(!sddl_is_protected_user_private(hosted_windows_parent, sid));
        assert!(!sddl_is_protected_user_private(
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LA)",
            sid
        ));
        assert!(!sddl_is_user_private("D:(A;;FA;;;WD)", sid));
        let protected_with_broad_read = format!("D:P(A;;FA;;;{sid})(A;ID;FR;;;WD)");
        assert!(sddl_is_user_private(&protected_with_broad_read, sid));
        assert!(!sddl_is_protected_user_private(
            &protected_with_broad_read,
            sid
        ));
        assert!(!sddl_is_user_private("D:P(A;;FA;;;AU)", sid));
        assert!(!sddl_is_user_private("D:P(A;;FA;;;BU)", sid));
        assert!(!sddl_is_user_private("D:P(A;;FA;;;", sid));
        assert!(!sddl_is_user_private("", sid));
    }

    #[test]
    fn canonical_dacl_comparison_ignores_only_control_flags() {
        let expected = "D:P(A;;FA;;;LA)";
        assert!(sddl_has_same_dacl_aces("D:PAI(A;;FA;;;LA)", expected));
        assert!(sddl_has_same_dacl_aces("D:PAR(A;;FA;;;la)", expected));
        assert!(!sddl_has_same_dacl_aces(
            "D:PAI(A;;FA;;;LA)(A;;FR;;;SY)",
            expected
        ));
        assert!(!sddl_has_same_dacl_aces("D:P", expected));
        assert!(!sddl_has_same_dacl_aces("O:LA(A;;FA;;;LA)", expected));
    }

    #[test]
    fn production_open_intent_refuses_symlink_follow_and_weakened_variant_does_not() {
        let production = FinalComponentOpenIntent::for_policy(PathSecurityPolicy::Private);
        let weakened = FinalComponentOpenIntent {
            no_follow: false,
            create_exclusive_if_absent: true,
            owner_only_create_mode: true,
        };
        assert!(production.refuses_symlink_substitution());
        assert!(!weakened.refuses_symlink_substitution());
        assert_ne!(production, weakened);
        assert!(
            FinalComponentOpenIntent::for_policy(PathSecurityPolicy::Shared)
                .refuses_symlink_substitution()
        );
    }

    #[test]
    fn parent_dir_components_are_rejected() {
        let error = refuse_parent_dir_components(Path::new("foo/../bar.lock")).unwrap_err();
        assert!(error.to_string().contains("`..`"));
    }

    #[cfg(unix)]
    #[test]
    fn unix_private_open_creates_0700_dir_and_0600_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("locks");
        let path = dir.join("install.lock");
        let (file, identity) = open_lock_file(&path, PathSecurityPolicy::Private).unwrap();
        drop(file);
        let dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        let file_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);
        assert_eq!(identity, fs::canonicalize(&path).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn unix_private_open_refuses_final_component_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target.lock");
        fs::write(&target, b"redirected\n").unwrap();
        let link = temp.path().join("alias.lock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = open_lock_file(&link, PathSecurityPolicy::Private).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("symlink") || message.contains("substitution"),
            "unexpected diagnostic: {message}"
        );
        assert_eq!(fs::read(&target).unwrap(), b"redirected\n");
    }

    #[cfg(unix)]
    #[test]
    fn unix_private_open_refuses_symlink_parent() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = temp.path().join("linked");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let path = link.join("install.lock");
        let error = open_lock_file(&path, PathSecurityPolicy::Private).unwrap_err();
        assert!(format!("{error:#}").contains("symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn unix_private_open_refuses_permissive_existing_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wide.lock");
        fs::write(&path, b"wide\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        let error = open_lock_file(&path, PathSecurityPolicy::Private).unwrap_err();
        assert!(format!("{error:#}").contains("owner-only"));
        assert_eq!(fs::read(&path).unwrap(), b"wide\n");
    }

    #[cfg(unix)]
    #[test]
    fn unix_shared_policy_allows_existing_group_readable_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("shared.lock");
        fs::write(&path, b"shared\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let (file, _) = open_lock_file(&path, PathSecurityPolicy::Shared).unwrap();
        drop(file);
    }

    #[cfg(unix)]
    #[test]
    fn unix_private_open_refuses_group_writable_parent() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("shared-parent");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o770)).unwrap();
        let path = parent.join("install.lock");
        let error = open_lock_file(&path, PathSecurityPolicy::Private).unwrap_err();
        assert!(format!("{error:#}").contains("writable"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_private_open_uses_non_inheritable_handle() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("install.lock");
        let (file, identity) = open_lock_file(&path, PathSecurityPolicy::Private).unwrap();
        assert!(
            !windows_acl::handle_is_inheritable(&file).unwrap(),
            "lock file handle must not be inheritable"
        );
        drop(file);
        assert_eq!(identity, fs::canonicalize(&path).unwrap());
    }
}

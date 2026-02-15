//! Crash state persistence
//!
//! Handles writing and reading crash recovery state to disk.

use std::fs;
use std::io;
use std::path::PathBuf;

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::upgrade::UpgradeState;

/// Crash state file - contains all info needed to recover
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashState {
    /// The terminal state (reuses upgrade state format)
    pub state: UpgradeState,
    /// Timestamp when state was last written
    pub timestamp: u64,
    /// PID of the process that wrote this state
    pub pid: u32,
}

impl CrashState {
    /// Create a new crash state
    pub fn new(state: UpgradeState) -> Self {
        Self {
            state,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            pid: std::process::id(),
        }
    }
}

/// Get the cache directory for cterm
fn cache_dir() -> PathBuf {
    ProjectDirs::from("com", "cterm", "cterm")
        .map(|dirs| dirs.cache_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/tmp/cterm"))
}

/// Get the path to the crash state file
pub fn crash_state_path() -> PathBuf {
    cache_dir().join("crash_state.bin")
}

/// Get the path to the crash marker file (indicates a crash occurred)
pub fn crash_marker_path() -> PathBuf {
    cache_dir().join("crash_marker")
}

/// Write crash state to disk
pub fn write_crash_state(state: &CrashState) -> io::Result<()> {
    let path = crash_state_path();

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Serialize with bincode
    let bytes =
        bincode::serialize(state).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Write atomically using temp file + rename
    let temp_path = path.with_extension("tmp");
    fs::write(&temp_path, &bytes)?;

    // Set restrictive permissions (crash state may contain scrollback with secrets)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        fs::set_permissions(&temp_path, perms)?;
    }

    fs::rename(&temp_path, &path)?;

    log::trace!("Wrote crash state: {} bytes", bytes.len());

    Ok(())
}

/// Read crash state from disk
pub fn read_crash_state() -> io::Result<CrashState> {
    let path = crash_state_path();
    let bytes = fs::read(&path)?;

    let state: CrashState =
        bincode::deserialize(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    log::info!(
        "Read crash state: {} windows, written by PID {} at timestamp {}",
        state.state.windows.len(),
        state.pid,
        state.timestamp
    );

    Ok(state)
}

/// Clear crash state file (called after successful startup)
pub fn clear_crash_state() -> io::Result<()> {
    let path = crash_state_path();
    if path.exists() {
        // Check for symlink to prevent targeted file deletion
        let meta = fs::symlink_metadata(&path)?;
        if meta.is_symlink() {
            log::warn!("Crash state path is a symlink, refusing to remove");
            return Ok(());
        }
        fs::remove_file(&path)?;
    }
    Ok(())
}

/// Write crash marker (indicates a crash happened)
pub fn write_crash_marker(signal: i32) -> io::Result<()> {
    let path = crash_marker_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, format!("{}\n{}", signal, std::process::id()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = fs::set_permissions(&path, perms);
    }

    Ok(())
}

/// Read and clear crash marker
pub fn read_crash_marker() -> Option<(i32, u32)> {
    let path = crash_marker_path();
    if !path.exists() {
        return None;
    }

    // Check for symlink before reading/removing
    if let Ok(meta) = fs::symlink_metadata(&path) {
        if meta.is_symlink() {
            log::warn!("Crash marker path is a symlink, ignoring");
            return None;
        }
    }

    let content = fs::read_to_string(&path).ok()?;
    let _ = fs::remove_file(&path);

    let mut lines = content.lines();
    let signal: i32 = lines.next()?.parse().ok()?;
    let pid: u32 = lines.next()?.parse().ok()?;

    Some((signal, pid))
}

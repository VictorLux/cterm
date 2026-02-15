# Security Audit Report — cterm

**Date:** 2026-02-15
**Scope:** Full source code audit of all crates (`cterm-core`, `cterm-app`, `cterm-cocoa`, `cterm-gtk`, `cterm-ui`)
**Focus:** Backdoors, data exfiltration, memory safety, input validation, supply chain, network activity

---

## Executive Summary

No backdoors, telemetry, or data exfiltration mechanisms found. The codebase is clean and transparent. All network activity is user-initiated (GitHub update checks only). The main areas of concern are: unsafe Objective-C interop in the macOS UI layer, the upgrade mechanism lacking mandatory signature verification, and unbounded allocations in the VT parser that could be exploited for denial-of-service via malicious terminal output.

**Overall finding counts:**

| Severity | Count |
|----------|-------|
| Critical | 3 |
| High | 7 |
| Medium | 8 |
| Low | 5 |

---

## Critical

### 1. Upgrade checksum verification is optional

**Location:** `crates/cterm-app/src/upgrade/updater.rs:404-433`

If GitHub doesn't provide a `.sha256` file for a release asset, verification silently returns `Ok(false)` and the update proceeds unverified. Combined with no cryptographic signature verification, a compromised GitHub release or MITM could deliver a malicious binary.

```rust
let checksum_url = match &info.checksum_url {
    Some(url) => url,
    None => return Ok(false), // Silently continues without verification
};
```

**Recommendation:** Make checksum verification mandatory. Implement Ed25519/GPG signature verification with a public key embedded in the binary.

---

### 2. Potential integer overflow in Sixel decoder allocation

**Location:** `crates/cterm-core/src/sixel.rs:402-409`

`new_width * new_height * 4` is computed without checked arithmetic. If a malicious Sixel sequence specifies very large dimensions, the multiplication could overflow on 32-bit targets, causing a smaller-than-expected allocation followed by out-of-bounds writes.

```rust
let mut new_pixels = if self.transparent_bg {
    vec![0u8; new_width * new_height * 4] // Unchecked multiplication
} else { ... }
```

**Recommendation:** Use `checked_mul()` and reject images exceeding a reasonable pixel budget.

---

### 3. Unsafe signal handler in multi-threaded context

**Location:** `crates/cterm-cocoa/src/app.rs:1317-1331`

The SIGSEGV/SIGBUS handler calls `std::backtrace::Backtrace::force_capture()` and writes to stderr. Neither operation is async-signal-safe. In a multi-threaded application this is undefined behavior and could cause deadlocks or memory corruption.

**Recommendation:** Use the `signal-hook` crate or limit signal handlers to async-signal-safe operations (write raw bytes to a pipe, then abort).

---

## High

### 4. No binary signature verification for updates

**Location:** `crates/cterm-app/src/upgrade/updater.rs` (throughout)

SHA256 checksums (when present) prevent corruption but not tampering by an attacker with repo or CDN access. No GPG or code-signing verification exists.

**Recommendation:** Implement Ed25519 signature verification. Embed the public key in the binary.

---

### 5. Download URL not validated against expected domain

**Location:** `crates/cterm-app/src/upgrade/updater.rs:175-199`

The `browser_download_url` from the GitHub API JSON response is used directly without verifying it points to the expected GitHub releases domain. A tampered API response could redirect the download to an attacker-controlled server.

**Recommendation:** Validate that asset URLs match `https://github.com/KarpelesLab/cterm/releases/download/...`.

---

### 6. Symlink attack in upgrade backup path

**Location:** `crates/cterm-app/src/upgrade/updater.rs:378-385`

Before replacing the app bundle, the old one is backed up to a predictable path (`cterm.app.backup`). If an attacker places a symlink at that path, `remove_dir_all` deletes the symlink target instead of the backup directory.

```rust
let backup_path = target_app.with_extension("app.backup");
if backup_path.exists() {
    std::fs::remove_dir_all(&backup_path)?; // Follows symlinks
}
```

**Recommendation:** Check that `backup_path` is not a symlink before removing.

---

### 7. Upgrade FD state serialization not authenticated

**Location:** `crates/cterm-app/src/upgrade/protocol.rs:104`

Terminal state is serialized to JSON and passed over a Unix socket without integrity validation (HMAC or signature). A local attacker with socket access could inject crafted state during the seamless upgrade window.

**Recommendation:** Add HMAC validation to serialized upgrade state.

---

### 8. Unsafe pointer casts without type validation (macOS)

**Location:** `crates/cterm-cocoa/src/app.rs:472,500,636` and `crates/cterm-cocoa/src/window.rs:449,535`

Multiple locations cast `NSWindow`/`AnyObject` pointers to `CtermWindow`/`NSMenuItem`/`AppDelegate` without runtime type checks. If a non-cterm window is present (e.g., system dialog, third-party accessibility tool), this is undefined behavior.

```rust
let cterm_window: &CtermWindow = unsafe {
    &*(&*key_window as *const NSWindow as *const CtermWindow)
};
```

**Recommendation:** Add `msg_send![obj, isKindOfClass: class]` guards before every unsafe pointer cast.

---

### 9. Dangling pointer risk in Quick Open callbacks

**Location:** `crates/cterm-cocoa/src/window.rs:481-491`

Callbacks capture `self as *const Self` (a raw pointer) without incrementing the Objective-C retain count. If the window is deallocated while the overlay is visible, the captured pointer dangles and subsequent use is a use-after-free.

```rust
let window_ptr = self as *const Self;
overlay.set_on_select(move |template| unsafe {
    let window = &*window_ptr; // Dangling if window was deallocated
    window.open_template_tab(&template);
});
```

**Recommendation:** Use `Retained<>` to prevent premature deallocation.

---

### 10. Git credential exposure risk

**Location:** `crates/cterm-app/src/git_sync.rs` (throughout)

Git operations are performed via subprocess (`Command::new("git")`). If the user has HTTPS remotes with credential helpers, credentials could appear in process listings or debug log output.

**Recommendation:** Document that SSH keys with agents are the recommended authentication method. Avoid logging git command outputs at debug/trace level.

---

## Medium

### 11. Unbounded OSC 1337 buffer growth (DoS)

**Location:** `crates/cterm-core/src/parser.rs:47-53`

The `Osc1337State` enum contains unbounded `Vec<u8>` fields. A malicious remote server can send an extremely long OSC 1337 sequence to exhaust memory without any size limit.

```rust
Osc1337Content(Vec<u8>),  // No size limit
Osc1337Params(String),     // Unbounded String
```

**Recommendation:** Cap OSC buffer at ~16MB and discard sequences exceeding the limit.

---

### 12. Crash state and config files created with default permissions

**Location:** `crates/cterm-app/src/crash_recovery/state.rs:57-77` and `crates/cterm-app/src/config.rs:900-904`

Files are written with `std::fs::write()` which inherits the process umask. On systems with a permissive umask, crash state (which contains scrollback with potential secrets) and config files could be world-readable.

```rust
fs::write(&temp_path, &bytes)?; // Created with default umask
```

**Recommendation:** Explicitly set `0o600` permissions after file creation on Unix.

---

### 13. Predictable temp file paths for scrollback

**Location:** `crates/cterm-app/src/upgrade/state.rs:246-249`

Scrollback spill files use the pattern `cterm_scrollback_{PID}_{index}.bin` which is predictable and vulnerable to symlink race conditions.

```rust
let path = std::env::temp_dir().join(format!(
    "cterm_scrollback_{}_{}.bin",
    std::process::id(),
    index
));
```

**Recommendation:** Use `tempfile::NamedTempFile` for secure random naming.

---

### 14. No symlink checks before crash state file operations

**Location:** `crates/cterm-app/src/crash_recovery/state.rs:98-104`

`fs::remove_file()` is called without checking if the path is a symlink, allowing an attacker to cause targeted file deletion by planting a symlink at the crash state path.

**Recommendation:** Use `fs::symlink_metadata()` to detect symlinks before operating on files.

---

### 15. Image dimension allows large memory allocation

**Location:** `crates/cterm-core/src/image_decode.rs:50-52`

`MAX_IMAGE_DIMENSION` is 4096, allowing 4096x4096 RGBA images (~64MB each). Multiple such images delivered via iTerm2 inline images or Sixel could exhaust memory.

**Recommendation:** Implement a total pixel budget across all inline images (e.g., 64MB total) with LRU eviction.

---

### 16. TOCTOU race in terminal view pointer (macOS)

**Location:** `crates/cterm-cocoa/src/terminal_view.rs:1472-1476`

A `view_invalid` atomic flag is checked before using a raw pointer in a background thread callback, but the pointer could be invalidated between the check and the use.

**Recommendation:** Use `Arc<>` with proper synchronization instead of raw pointers for cross-thread data sharing.

---

### 17. Git remote URL not validated

**Location:** `crates/cterm-app/src/git_sync.rs:172-189`

Remote URLs are passed directly to `git remote add` without validation. Malicious or malformed URLs could trigger unintended git behavior.

**Recommendation:** Validate that remote URLs use `https://`, `ssh://`, or `git@` protocols only.

---

### 18. Hard reset during git sync conflict silently overwrites local config

**Location:** `crates/cterm-app/src/git_sync.rs:336-338`

A `git reset --hard` to the remote reference discards all local config changes without creating a backup or prompting the user.

```rust
run_git(config_dir, &["reset", "--hard", &remote_ref])?;
```

**Recommendation:** Create a backup of local config before performing hard reset. Consider prompting the user.

---

## Low

### 19. No rate limiting on VT parser input

**Location:** `crates/cterm-core/src/parser.rs:86`

The parser has no complexity budget or rate limiting. A rapid stream of complex escape sequences could consume excessive CPU time.

---

### 20. Clipboard paste has no size limit

**Location:** `crates/cterm-gtk/src/window.rs:428-441` (and macOS equivalent)

Clipboard data is pasted directly to the PTY without size validation. A very large clipboard payload could flood the terminal.

**Recommendation:** Warn or prompt for confirmation when pasting data larger than a threshold (e.g., 1MB).

---

### 21. Base64 padding loop edge case

**Location:** `crates/cterm-core/src/streaming_file.rs:252-254`

The padding loop appends `=` until the buffer length is a multiple of 4, but no iteration limit prevents a potential spin if buffer state is corrupted.

```rust
while !self.base64_buffer.len().is_multiple_of(4) {
    self.base64_buffer.push(b'=');
}
```

**Recommendation:** Add a maximum iteration guard (e.g., `for _ in 0..3`).

---

### 22. CString::new() failures silently ignored

**Location:** `crates/cterm-core/src/pty.rs:451-470`

Null bytes in shell path or argument strings cause `CString::new()` to fail, which is silently ignored via `if let Ok(...)`. This could lead to unexpected fallback behavior.

**Recommendation:** Log a warning when CString conversion fails.

---

### 23. Tool shortcuts execute arbitrary commands

**Location:** `crates/cterm-gtk/src/window.rs:726` (and macOS equivalent)

Tool shortcuts defined in config are executed as subprocesses. This is by design, but a compromised config file means arbitrary code execution.

**Recommendation:** Consider restricting tool commands to absolute paths. Document the security implications.

---

## Positive Findings

The following security properties were verified:

- **Zero telemetry or analytics** — no phone-home, no tracking, no crash reporting services
- **No background network activity** — all connections are user-initiated (update checks only)
- **No hardcoded credentials or API keys** in source code
- **TLS enforced** on all network connections via rustls backend
- **Clean dependency tree** — all dependencies from crates.io, version-pinned in Cargo.lock
- **No suspicious build scripts** — only protobuf compilation for the headless crate
- **Terminal content is never transmitted externally**
- **Single HTTP client** (reqwest) used for a single legitimate purpose (GitHub API)
- **Open source, publicly auditable code**

---

## Recommended Priority Actions

| Priority | Action | Findings |
|----------|--------|----------|
| **P0** | Mandatory checksum verification + add binary signature verification for updates | #1, #4, #5 |
| **P0** | Use checked arithmetic in Sixel/DRCS decoders | #2 |
| **P1** | Fix signal handler to be async-signal-safe | #3 |
| **P1** | Add `isKindOfClass:` guards on all unsafe ObjC pointer casts | #8 |
| **P1** | Cap OSC 1337 buffer size to prevent memory exhaustion | #11 |
| **P1** | Set explicit file permissions (`0o600`) on config and state files | #12 |
| **P2** | Use `tempfile` crate for secure temp file creation | #13 |
| **P2** | Add symlink checks before file removal operations | #6, #14 |
| **P2** | Validate git remote URLs and download asset URLs | #5, #17 |
| **P2** | Use `Retained<>` for all ObjC callback captured pointers | #9, #16 |
| **P3** | Add clipboard paste size limits and confirmation prompt | #20 |
| **P3** | Implement total pixel budget for inline images | #15 |
| **P3** | Add iteration guards in base64 padding and log CString failures | #21, #22 |

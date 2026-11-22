//! The relay log (~/Library/Logs/AlwaysConnect/relay.log; DESIGN.md
//! §28.1, §30.9; moved to Rust in §32.9): why relayed connections end
//! and the login's shape, readable without administrator rights (the
//! background service's own log is root-only). Owner-only local metadata may
//! include targets; the public relay_diagnostics projection removes them.
//! No credentials or raw HTTP content. Over 1 MB the file starts afresh.
//! Harnesses log elsewhere (ALWAYSCONNECT_RELAY_LOG), never into the
//! user's file.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const LIMIT: u64 = 1_000_000;
static LOCK: Mutex<()> = Mutex::new(());

pub fn path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("ALWAYSCONNECT_RELAY_LOG") {
        return Some(PathBuf::from(p));
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Logs/AlwaysConnect/relay.log"))
}

/// "2026-11-06T09:44:19Z" (UTC), as ISO8601DateFormatter wrote it.
pub fn stamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, rem / 3600, rem % 3600 / 60, rem % 60)
}

pub fn write(line: &str) {
    let Some(path) = path() else { return };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let text = format!("{} {}\n", stamp(now), line);
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    append(&path, &text);
}

fn append(path: &Path, text: &str) {
    // Work through the opened descriptor, never follow a log symlink or
    // chmod/truncate its target. Existing older logs become owner-only too.
    let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true)
        .mode(0o600).custom_flags(libc::O_NOFOLLOW).open(path) else { return };
    if file.set_permissions(std::fs::Permissions::from_mode(0o600)).is_err() { return; }
    if file.metadata().is_ok_and(|m| m.len() > LIMIT) && file.set_len(0).is_err() { return; }
    let _ = file.write_all(text.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps() {
        assert_eq!(stamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(stamp(1_793_958_259), "2026-11-06T09:44:19Z");
        assert_eq!(stamp(951_782_400), "2000-02-29T00:00:00Z");
    }
    #[test]
    fn relay_log_is_private_and_does_not_follow_symlinks() {
        let dir = std::env::temp_dir().join(format!("ac-relay-log-permissions-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("relay.log"); std::fs::write(&file, "old").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        append(&file, "metadata");
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        let link = dir.join("link.log"); let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&file, &link).unwrap(); append(&link, "not-appended");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "oldmetadata");
        std::fs::remove_dir_all(dir).unwrap();
    }

}

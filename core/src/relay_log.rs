//! The relay log (~/Library/Logs/AlwaysConnect/relay.log; DESIGN.md
//! §28.1, §30.9; moved to Rust in §32.9): why relayed connections end
//! and the login's shape, readable without administrator rights (the
//! background service's own log is root-only). Reasons and counts only:
//! no addresses, no content. Bounded: over 1 MB the file starts afresh.
//! Harnesses log elsewhere (ALWAYSCONNECT_RELAY_LOG), never into the
//! user's file.

use std::io::Write;
use std::path::PathBuf;
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
    if std::fs::metadata(&path).map(|m| m.len() > LIMIT).unwrap_or(false) {
        let _ = std::fs::remove_file(&path);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = f.write_all(text.as_bytes());
    }
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
}

//! Update check (DESIGN.md §三十三): which GitHub Release, if any, the
//! App should point the user at.
//!
//! The App fetches `GET /repos/<owner>/<repo>/releases` itself (a thin
//! URLSession shell) and hands the body here with its own version. This
//! module parses the list, compares versions and returns one decision.
//! Pre-releases count (user, 2026-11-06: "预发布也提示"); drafts never do.
//! Nothing is downloaded or installed: the App only opens the Release
//! page, the update itself is the user's.

use serde::Deserialize;
use std::cmp::Ordering;

/// Only Release pages on GitHub are opened in the browser: a reply that
/// names any other address is treated as no release at all.
const PAGE_PREFIX: &str = "https://github.com/";

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: Option<String>,
    html_url: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

/// A version as tags and CFBundleShortVersionString write it:
/// `v1.2.3`, `1.2`, `0.2.0-beta.1`, `1.0.0+build5`.
#[derive(Debug, Clone)]
pub struct Version {
    core: Vec<u64>,
    pre: Vec<String>,
}

impl Version {
    pub fn parse(text: &str) -> Option<Version> {
        let text = text.trim();
        let text = text.strip_prefix(['v', 'V']).unwrap_or(text);
        // Build metadata never orders versions (SemVer §10).
        let text = text.split('+').next().unwrap_or("");
        let (core, pre) = match text.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (text, None),
        };
        if core.is_empty() {
            return None;
        }
        let core = core
            .split('.')
            .map(|part| {
                if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                    None
                } else {
                    part.parse::<u64>().ok()
                }
            })
            .collect::<Option<Vec<u64>>>()?;
        let pre = match pre {
            Some(pre) => {
                let ids: Vec<String> = pre.split('.').map(str::to_string).collect();
                if ids.iter().any(|id| id.is_empty()) {
                    return None;
                }
                ids
            }
            None => Vec::new(),
        };
        Some(Version { core, pre })
    }

    /// `1.2` is `1.2.0` again: missing parts count as zero.
    fn core_part(&self, i: usize) -> u64 {
        self.core.get(i).copied().unwrap_or(0)
    }

    pub fn display(&self) -> String {
        let mut core = self.core.clone();
        while core.len() < 3 {
            core.push(0);
        }
        let mut s = core.iter().map(u64::to_string).collect::<Vec<_>>().join(".");
        if !self.pre.is_empty() {
            s.push('-');
            s.push_str(&self.pre.join("."));
        }
        s
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let len = self.core.len().max(other.core.len());
        for i in 0..len {
            match self.core_part(i).cmp(&other.core_part(i)) {
                Ordering::Equal => {}
                unequal => return unequal,
            }
        }
        // A pre-release is lower than the release it leads to (SemVer §11).
        match (self.pre.is_empty(), other.pre.is_empty()) {
            (true, true) => return Ordering::Equal,
            (true, false) => return Ordering::Greater,
            (false, true) => return Ordering::Less,
            (false, false) => {}
        }
        for (a, b) in self.pre.iter().zip(other.pre.iter()) {
            let order = match (a.parse::<u64>(), b.parse::<u64>()) {
                (Ok(a), Ok(b)) => a.cmp(&b),
                // Numeric identifiers sort before alphanumeric ones.
                (Ok(_), Err(_)) => Ordering::Less,
                (Err(_), Ok(_)) => Ordering::Greater,
                (Err(_), Err(_)) => a.cmp(b),
            };
            if order != Ordering::Equal {
                return order;
            }
        }
        self.pre.len().cmp(&other.pre.len())
    }
}

/// Equal when they order equal: `1.2` is `1.2.0`.
impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// What the App shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// A newer release: its version as shown, the tag, and its page.
    Newer { version: String, tag: String, url: String, prerelease: bool },
    /// The newest release is the one the user chose to skip.
    Skipped { version: String },
    /// Nothing newer than this App.
    Current,
    /// The reply was not a release list (private repository, rate limit,
    /// a captive portal page) or this App's version is unreadable.
    Unreadable,
}

/// Picks the newest non-draft release above `current`. `skipped` is the
/// version the user dismissed; a later release still shows.
pub fn decide(current: &str, releases_json: &str, skipped: Option<&str>) -> Decision {
    let Some(current) = Version::parse(current) else {
        return Decision::Unreadable;
    };
    let Ok(releases) = serde_json::from_str::<Vec<Release>>(releases_json) else {
        return Decision::Unreadable;
    };
    let newest = releases
        .into_iter()
        .filter(|r| !r.draft)
        .filter_map(|r| {
            let tag = r.tag_name?;
            let url = r.html_url.filter(|u| u.starts_with(PAGE_PREFIX))?;
            let version = Version::parse(&tag)?;
            Some((version, tag, url, r.prerelease))
        })
        .max_by(|a, b| a.0.cmp(&b.0));
    let Some((version, tag, url, prerelease)) = newest else {
        return Decision::Current;
    };
    if version <= current {
        return Decision::Current;
    }
    if skipped.and_then(Version::parse).is_some_and(|s| s == version) {
        return Decision::Skipped { version: version.display() };
    }
    Decision::Newer { version: version.display(), tag, url, prerelease }
}

/// The decision as the JSON the App reads.
pub fn to_json(decision: &Decision) -> String {
    let value = match decision {
        Decision::Newer { version, tag, url, prerelease } => serde_json::json!({
            "status": "newer", "version": version, "tag": tag, "url": url, "prerelease": prerelease,
        }),
        Decision::Skipped { version } => serde_json::json!({ "status": "skipped", "version": version }),
        Decision::Current => serde_json::json!({ "status": "current" }),
        Decision::Unreadable => serde_json::json!({ "status": "unreadable" }),
    };
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn parses_tags_and_bundle_versions() {
        assert_eq!(v("v0.1.0"), v("0.1.0"));
        assert_eq!(v("1.2"), v("1.2.0"));
        assert_eq!(v("V2"), v("2.0.0"));
        assert_eq!(v("1.0.0+build.5"), v("1.0.0"));
        assert_eq!(v(" 0.3.1 ").display(), "0.3.1");
        assert_eq!(v("0.2-beta.1").display(), "0.2.0-beta.1");
        for bad in ["", "v", "latest", "1..2", "1.x", "1.0-", "1.0-a..b", "-1.0", "1.2.3.4a"] {
            assert!(Version::parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn orders_numerically_and_prereleases_below_releases() {
        assert!(v("0.10.0") > v("0.9.0"));
        assert!(v("1.0.0") > v("0.99.99"));
        assert!(v("1.0.1") > v("1.0"));
        assert!(v("1.0.0-beta") < v("1.0.0"));
        assert!(v("1.0.0-beta") > v("0.9.9"));
        // SemVer §11's own chain.
        let chain = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
                     "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"];
        for pair in chain.windows(2) {
            assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1]);
        }
    }

    fn release(tag: &str, draft: bool, pre: bool) -> String {
        format!(
            r#"{{"tag_name":"{tag}","html_url":"https://github.com/o/r/releases/tag/{tag}","draft":{draft},"prerelease":{pre},"name":"x","assets":[]}}"#
        )
    }

    fn list(items: &[String]) -> String {
        format!("[{}]", items.join(","))
    }

    #[test]
    fn picks_the_newest_release_including_prereleases() {
        let body = list(&[release("v0.2.0", false, false), release("v0.3.0-beta.1", false, true),
                          release("v0.1.0", false, true)]);
        assert_eq!(
            decide("0.1.0", &body, None),
            Decision::Newer {
                version: "0.3.0-beta.1".into(),
                tag: "v0.3.0-beta.1".into(),
                url: "https://github.com/o/r/releases/tag/v0.3.0-beta.1".into(),
                prerelease: true,
            }
        );
    }

    #[test]
    fn drafts_never_count() {
        let body = list(&[release("v9.0.0", true, false), release("v0.1.0", false, true)]);
        assert_eq!(decide("0.1.0", &body, None), Decision::Current);
    }

    #[test]
    fn same_or_older_is_current() {
        let body = list(&[release("v0.1.0", false, true)]);
        assert_eq!(decide("0.1.0", &body, None), Decision::Current);
        assert_eq!(decide("0.2.0", &body, None), Decision::Current);
        // A beta of the version already installed is older than it.
        let body = list(&[release("v0.2.0-rc.1", false, true)]);
        assert_eq!(decide("0.2.0", &body, None), Decision::Current);
        assert_eq!(decide("0.1.0", "[]", None), Decision::Current);
    }

    #[test]
    fn skipped_version_hides_until_a_later_one() {
        let body = list(&[release("v0.2.0", false, false)]);
        assert_eq!(decide("0.1.0", &body, Some("0.2.0")),
                   Decision::Skipped { version: "0.2.0".into() });
        let body = list(&[release("v0.2.0", false, false), release("v0.3.0", false, false)]);
        assert!(matches!(decide("0.1.0", &body, Some("0.2.0")), Decision::Newer { ref version, .. } if version == "0.3.0"));
    }

    #[test]
    fn non_lists_and_foreign_pages_are_not_releases() {
        // A private repository answers 404 with an object, not a list.
        let not_found = r#"{"message":"Not Found","documentation_url":"https://docs.github.com"}"#;
        assert_eq!(decide("0.1.0", not_found, None), Decision::Unreadable);
        assert_eq!(decide("0.1.0", "<html>login</html>", None), Decision::Unreadable);
        assert_eq!(decide("dev", "[]", None), Decision::Unreadable);
        let foreign = r#"[{"tag_name":"v9.0.0","html_url":"https://evil.example/x","draft":false,"prerelease":false}]"#;
        assert_eq!(decide("0.1.0", foreign, None), Decision::Current);
        let odd_tag = list(&[release("nightly", false, true)]);
        assert_eq!(decide("0.1.0", &odd_tag, None), Decision::Current);
    }

    #[test]
    fn json_for_the_app() {
        let body = list(&[release("v0.2.0", false, false)]);
        let json: serde_json::Value = serde_json::from_str(&to_json(&decide("0.1.0", &body, None))).unwrap();
        assert_eq!(json["status"], "newer");
        assert_eq!(json["version"], "0.2.0");
        assert_eq!(json["url"], "https://github.com/o/r/releases/tag/v0.2.0");
        assert_eq!(json["prerelease"], false);
        assert_eq!(to_json(&Decision::Current), r#"{"status":"current"}"#);
    }
}

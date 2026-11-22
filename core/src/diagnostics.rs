//! Export-only projections. No unknown or free-form text is ever returned.

/// Convert a diagnostic field to fixed labels or bounded numeric metadata.
/// This intentionally does not redact and then return the original string.
pub fn classify(kind: &str, value: &str) -> String {
    match kind {
        "ownState" if value.parse::<i32>().ok() == Some(3) => "等待认证响应".into(),
        "ownState" => classify("state", value),
        "state" => match value.parse::<i32>() {
            Ok(0) => "已断开",
            Ok(1) => "连接中",
            Ok(2) => "认证中",
            Ok(3) => "等待批准",
            Ok(4) => "已连接",
            Ok(5) => "重连中",
            _ => "状态未知",
        }
        .into(),
        "detail" => crate::cisco::diagnostic_detail(value).into(),
        "outcome" => match value {
            "recovered" => "已恢复",
            "failed" => "未恢复",
            "stoppedByUser" => "手动断开",
            "quit" => "退出 App",
            "legacy" => "已恢复（旧记录）",
            _ => "结果未知",
        }
        .into(),
        "engine" => match value {
            "cisco" => "经 Cisco",
            "own" => "自建连接",
            "" => "未记录连接方式",
            _ => "连接方式未知",
        }
        .into(),
        "rule" => match value {
            "app" => "应用",
            "domain" => "域名",
            "network" => "网络",
            _ => "规则类型未知",
        }
        .into(),
        "version" => version(value).unwrap_or_else(|| "未提供".into()),
        "timeline" => crate::cisco::diagnostic_timeline(value),
        "durationSeconds" => duration(value).unwrap_or_default(),
        "isSleepRecord" => match value {
            "true" => "睡眠记录 true",
            "false" => "睡眠记录 false",
            _ => "",
        }
        .into(),
        "sleepDropCount" => sleep_drop_count(value).unwrap_or_default(),
        _ => "已省略".into(),
    }
}

// Export limits, not control policy: retain subsecond downtime and up to ten
// Julian years / one million folded drops. Invalid metadata is omitted.
fn duration(value: &str) -> Option<String> {
    if value.len() > 64 {
        return None;
    }
    let seconds = value.parse::<f64>().ok()?;
    if !seconds.is_finite() || !(0.0..=315_576_000.0).contains(&seconds) {
        return None;
    }
    let seconds = if seconds == 0.0 { 0.0 } else { seconds };
    Some(format!("实际掉线 {seconds} 秒"))
}

fn sleep_drop_count(value: &str) -> Option<String> {
    if value.len() > 16 {
        return None;
    }
    let count = value.parse::<u32>().ok()?;
    (1..=1_000_000)
        .contains(&count)
        .then(|| format!("睡眠期间断开 {count} 次"))
}

fn version(value: &str) -> Option<String> {
    if value.len() > 20 {
        return None;
    }
    let fields: Vec<_> = value.split('.').collect();
    if fields.len() != 3 {
        return None;
    }
    let mut numbers = Vec::new();
    for field in fields {
        if field.is_empty() || !field.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        numbers.push(field.parse::<u16>().ok()?);
    }
    Some(format!("{}.{}.{}", numbers[0], numbers[1], numbers[2]))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn own_wait_state_does_not_assert_phone_approval() {
        assert_eq!(classify("ownState", "3"), "等待认证响应");
        assert_eq!(classify("ownState", "2"), "认证中");
        assert_eq!(classify("state", "3"), "等待批准");
    }

    #[test]
    fn unknown_fields_cannot_echo_arbitrary_payloads() {
        let raw = "RAW_CANARY_7 USER_CANARY_7 203.0.113.73 backup-canary.example GROUP_CANARY_7";
        for kind in [
            "state",
            "detail",
            "outcome",
            "engine",
            "rule",
            "version",
            "timeline",
            "unknown",
            "durationSeconds",
            "isSleepRecord",
            "sleepDropCount",
        ] {
            let text = classify(kind, raw);
            for token in raw.split_whitespace() {
                assert!(!text.contains(token), "{kind}");
            }
        }
    }
    #[test]
    fn history_metadata_is_bounded_and_rebuilt_without_rounding_to_minutes() {
        for (raw, expected) in [
            ("7.0", "7"),
            ("9e2", "900"),
            ("0.375", "0.375"),
            ("-0", "0"),
            ("315576000", "315576000"),
        ] {
            assert_eq!(
                classify("durationSeconds", raw),
                format!("实际掉线 {expected} 秒")
            );
        }
        assert_eq!(classify("sleepDropCount", "0003"), "睡眠期间断开 3 次");
        assert_eq!(
            classify("sleepDropCount", "1000000"),
            "睡眠期间断开 1000000 次"
        );
        assert_eq!(classify("isSleepRecord", "true"), "睡眠记录 true");
        assert_eq!(classify("isSleepRecord", "false"), "睡眠记录 false");
    }
    #[test]
    fn invalid_history_metadata_is_omitted() {
        for raw in [
            "NaN",
            "inf",
            "-inf",
            "-1",
            "315576001",
            "1e999",
            "7 RAW_CANARY_7",
            "",
            &"0".repeat(65),
        ] {
            assert_eq!(classify("durationSeconds", raw), "", "{raw}");
        }
        for raw in [
            "0",
            "-1",
            "1000001",
            "4294967296",
            "1.5",
            "3 RAW_CANARY_7",
            "",
            &"0".repeat(17),
        ] {
            assert_eq!(classify("sleepDropCount", raw), "", "{raw}");
        }
        for raw in ["True", "1", "true RAW_CANARY_7", ""] {
            assert_eq!(classify("isSleepRecord", raw), "");
        }
    }
    #[test]
    fn error_categories_reuse_the_cisco_whitelist_without_raw_text() {
        assert_eq!(
            classify("detail", "Login error: USER_CANARY_7"),
            "登录被拒绝"
        );
        assert_eq!(
            classify(
                "detail",
                "no response from backup-canary.example 203.0.113.73"
            ),
            "未收到应答或连接超时"
        );
        assert_eq!(classify("detail", ">> error: session suspended longer than the allotted time limit requires re-authentication USER_CANARY_7"), "会话挂起超时，需重新认证");
        assert_eq!(classify("version", "000.02.007"), "0.2.7");
        assert_eq!(classify("version", "203.0.113.73"), "未提供");
    }
}

//! Export-only projections. No unknown or free-form text is ever returned.

/// Convert a diagnostic field to fixed labels or bounded numeric metadata.
/// This intentionally does not redact and then return the original string.
pub fn classify(kind: &str, value: &str) -> String {
    match kind {
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
        _ => "已省略".into(),
    }
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
    fn unknown_fields_cannot_echo_arbitrary_payloads() {
        let raw = "RAW_CANARY_7 USER_CANARY_7 203.0.113.73 backup-canary.example GROUP_CANARY_7";
        for kind in [
            "state", "detail", "outcome", "engine", "rule", "version", "timeline", "unknown",
        ] {
            let text = classify(kind, raw);
            for token in raw.split_whitespace() {
                assert!(!text.contains(token), "{kind}");
            }
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

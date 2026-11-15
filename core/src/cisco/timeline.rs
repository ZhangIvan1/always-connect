//! Bounded, memory-only diagnostics. Untrusted CLI text never enters the ring.
use std::cell::Cell;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

const CAPACITY: usize = 200;
const RETENTION: Duration = Duration::from_secs(2 * 3600);
const HEADER: &str = "最近至多 200 条 / 2 小时；时间为距导出的墙钟秒数（含休眠）；仅白名单分类\n";

/// Fixed labels only; neither arguments nor CLI output may be stored here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Operation {
    Intent,
    ConnectRequest,
    DisconnectRequest,
    Refresh,
    State,
    Stats,
    Connect,
    Disconnect,
    Credentials,
    GuiWait,
    GatewayResolution,
    Pause,
    Resume,
    Tick,
    Rearm,
}
impl Operation {
    fn label(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::ConnectRequest => "request-connect",
            Self::DisconnectRequest => "request-disconnect",
            Self::Refresh => "refresh",
            Self::State => "state",
            Self::Stats => "stats",
            Self::Connect => "connect",
            Self::Disconnect => "disconnect",
            Self::Credentials => "credentials",
            Self::GuiWait => "gui-wait",
            Self::GatewayResolution => "gateway-resolution",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Tick => "tick",
            Self::Rearm => "rearm",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Queued,
    Start,
    End,
    Cancel,
    OutputClosed,
    StateChanged,
    Observation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Completed,
    Success,
    Failed,
    Cancelled,
    Term,
    Kill,
    Timeout,
    OutputClosed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CiscoState {
    Connected,
    Reconnecting,
    Disconnected,
    Connecting,
    Authenticating,
    Unknown,
}
impl CiscoState {
    fn parse(value: &str) -> Self {
        match value {
            "Connected" => Self::Connected,
            "Reconnecting" => Self::Reconnecting,
            "Disconnected" => Self::Disconnected,
            "Connecting" => Self::Connecting,
            "Authenticating" => Self::Authenticating,
            _ => Self::Unknown,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ErrorClass {
    SuspendedSessionTimeout,
    ConnectCapabilityUnavailable,
    NameResolution,
    NoResponse,
    LoginRejected,
    LoginFailed,
    Other,
}
impl ErrorClass {
    fn parse(line: &str) -> Option<Self> {
        if line.contains("Login error") {
            return Some(Self::LoginRejected);
        }
        if line.contains("Login failed") {
            return Some(Self::LoginFailed);
        }
        let (_, error) = line.split_once(">> error:")?;
        let error = error.to_ascii_lowercase();
        Some(
            if error.contains("suspended longer than") && error.contains("re-authentication") {
                Self::SuspendedSessionTimeout
            } else if error.contains("connect capability is unavailable") {
                Self::ConnectCapabilityUnavailable
            } else if error.contains("domain name resolution") {
                Self::NameResolution
            } else if error.contains("no response") || error.contains("timed out") {
                Self::NoResponse
            } else {
                Self::Other
            },
        )
    }
}

#[derive(Clone, Copy)]
struct Event {
    at: SystemTime,
    id: u64,
    intent: u32,
    operation: Operation,
    phase: Phase,
    outcome: Outcome,
    state: Option<CiscoState>,
    error: Option<ErrorClass>,
    previous: Option<CiscoState>,
    dwell: Duration,
}
struct Ring {
    next: u64,
    events: VecDeque<Event>,
    // Only enums and clocks: no server, interface, account or CLI strings.
    observed: Option<(CiscoState, SystemTime, SystemTime)>,
}
impl Ring {
    fn trim(&mut self, now: SystemTime) {
        // Wall time includes sleep. On a backwards clock change, discard
        // future-dated entries rather than retaining them beyond the window.
        self.events
            .retain(|e| now.duration_since(e.at).is_ok_and(|age| age <= RETENTION));
        if self.observed.is_some_and(|(_, _, last)| {
            now.duration_since(last).map_or(true, |age| age > RETENTION)
        }) {
            self.observed = None;
        }
    }
    fn push(&mut self, event: Event) {
        self.trim(event.at);
        if self.events.len() == CAPACITY {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }
    fn text(&mut self, now: SystemTime) -> String {
        self.trim(now);
        let mut text = String::from(HEADER);
        for e in &self.events {
            text.push_str(&format!(
                "-{:.3}s #{} intent={} {} {:?} {:?}",
                now.duration_since(e.at).unwrap_or_default().as_secs_f64(),
                e.id,
                e.intent,
                e.operation.label(),
                e.phase,
                e.outcome
            ));
            if let Some(state) = e.state {
                text.push_str(&format!(" state={state:?}"));
            }
            if let Some(error) = e.error {
                text.push_str(&format!(" error={error:?}"));
            }
            if e.phase == Phase::StateChanged {
                text.push_str(&format!(
                    " previous={:?} dwell={:.3}s",
                    e.previous,
                    e.dwell.min(RETENTION).as_secs_f64()
                ));
            }
            text.push('\n');
        }
        if let Some((state, since, _)) = self.observed {
            text.push_str(&format!(
                "last-tick-state={state:?} dwell-within-window={:.3}s\n",
                now.duration_since(since)
                    .unwrap_or_default()
                    .min(RETENTION)
                    .as_secs_f64()
            ));
        }
        text
    }
}

/// A separate short-held lock keeps export available while the worker is busy.
pub(super) struct Recorder(Mutex<Ring>);
impl Recorder {
    pub fn new() -> Self {
        Self(Mutex::new(Ring {
            next: 0,
            events: VecDeque::with_capacity(CAPACITY),
            observed: None,
        }))
    }
    pub fn queued(&self, operation: Operation, intent: u32) -> u64 {
        let mut ring = self.0.lock().unwrap();
        ring.next = ring.next.wrapping_add(1);
        let id = ring.next;
        ring.push(Event {
            at: SystemTime::now(),
            id,
            intent,
            operation,
            phase: Phase::Queued,
            outcome: Outcome::Completed,
            state: None,
            error: None,
            previous: None,
            dwell: Duration::ZERO,
        });
        id
    }
    pub fn start(&self, id: u64, operation: Operation, intent: u32) -> Trace<'_> {
        let trace = Trace {
            recorder: self,
            id,
            operation,
            intent,
            state: Cell::new(None),
            error: Cell::new(None),
            outcome: Cell::new(Outcome::Completed),
        };
        trace.note(Phase::Start, Outcome::Completed);
        trace
    }
    pub fn begin(&self, operation: Operation, intent: u32) -> Trace<'_> {
        self.start(self.queued(operation, intent), operation, intent)
    }
    pub fn observe_state(&self, intent: u32, value: Option<&str>) {
        self.observe_state_at(
            intent,
            CiscoState::parse(value.unwrap_or("Unknown")),
            SystemTime::now(),
        );
    }
    fn observe_state_at(&self, intent: u32, state: CiscoState, now: SystemTime) {
        let mut ring = self.0.lock().unwrap();
        ring.trim(now);
        if let Some((old, _, last)) = ring.observed.as_mut() {
            if *old == state {
                *last = now;
                return;
            }
        }
        let old = ring.observed.replace((state, now, now));
        ring.push(Event {
            at: now,
            id: 0,
            intent,
            operation: Operation::Tick,
            phase: Phase::StateChanged,
            outcome: Outcome::Completed,
            state: Some(state),
            error: None,
            previous: old.map(|(s, _, _)| s),
            dwell: old.map_or(Duration::ZERO, |(_, t, _)| {
                now.duration_since(t).unwrap_or_default()
            }),
        });
    }
    pub fn text(&self) -> String {
        self.0.lock().unwrap().text(SystemTime::now())
    }
}

/// Records completion on every return, including cancellation and stale work.
pub(super) struct Trace<'a> {
    recorder: &'a Recorder,
    id: u64,
    operation: Operation,
    intent: u32,
    state: Cell<Option<CiscoState>>,
    error: Cell<Option<ErrorClass>>,
    outcome: Cell<Outcome>,
}
impl Trace<'_> {
    pub fn note(&self, phase: Phase, outcome: Outcome) {
        self.recorder.0.lock().unwrap().push(Event {
            at: SystemTime::now(),
            id: self.id,
            intent: self.intent,
            operation: self.operation,
            phase,
            outcome,
            state: self.state.get(),
            error: self.error.get(),
            previous: None,
            dwell: Duration::ZERO,
        });
    }
    pub fn cli_line(&self, line: &str) {
        let previous = (self.state.get(), self.error.get());
        if let Some((_, state)) = line.split_once(">> state: ") {
            self.state.set(Some(CiscoState::parse(state.trim())));
        }
        if let Some(error) = ErrorClass::parse(line) {
            self.error.set(Some(error));
        }
        if previous != (self.state.get(), self.error.get()) {
            self.note(Phase::Observation, Outcome::Completed);
        }
    }
    pub fn result(&self, outcome: Outcome) {
        self.outcome.set(outcome);
    }
}
impl Drop for Trace<'_> {
    fn drop(&mut self) {
        self.note(Phase::End, self.outcome.get());
    }
}

/// Export free-form status/history reasons through the same closed error map.
pub(super) fn diagnostic_detail(text: &str) -> &'static str {
    if text.is_empty() {
        return "未记录";
    }
    if text.len() > 8192 {
        return "其他详情已省略";
    }
    let error = ErrorClass::parse(text).or_else(|| ErrorClass::parse(&format!(">> error: {text}")));
    match error {
        Some(ErrorClass::SuspendedSessionTimeout) => "会话挂起超时，需重新认证",
        Some(ErrorClass::ConnectCapabilityUnavailable) => "连接能力不可用",
        Some(ErrorClass::NameResolution) => "域名解析失败",
        Some(ErrorClass::NoResponse) => "未收到应答或连接超时",
        Some(ErrorClass::LoginRejected) => "登录被拒绝",
        Some(ErrorClass::LoginFailed) => "登录失败",
        _ => "其他详情已省略",
    }
}

const STATES: &[&str] = &[
    "Connected",
    "Reconnecting",
    "Disconnected",
    "Connecting",
    "Authenticating",
    "Unknown",
];
const OPERATIONS: &[&str] = &[
    "intent",
    "request-connect",
    "request-disconnect",
    "refresh",
    "state",
    "stats",
    "connect",
    "disconnect",
    "credentials",
    "gui-wait",
    "gateway-resolution",
    "pause",
    "resume",
    "tick",
    "rearm",
];
const PHASES: &[&str] = &[
    "Queued",
    "Start",
    "End",
    "Cancel",
    "OutputClosed",
    "StateChanged",
    "Observation",
];
const OUTCOMES: &[&str] = &[
    "Completed",
    "Success",
    "Failed",
    "Cancelled",
    "Term",
    "Kill",
    "Timeout",
    "OutputClosed",
];
const ERRORS: &[&str] = &[
    "SuspendedSessionTimeout",
    "ConnectCapabilityUnavailable",
    "NameResolution",
    "NoResponse",
    "LoginRejected",
    "LoginFailed",
    "Other",
];
fn fixed(value: &str, allowed: &'static [&'static str]) -> Option<&'static str> {
    allowed.iter().copied().find(|label| *label == value)
}
fn seconds(value: &str) -> Option<f64> {
    let number: f64 = value.strip_suffix('s')?.parse().ok()?;
    (number.is_finite() && (0.0..=RETENTION.as_secs_f64()).contains(&number)).then_some(number)
}
fn export_row(line: &str) -> Option<String> {
    let fields: Vec<_> = line.split_ascii_whitespace().collect();
    if fields.len() == 2 {
        let state = fixed(fields[0].strip_prefix("last-tick-state=")?, STATES)?;
        let dwell = seconds(fields[1].strip_prefix("dwell-within-window=")?)?;
        return Some(format!(
            "last-tick-state={state} dwell-within-window={dwell:.3}s\n"
        ));
    }
    if !(6..=10).contains(&fields.len()) {
        return None;
    }
    let age = seconds(fields[0].strip_prefix('-')?)?;
    let id: u64 = fields[1].strip_prefix('#')?.parse().ok()?;
    let intent: u32 = fields[2].strip_prefix("intent=")?.parse().ok()?;
    let operation = fixed(fields[3], OPERATIONS)?;
    let phase = fixed(fields[4], PHASES)?;
    let outcome = fixed(fields[5], OUTCOMES)?;
    let mut out = format!("-{age:.3}s #{id} intent={intent} {operation} {phase} {outcome}");
    let mut seen = 0;
    for field in &fields[6..] {
        let (key, value) = field.split_once('=')?;
        let (bit, canonical) = match key {
            "state" => (1, format!("state={}", fixed(value, STATES)?)),
            "error" => (2, format!("error={}", fixed(value, ERRORS)?)),
            "previous" => {
                let previous = if value == "None" {
                    "None".to_owned()
                } else {
                    format!(
                        "Some({})",
                        fixed(value.strip_prefix("Some(")?.strip_suffix(')')?, STATES)?
                    )
                };
                (4, format!("previous={previous}"))
            }
            "dwell" => (8, format!("dwell={:.3}s", seconds(value)?)),
            _ => return None,
        };
        if seen & bit != 0 {
            return None;
        }
        seen |= bit;
        out.push(' ');
        out.push_str(&canonical);
    }
    out.push('\n');
    Some(out)
}

/// Rebuild even the timeline field at the export boundary. Unknown formats
/// (including future producer fields) fail closed instead of passing text on.
pub(super) fn sanitize_export(text: &str) -> String {
    let omitted = || "时间线不可用或格式未知（已省略）\n".to_string();
    if text.len() > 64 * 1024 {
        return omitted();
    }
    let mut lines = text.lines();
    if lines.next() != Some(HEADER.trim_end()) {
        return omitted();
    }
    let mut out = HEADER.to_owned();
    let mut count = 0;
    let mut summary = false;
    for line in lines {
        if summary {
            return omitted();
        }
        if line.starts_with("last-tick-state=") {
            summary = true;
        } else {
            count += 1;
        }
        if count > CAPACITY {
            return omitted();
        }
        let Some(row) = export_row(line) else {
            return omitted();
        };
        out.push_str(&row);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn export_rebuilds_real_rows_and_rejects_unknown_text() {
        let recorder = Recorder::new();
        let trace = recorder.begin(Operation::Connect, 3);
        trace.cli_line(">> state: Connected");
        trace.cli_line(">> error: Login failed USER_CANARY_7");
        drop(trace);
        recorder.observe_state(3, Some("Connected"));
        let text = recorder.text();
        assert_eq!(sanitize_export(&text), text);
        assert!(!sanitize_export(&(text.clone() + "RAW_CANARY_7\n")).contains("RAW_CANARY_7"));
        let injected = text.replace("state=Connected", "state=USER_CANARY_7");
        assert!(!sanitize_export(&injected).contains("USER_CANARY_7"));
        assert_eq!(
            sanitize_export("untrusted"),
            "时间线不可用或格式未知（已省略）\n"
        );
    }

    #[test]
    fn capacity_and_retention_are_both_bounded() {
        let recorder = Recorder::new();
        for _ in 0..250 {
            recorder.begin(Operation::Tick, 1);
        }
        let mut ring = recorder.0.lock().unwrap();
        assert_eq!(ring.events.len(), CAPACITY);
        let first = ring.events.front().unwrap().id;
        assert!(first > 1);
        let future = SystemTime::now() + RETENTION + Duration::from_secs(1);
        assert!(!ring.text(future).contains("intent="));
        assert!(ring.events.is_empty());
    }
    #[test]
    fn cli_text_is_never_retained_or_exported() {
        let recorder = Recorder::new();
        let trace = recorder.begin(Operation::Connect, 7);
        for line in [
            ">> state: Connected",
            ">> state: server.private.example alice 198.51.100.88",
            ">> error: server.private.example alice 198.51.100.88 suspended longer than the allotted time limit requires re-authentication",
        ] { trace.cli_line(line); }
        drop(trace);
        let text = recorder.text();
        for secret in [
            "server.private.example",
            "alice",
            "198.51.100.88",
            "allotted time limit",
        ] {
            assert!(!text.contains(secret));
        }
        assert!(text.contains("SuspendedSessionTimeout"));
        assert!(text.contains("state=Unknown"));
    }
    #[test]
    fn phases_and_state_dwell_keep_their_order() {
        let recorder = Recorder::new();
        let id = recorder.queued(Operation::Connect, 4);
        let trace = recorder.start(id, Operation::Connect, 4);
        trace.note(Phase::Cancel, Outcome::Term);
        trace.result(Outcome::Cancelled);
        drop(trace);
        let now = SystemTime::now();
        recorder.observe_state_at(4, CiscoState::Connected, now);
        recorder.observe_state_at(4, CiscoState::Reconnecting, now + Duration::from_secs(3));
        recorder.observe_state_at(4, CiscoState::Disconnected, now + Duration::from_secs(8));
        let mut ring = recorder.0.lock().unwrap();
        assert_eq!(
            ring.events
                .iter()
                .take(4)
                .map(|e| e.phase)
                .collect::<Vec<_>>(),
            [Phase::Queued, Phase::Start, Phase::Cancel, Phase::End]
        );
        let text = ring.text(now + Duration::from_secs(10));
        assert!(text.contains("previous=Some(Connected) dwell=3.000s"));
        assert!(text.contains("previous=Some(Reconnecting) dwell=5.000s"));
        assert!(text.contains("last-tick-state=Disconnected dwell-within-window=2.000s"));
    }
}

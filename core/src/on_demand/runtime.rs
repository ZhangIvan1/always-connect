//! Pure event reducers. Tokens fence late callbacks; actions contain no system I/O.
use super::{decide, transition, Request, Rule, Runtime, Transition};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// One disconnect's lifetime, including the local Cisco stop and status observation.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Disconnect {
    /// A disconnect still needs a confirmed idle observation.
    pub waiting: bool,
    /// Identity of the current operation, never reused by a later begin.
    pub generation: u64,
    /// Identity of the current observation, invalidated by recovery events.
    pub verification: u64,
    /// Local Cisco stop completion has arrived (not an early UI notification).
    pub local_stopped: bool,
    /// One observation is outstanding; no idle polling is scheduled.
    pub checking: bool,
    /// Forced recovery owns the system until cancelled or completed.
    pub suspended: bool,
    /// The bounded observation window starts only after every stop was sent.
    pub expired: bool,
}
impl Disconnect {
    fn current(&self, event: &Value) -> bool {
        self.waiting && event["token"].as_u64() == Some(self.generation)
    }
    fn invalidate(&mut self) {
        self.verification = self.verification.wrapping_add(1);
        self.checking = false;
    }
    fn reconcile(&mut self, actions: &mut Vec<Value>) {
        if self.waiting && self.local_stopped && !self.checking && !self.suspended {
            self.checking = true;
            self.verification = self.verification.wrapping_add(1);
            actions.push(
                json!({"kind":"verify", "token":self.generation, "observation":self.verification, "seconds":6, "cli_seconds":5}),
            );
        }
    }
    fn finish(&mut self, actions: &mut Vec<Value>, uncertain: bool) {
        self.waiting = false;
        self.invalidate();
        actions.push(json!({"kind":"settled"}));
        if uncertain {
            actions.push(json!({"kind":"attention"}));
        }
    }
    /// Prefer confirmed idle; missing observations cannot veto a new connection forever.
    pub fn event(&mut self, event: &Value, actions: &mut Vec<Value>) -> bool {
        match event["kind"].as_str().unwrap_or("") {
            "begin" if !self.waiting => {
                self.generation = self.generation.wrapping_add(1);
                self.waiting = true;
                self.local_stopped = false;
                self.expired = false;
                actions.push(json!({"kind":"stop", "token":self.generation}));
                actions.push(json!({"kind":"deadline", "token":self.generation, "seconds":3}));
            }
            "local_stopped" if self.current(event) => {
                if !self.local_stopped {
                    self.local_stopped = true;
                    actions.push(
                        json!({"kind":"release_deadline", "token":self.generation, "seconds":10}),
                    );
                }
                self.reconcile(actions);
            }
            "reply" if self.current(event) => self.reconcile(actions),
            "deadline" if self.current(event) => {
                // A slow local Cisco stop is not evidence of an unresponsive service.
                self.reconcile(actions);
            }
            "release_deadline" if self.current(event) && self.local_stopped => {
                self.expired = true;
                if !self.suspended {
                    self.finish(actions, true);
                }
            }
            "transport_lost" => {
                self.invalidate();
                if !event["resetting"].as_bool().unwrap_or(false)
                    && (!event["invalidated"].as_bool().unwrap_or(true) || self.waiting)
                {
                    actions.push(json!({"kind":"recover_service", "active":self.waiting || event["active"].as_bool().unwrap_or(false)}));
                }
            }
            "suspend" => {
                self.suspended = true;
                self.invalidate();
            }
            "recover" | "recheck" => {
                if event["kind"] == "recover" {
                    self.suspended = false;
                }
                self.invalidate();
                if self.expired && self.waiting && !self.suspended {
                    self.finish(actions, true);
                } else {
                    self.reconcile(actions);
                }
            }
            "result" | "verify_timeout"
                if self.current(event)
                    && self.checking
                    && event["observation"].as_u64() == Some(self.verification) =>
            {
                self.invalidate();
                let idle = event["kind"] == "result"
                    && event["status"].as_i64() == Some(0)
                    && event["held"].as_bool() == Some(false)
                    && (!event["uses_cisco"].as_bool().unwrap_or(true)
                        || event["cisco"].as_str() == Some("Disconnected"));
                if idle && !self.suspended {
                    self.finish(actions, false);
                }
            }
            "is_current" => return self.current(event),
            _ => (),
        }
        false
    }
}

/// Event-driven policy evaluation and connection intent. Facts and closures live outside Rust.
#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Controller {
    pub policy: Runtime,
    pub enabled: bool,
    pub rules: Vec<Rule>,
    pub ready: bool,
    pub evaluating: bool,
    pub generation: u64,
    pub pending_auto: bool,
    pub pending_resume: bool,
    pub launch_ready: bool,
    pub last_facts: Option<Value>,
    pub collected_facts: Option<Value>,
    pub rule_name: Option<String>,
    pub collecting: bool,
    pub probe_epoch: u64,
    pub pending_probe: Option<String>,
}
impl Default for Controller {
    fn default() -> Self {
        Self {
            policy: Runtime::default(),
            enabled: false,
            rules: vec![],
            ready: false,
            evaluating: false,
            generation: 0,
            pending_auto: false,
            pending_resume: false,
            launch_ready: true,
            last_facts: None,
            collected_facts: None,
            rule_name: None,
            collecting: false,
            probe_epoch: 0,
            pending_probe: None,
        }
    }
}
fn flag(value: &Value, name: &str) -> bool {
    value[name].as_bool().unwrap_or(false)
}
fn offline(mut facts: Value) -> Value {
    facts["probes"] = json!({});
    facts
}
impl Controller {
    fn invalidate(&mut self, actions: &mut Vec<Value>) {
        self.generation = self.generation.wrapping_add(1);
        self.collecting = false;
        self.pending_probe = None;
        actions.push(json!({"kind":"cancel_probe"}));
    }
    fn apply(
        &mut self,
        event: &str,
        action: &str,
        rule_id: Option<String>,
        context: &Value,
        out: &mut Vec<Value>,
    ) {
        let effect = transition(Transition {
            state: self.policy.clone(),
            event: event.into(),
            action: action.into(),
            rule_id,
            active: flag(context, "active"),
            auto_connect: flag(context, "auto_connect"),
        });
        self.policy = effect.state;
        if self.policy.paused {
            self.pending_resume = false;
            self.rule_name = self
                .rules
                .iter()
                .find(|r| Some(&r.id) == self.policy.rule_id.as_ref())
                .map(|r| r.name.clone())
                .or(self.rule_name.take());
        } else {
            self.rule_name = None;
        }
        out.push(json!({"kind":"update_ui"}));
        match effect.effect.as_str() {
            "disconnect" => out.push(json!({"kind":"disconnect"})),
            "connect" => self.pending_resume = true,
            _ => (),
        }
    }
    fn flush(&mut self, context: &Value, out: &mut Vec<Value>) {
        if flag(context, "waiting") {
            if self.pending_resume || self.pending_auto {
                out.push(json!({"kind":"recheck"}));
            }
        } else if self.ready
            && self.launch_ready
            && !self.policy.paused
            && (self.pending_auto || self.pending_resume)
        {
            out.push(json!({"kind":if self.pending_auto {"start_auto"} else {"start"}}));
            self.pending_auto = false;
            self.pending_resume = false;
        }
    }
    fn finish(&mut self, context: &Value, out: &mut Vec<Value>) {
        self.ready = true;
        self.evaluating = false;
        // A paused decision consumes any deferred automatic entry.
        if self.policy.paused {
            self.pending_auto = false;
        }
        self.flush(context, out);
    }
    fn evaluate(&mut self, reason: &str, context: &Value, out: &mut Vec<Value>) {
        self.invalidate(out);
        self.ready = false;
        self.evaluating = true;
        if !self.enabled {
            self.apply("settings", "ignore", None, context, out);
            self.apply("decision", "connect", None, context, out);
            self.finish(context, out);
        } else {
            self.collecting = true;
            out.push(
                json!({"kind":"collect", "reason":reason, "token":self.generation,
                "needs_ssid":self.rules.iter().any(|r| !r.ssids.is_empty())}),
            );
        }
    }
    fn decide(&mut self, facts: Value, context: &Value, out: &mut Vec<Value>) {
        let request = Request {
            enabled: self.enabled,
            rules: self.rules.clone(),
            facts: serde_json::from_value(facts.clone()).unwrap_or_default(),
        };
        let decision = decide(&request);
        if let Some(probe) = decision.probe {
            self.probe_epoch = self.probe_epoch.wrapping_add(1);
            self.pending_probe = decision.rule_id.clone();
            out.push(
                json!({"kind":"probe", "token":self.generation, "probe":probe,
                "facts":facts, "rule_id":decision.rule_id, "probe_epoch":self.probe_epoch}),
            );
        } else {
            self.last_facts = Some(offline(facts));
            self.apply("decision", &decision.action, decision.rule_id, context, out);
            self.finish(context, out);
        }
    }
    fn manual(&mut self, context: &Value, out: &mut Vec<Value>) {
        self.invalidate(out);
        self.evaluating = false;
        self.pending_auto = false;
        self.pending_resume = false;
        self.ready = true;
        self.last_facts = self.collected_facts.clone().or(self.last_facts.take());
        self.apply("manual", "ignore", None, context, out);
    }
    /// Apply events from the shell; all probe/launch/disconnect ordering is decided here.
    pub fn event(&mut self, event: &Value, context: &Value, out: &mut Vec<Value>) -> bool {
        match event["kind"].as_str().unwrap_or("") {
            "configure" => {
                self.enabled = flag(event, "enabled");
                self.rules = serde_json::from_value(event["rules"].clone()).unwrap_or_default();
                self.evaluate("settings", context, out);
            }
            "manual" => self.manual(context, out),
            "user_stop" => {
                self.manual(context, out);
                out.push(json!({"kind":if flag(context,"waiting") {"recheck"} else {"stop_user"}}));
            }
            "manual_request" => {
                self.manual(context, out);
                if flag(context, "waiting") {
                    self.pending_resume = true;
                    self.pending_auto = true;
                    out.push(json!({"kind":"recheck"}));
                } else {
                    out.push(json!({"kind":"start_auto"}));
                }
            }
            "automatic" => {
                if flag(context, "waiting") {
                    if !self.policy.paused {
                        self.pending_resume = true;
                        self.pending_auto = true;
                    }
                    out.push(json!({"kind":"recheck"}));
                } else if !self.ready {
                    self.pending_auto = true;
                    if !self.evaluating {
                        self.evaluate("startup", context, out);
                    }
                } else if !self.policy.paused {
                    self.pending_auto = true;
                    self.flush(context, out);
                }
            }
            "network_will_change" if self.enabled => {
                self.invalidate(out);
                self.ready = false;
                self.evaluating = true;
                out.push(json!({"kind":"debounce", "token":self.generation, "seconds":1.5}));
            }
            "network"
                if event.get("token").is_none()
                    || event["token"].as_u64() == Some(self.generation) =>
            {
                self.evaluate("network", context, out)
            }
            "facts" if self.collecting && event["token"].as_u64() == Some(self.generation) => {
                self.collecting = false;
                let facts = event["facts"].clone();
                if event["reason"] == "network"
                    && self.last_facts.as_ref() == Some(&offline(facts.clone()))
                {
                    self.finish(context, out);
                } else {
                    self.collected_facts = Some(offline(facts.clone()));
                    if let Some(reason @ ("network" | "settings")) = event["reason"].as_str() {
                        self.apply(reason, "ignore", None, context, out);
                    }
                    self.decide(facts, context, out);
                }
            }
            "probe"
                if self.evaluating
                    && event["token"].as_u64() == Some(self.generation)
                    && event["probe_epoch"].as_u64() == Some(self.probe_epoch)
                    && event["rule_id"].as_str() == self.pending_probe.as_deref() =>
            {
                self.pending_probe = None;
                let mut facts = event["facts"].clone();
                if let Some(id) = event["rule_id"].as_str() {
                    facts["probes"][id] = json!(flag(event, "matched"));
                }
                self.decide(facts, context, out);
            }
            "hold_launch" => self.launch_ready = false,
            "launch_finished" => {
                self.launch_ready = true;
                self.pending_resume |= flag(event, "automatic");
                if !self.ready && !self.evaluating {
                    self.evaluate("startup", context, out);
                }
                self.flush(context, out);
            }
            "disconnect_settled" => self.flush(context, out),
            "cancel_resume" => {
                self.pending_resume = false;
                self.pending_auto = false;
            }
            "service_recovered" => {
                out.push(json!({"kind":if flag(context,"waiting") || self.policy.paused {"refresh_service"} else {"recover_service"}}));
            }
            "permit" => return !self.policy.paused,
            _ => (),
        }
        false
    }
}
/// The common FFI envelope: opaque state + event + physical context -> state/actions.
pub fn step(request: Value) -> Value {
    let mut actions = Vec::new();
    let event = &request["event"];
    if request["kind"] == "disconnect" {
        let mut state: Disconnect =
            serde_json::from_value(request["state"].clone()).unwrap_or_default();
        let allowed = state.event(event, &mut actions);
        json!({"state":state,"actions":actions,"allowed":allowed})
    } else {
        let mut state: Controller =
            serde_json::from_value(request["state"].clone()).unwrap_or_default();
        let allowed = state.event(event, &request["context"], &mut actions);
        json!({"state":state,"actions":actions,"allowed":allowed})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn d(state: &mut Disconnect, event: Value) -> Vec<Value> {
        let mut out = vec![];
        state.event(&event, &mut out);
        out
    }
    fn c(state: &mut Controller, event: Value, context: Value) -> Vec<Value> {
        let mut out = vec![];
        state.event(&event, &context, &mut out);
        out
    }
    fn has(out: &[Value], kind: &str) -> bool {
        out.iter().any(|a| a["kind"] == kind)
    }
    fn result(s: &Disconnect, status: i64, held: bool, cisco: Option<&str>) -> Value {
        json!({"kind":"result","token":s.generation,"observation":s.verification,
            "status":status,"held":held,"uses_cisco":cisco.is_some(),"cisco":cisco})
    }
    fn begin(s: &mut Disconnect) -> Vec<Value> {
        assert!(has(&d(s, json!({"kind":"begin"})), "stop"));
        d(s, json!({"kind":"local_stopped","token":s.generation}))
    }
    #[test]
    fn no_reply_deadline_requires_real_idle_and_settles_once() {
        let mut s = Disconnect::default();
        assert!(has(&begin(&mut s), "verify"));
        let token = s.generation;
        let out = d(&mut s, json!({"kind":"deadline","token":token}));
        assert!(!has(&out, "attention"));
        assert!(s.waiting);
        assert!(!has(&out, "settled"));
        let observation = result(&s, 0, false, None);
        assert!(has(&d(&mut s, observation.clone()), "settled"));
        assert!(!s.waiting);
        assert!(d(&mut s, observation).is_empty());
        assert!(d(&mut s, json!({"kind":"reply","token":token})).is_empty());
    }
    #[test]
    fn missing_verification_releases_once_after_local_stop_and_ignores_late_callbacks() {
        let mut s = Disconnect::default();
        let actions = begin(&mut s);
        assert!(has(&actions, "release_deadline"));
        let token = s.generation;
        let late_result = result(&s, 0, false, Some("Disconnected"));
        let actions = d(&mut s, json!({"kind":"release_deadline", "token":token}));
        assert!(has(&actions, "settled"));
        assert!(!s.waiting);
        // Neither callback may dispatch another stop/unload against the new session.
        assert!(d(&mut s, json!({"kind":"reply", "token":token})).is_empty());
        assert!(d(&mut s, late_result).is_empty());
        assert!(d(&mut s, json!({"kind":"release_deadline", "token":token})).is_empty());
        d(&mut s, json!({"kind":"begin"}));
        assert!(d(&mut s, json!({"kind":"release_deadline", "token":token})).is_empty());
        assert!(s.waiting);
    }
    #[test]
    fn slow_local_stop_is_not_helper_failure_and_recovery_owns_expired_release() {
        let mut s = Disconnect::default();
        d(&mut s, json!({"kind":"begin"}));
        let token = s.generation;
        assert!(!has(
            &d(&mut s, json!({"kind":"deadline", "token":token})),
            "attention"
        ));
        assert!(d(&mut s, json!({"kind":"release_deadline", "token":token})).is_empty());
        d(&mut s, json!({"kind":"local_stopped", "token":token}));
        d(&mut s, json!({"kind":"suspend"}));
        assert!(!has(
            &d(&mut s, json!({"kind":"release_deadline", "token":token})),
            "settled"
        ));
        assert!(s.waiting);
        assert!(has(&d(&mut s, json!({"kind":"recover"})), "settled"));
        assert!(!s.waiting);
    }
    #[test]
    fn network_connect_waits_boundedly_then_flushes_one_start_without_auto_connect() {
        let mut s = Controller::default();
        configure(&mut s, false);
        let generation = s.generation;
        c(
            &mut s,
            json!({"kind":"facts", "token":generation, "reason":"settings",
            "facts":{"network":"wifi","ssid":"Example-WiFi"}}),
            json!({}),
        );
        assert!(s.policy.paused && !s.policy.resume);
        c(&mut s, json!({"kind":"network"}), json!({"waiting":true}));
        let generation = s.generation;
        let actions = c(
            &mut s,
            json!({"kind":"facts", "token":generation, "reason":"network",
            "facts":{"network":"wifi","ssid":"Home"}}),
            json!({"waiting":true}),
        );
        assert!(has(&actions, "recheck") && !has(&actions, "start"));
        let mut stop = Disconnect::default();
        begin(&mut stop);
        let token = stop.generation;
        assert!(has(
            &d(&mut stop, json!({"kind":"release_deadline", "token":token})),
            "settled"
        ));
        assert!(has(
            &c(
                &mut s,
                json!({"kind":"disconnect_settled"}),
                json!({"waiting":stop.waiting})
            ),
            "start"
        ));
        assert!(!has(
            &c(&mut s, json!({"kind":"disconnect_settled"}), json!({})),
            "start"
        ));
    }
    #[test]
    fn normal_state_cli_exit_grace_fits_verification_window() {
        let mut s = Disconnect::default();
        let actions = begin(&mut s);
        let verify = actions.iter().find(|a| a["kind"] == "verify").unwrap();
        let seconds = verify["cli_seconds"].as_u64().unwrap();
        assert!(verify["seconds"].as_u64().unwrap() > seconds);
        // The real state command can print Disconnected yet take >2 s to exit.
        // Use a shell substitute, never the installed Cisco CLI in cargo test.
        let reply = crate::cisco::run(
            "/bin/sh",
            &[
                "-c",
                "printf '>> state: Unknown\n>> state: Disconnected\n'; sleep 2.25",
            ],
            None,
            std::time::Duration::from_secs(seconds),
            &mut |_| {},
            &mut |_| {},
        );
        assert_eq!(reply.status, 0);
        assert_eq!(
            crate::cisco::parse_state(&reply.output).as_deref(),
            Some("Disconnected")
        );
    }
    #[test]
    fn active_held_unknown_and_cisco_not_stopped_never_release() {
        for (status, held, cisco) in [
            (1, false, None),
            (0, true, None),
            (-1, false, None),
            (0, false, Some("Connected")),
            (0, false, Some("Unknown")),
        ] {
            let mut s = Disconnect::default();
            begin(&mut s);
            let reply = result(&s, status, held, cisco);
            assert!(!has(&d(&mut s, reply), "settled"));
            assert!(s.waiting);
            assert!(has(&d(&mut s, json!({"kind":"recheck"})), "verify"));
            let reply = result(&s, 0, false, Some("Disconnected"));
            assert!(has(&d(&mut s, reply), "settled"));
        }
    }
    #[test]
    fn local_cisco_stop_fences_status_reads_and_queued_disconnect() {
        let mut s = Disconnect::default();
        d(&mut s, json!({"kind":"begin"}));
        let token = s.generation;
        assert!(!has(
            &d(&mut s, json!({"kind":"reply","token":token})),
            "verify"
        ));
        assert!(!has(&d(&mut s, json!({"kind":"recheck"})), "verify"));
        assert!(s.waiting);
        assert!(has(
            &d(&mut s, json!({"kind":"local_stopped","token":token})),
            "verify"
        ));
        let reply = result(&s, 0, false, Some("Disconnected"));
        assert!(has(&d(&mut s, reply.clone()), "settled"));
        d(&mut s, json!({"kind":"begin"}));
        assert_ne!(token, s.generation);
        assert!(d(&mut s, reply).is_empty());
        assert!(s.waiting);
    }
    #[test]
    fn recovered_transport_supersedes_lost_old_connection_observations() {
        let mut s = Disconnect::default();
        begin(&mut s);
        let old = result(&s, 0, false, None);
        assert!(has(
            &d(&mut s, json!({"kind":"transport_lost"})),
            "recover_service"
        ));
        assert!(has(&d(&mut s, json!({"kind":"recover"})), "verify"));
        assert!(d(&mut s, old).is_empty());
        assert!(s.waiting);
        let current = result(&s, 0, false, None);
        assert!(has(&d(&mut s, current), "settled"));
    }
    #[test]
    fn forced_recovery_cancel_and_complete_both_fence_old_replies() {
        for _finished in [false, true] {
            let mut s = Disconnect::default();
            begin(&mut s);
            let old = result(&s, 0, false, None);
            d(&mut s, json!({"kind":"suspend"}));
            assert!(s.suspended);
            assert!(d(&mut s, old.clone()).is_empty());
            assert!(!has(&d(&mut s, json!({"kind":"recheck"})), "verify"));
            assert!(has(&d(&mut s, json!({"kind":"recover"})), "verify"));
            assert!(d(&mut s, old).is_empty());
            let current = result(&s, 0, false, None);
            assert!(has(&d(&mut s, current), "settled"));
        }
    }
    #[test]
    fn verification_timeout_and_duplicate_replies_cannot_release_new_observation() {
        let mut s = Disconnect::default();
        begin(&mut s);
        let old = result(&s, 0, false, None);
        let timeout =
            json!({"kind":"verify_timeout","token":s.generation,"observation":s.verification});
        d(&mut s, timeout);
        assert!(s.waiting);
        assert!(d(&mut s, old.clone()).is_empty());
        d(&mut s, json!({"kind":"recheck"}));
        assert!(d(&mut s, old).is_empty());
        let current = result(&s, 0, false, None);
        assert!(has(&d(&mut s, current), "settled"));
    }
    #[test]
    fn manual_connection_waits_for_disconnect_and_launch_without_duplicate_start() {
        let mut s = Controller::default();
        let out = c(
            &mut s,
            json!({"kind":"manual_request"}),
            json!({"waiting":true}),
        );
        assert!(has(&out, "recheck"));
        assert!(!has(&out, "start_auto"));
        assert!(s.pending_resume);
        assert!(has(
            &c(
                &mut s,
                json!({"kind":"disconnect_settled"}),
                json!({"waiting":false})
            ),
            "start_auto"
        ));
        assert!(!has(
            &c(&mut s, json!({"kind":"disconnect_settled"}), json!({})),
            "start_auto"
        ));
        s.launch_ready = false;
        s.pending_resume = true;
        assert!(!has(
            &c(&mut s, json!({"kind":"disconnect_settled"}), json!({})),
            "start"
        ));
        assert!(has(
            &c(
                &mut s,
                json!({"kind":"launch_finished","automatic":false}),
                json!({})
            ),
            "start"
        ));
    }
    fn configure(s: &mut Controller, probe: bool) -> Vec<Value> {
        let mut rule =
            json!({"id":"office","name":"Office","ssids":["Example-WiFi"],"action":"disconnect"});
        if probe {
            rule["probe"] = json!({"kind":"dns","target":"intranet.example.com"});
        }
        c(
            s,
            json!({"kind":"configure","enabled":true,"rules":[rule]}),
            json!({"active":true}),
        )
    }
    fn facts(s: &mut Controller, ssid: &str, reason: &str) -> Vec<Value> {
        let event = json!({"kind":"facts","token":s.generation,"reason":reason,"facts":{"ssid":ssid,"probes":{}}});
        c(s, event, json!({"active":true}))
    }
    #[test]
    fn pause_ignore_manual_override_same_network_and_physical_change() {
        let mut s = Controller::default();
        configure(&mut s, false);
        assert!(has(
            &facts(&mut s, "Example-WiFi", "settings"),
            "disconnect"
        ));
        assert!(s.policy.paused);
        assert!(!has(
            &c(&mut s, json!({"kind":"automatic"}), json!({})),
            "start_auto"
        ));
        c(&mut s, json!({"kind":"manual"}), json!({}));
        assert!(!s.policy.paused);
        c(&mut s, json!({"kind":"network"}), json!({}));
        facts(&mut s, "Example-WiFi", "network");
        assert!(s.policy.manual);
        c(&mut s, json!({"kind":"network"}), json!({}));
        facts(&mut s, "Home", "network");
        assert!(!s.policy.manual);
        c(&mut s, json!({"kind":"network"}), json!({}));
        facts(&mut s, "Example-WiFi", "network");
        assert!(s.policy.paused);
        s.rules[0].action = "ignore".into();
        c(&mut s, json!({"kind":"network"}), json!({}));
        facts(&mut s, "Home", "network");
        // An unmatched ignore still falls through to connect; an explicitly matching ignore retains a pause.
        s.policy.paused = true;
        s.rules[0].ssids = vec!["Other".into()];
        c(&mut s, json!({"kind":"network"}), json!({}));
        facts(&mut s, "Other", "network");
        assert!(s.policy.paused);
    }
    #[test]
    fn debounce_cancels_stale_facts_probe_and_duplicate_probe_replies() {
        let mut s = Controller::default();
        configure(&mut s, true);
        let probe = facts(&mut s, "Example-WiFi", "settings")
            .into_iter()
            .find(|a| a["kind"] == "probe")
            .unwrap();
        let event = json!({"kind":"probe","token":probe["token"],"probe_epoch":probe["probe_epoch"],
            "rule_id":probe["rule_id"],"facts":probe["facts"],"matched":true});
        let debounce = c(&mut s, json!({"kind":"network_will_change"}), json!({}));
        assert!(has(&debounce, "debounce"));
        assert!(c(&mut s, event.clone(), json!({})).is_empty());
        assert!(!has(
            &c(&mut s, json!({"kind":"automatic"}), json!({})),
            "start_auto"
        ));
        let stale = json!({"kind":"network","token":s.generation});
        c(&mut s, json!({"kind":"manual"}), json!({}));
        assert!(c(&mut s, stale, json!({})).is_empty());
        configure(&mut s, true);
        let probe = facts(&mut s, "Example-WiFi", "settings")
            .into_iter()
            .find(|a| a["kind"] == "probe")
            .unwrap();
        let event = json!({"kind":"probe","token":probe["token"],"probe_epoch":probe["probe_epoch"],
            "rule_id":probe["rule_id"],"facts":probe["facts"],"matched":true});
        assert!(has(
            &c(&mut s, event.clone(), json!({"active":true})),
            "disconnect"
        ));
        assert!(c(&mut s, event, json!({})).is_empty());
    }
    #[test]
    fn disabled_settings_do_not_collect_and_restore_intent_waits_for_idle() {
        let mut s = Controller::default();
        configure(&mut s, false);
        facts(&mut s, "Example-WiFi", "settings");
        let out = c(
            &mut s,
            json!({"kind":"configure","enabled":false,"rules":[]}),
            json!({"waiting":true}),
        );
        assert!(!has(&out, "collect"));
        assert!(!s.policy.paused);
        assert!(s.pending_resume);
        assert!(!has(&out, "start"));
        assert!(has(&out, "recheck"));
        assert!(has(
            &c(&mut s, json!({"kind":"disconnect_settled"}), json!({})),
            "start"
        ));
    }
    #[test]
    fn force_restore_and_user_stop_cancel_deferred_resume() {
        let mut s = Controller::default();
        c(
            &mut s,
            json!({"kind":"manual_request"}),
            json!({"waiting":true}),
        );
        c(&mut s, json!({"kind":"cancel_resume"}), json!({}));
        assert!(!s.pending_resume && !s.pending_auto);
        assert!(!has(
            &c(&mut s, json!({"kind":"disconnect_settled"}), json!({})),
            "start"
        ));
        let out = c(&mut s, json!({"kind":"user_stop"}), json!({"waiting":true}));
        assert!(has(&out, "recheck"));
        assert!(!has(&out, "stop_user"));
        assert!(has(
            &c(&mut s, json!({"kind":"user_stop"}), json!({})),
            "stop_user"
        ));
    }
    #[test]
    fn restored_service_does_not_bypass_pause_or_disconnect_fence() {
        for waiting in [true, false] {
            let mut s = Controller::default();
            s.policy.paused = !waiting;
            let out = c(
                &mut s,
                json!({"kind":"service_recovered"}),
                json!({"waiting":waiting}),
            );
            assert!(has(&out, "refresh_service"));
            assert!(!has(&out, "recover_service"));
        }
    }
}

#[cfg(test)]
mod controller_sequences {
    use super::*;
    fn send(s: &mut Controller, e: Value, active: bool, auto: bool) -> Vec<Value> {
        let mut out = vec![];
        s.event(&e, &json!({"active":active,"auto_connect":auto}), &mut out);
        out
    }
    fn has(out: &[Value], kind: &str) -> bool {
        out.iter().any(|a| a["kind"] == kind)
    }
    fn facts(s: &mut Controller, ssid: &str, reason: &str, active: bool, auto: bool) -> Vec<Value> {
        send(
            s,
            json!({"kind":"facts","token":s.generation,"reason":reason,
            "facts":{"ssid":ssid,"probes":{}}}),
            active,
            auto,
        )
    }
    fn rules(s: &mut Controller, active: bool) {
        send(
            s,
            json!({"kind":"configure","enabled":true,"rules":[
            {"id":"a","name":"Office","action":"disconnect","ssids":["Example-WiFi"]}]}),
            active,
            false,
        );
    }
    #[test]
    fn startup_automatic_calls_coalesce_and_wait_for_facts_and_launch() {
        let mut s = Controller::default();
        s.launch_ready = false;
        rules(&mut s, false);
        for _ in 0..5 {
            assert!(!has(
                &send(&mut s, json!({"kind":"automatic"}), false, true),
                "start_auto"
            ));
        }
        assert!(!has(
            &facts(&mut s, "Home", "settings", false, true),
            "start_auto"
        ));
        assert!(has(
            &send(&mut s, json!({"kind":"launch_finished"}), false, true),
            "start_auto"
        ));
        assert!(!has(
            &send(&mut s, json!({"kind":"disconnect_settled"}), false, true),
            "start_auto"
        ));
    }
    #[test]
    fn leaving_trusted_network_resumes_even_if_pause_preceded_login() {
        for active in [false, true] {
            let mut s = Controller::default();
            rules(&mut s, active);
            facts(&mut s, "Example-WiFi", "settings", active, false);
            send(&mut s, json!({"kind":"network"}), false, false);
            assert_eq!(
                has(&facts(&mut s, "Home", "network", false, false), "start"),
                true
            );
        }
    }
    #[test]
    fn disabled_configuration_never_reads_and_repeated_events_do_not_poll() {
        let mut s = Controller::default();
        for kind in [
            "configure",
            "network",
            "network_will_change",
            "disconnect_settled",
        ] {
            let out = send(
                &mut s,
                json!({"kind":kind,"enabled":false,"rules":[]}),
                false,
                false,
            );
            assert!(!has(&out, "collect") && !has(&out, "probe") && !has(&out, "debounce"));
        }
    }
    #[test]
    fn manual_during_probe_and_duplicate_facts_do_not_undo_override() {
        let mut s = Controller::default();
        rules(&mut s, true);
        s.rules[0].probe = Some(super::super::Probe {
            kind: "dns".into(),
            target: "intranet.example.com".into(),
        });
        let old_facts = json!({"kind":"facts","token":s.generation,"reason":"settings","facts":{"ssid":"Example-WiFi","probes":{}}});
        let out = send(&mut s, old_facts.clone(), true, false);
        let p = out.into_iter().find(|a| a["kind"] == "probe").unwrap();
        assert!(send(&mut s, old_facts, true, false).is_empty());
        send(&mut s, json!({"kind":"manual"}), true, false);
        let late = json!({"kind":"probe","token":p["token"],"probe_epoch":p["probe_epoch"],"rule_id":p["rule_id"],"facts":p["facts"],"matched":true});
        assert!(send(&mut s, late, true, false).is_empty());
        assert!(s.policy.manual && !s.policy.paused);
    }
}

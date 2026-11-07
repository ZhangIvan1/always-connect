import Foundation

/// Shared XPC contract between the App and the privileged Helper
/// (DESIGN.md §16.1/§16.9). This file is compiled into BOTH targets
/// (Sources/Shared is in the App's and the Helper's source lists),
/// so the protocol, service name, and state codes cannot drift apart.
///
/// State codes match the Rust session driver (ffi.rs encode_state):
///   0 Disconnected, 1 Connecting, 2 Authenticating,
///   3 AwaitingApproval, 4 Connected, 5 Reconnecting.
/// There is no seventh state: a credentials rejection is reported as
/// the error detail on a terminal callback, not as a state.

let AlwaysConnectHelperMachService = "com.alwaysconnect.app.helper"

/// App -> Helper. All methods carry a reply block, as NSXPC requires
/// for two-way calls.
@objc protocol AlwaysConnectHelperProtocol {
    /// Start (or restart) a session. Credentials travel over XPC and
    /// live only in Helper memory; they are never written to disk.
    /// Reply: true when the engine accepted the request.
    func connect(
        server: String,
        group: String,
        username: String,
        password: String,
        withReply reply: @escaping (Bool) -> Void
    )
    /// User-confirmed manual disconnect: stop the CLI, restore the
    /// local network, unload pf.
    func disconnect(withReply reply: @escaping () -> Void)
    /// Current state code + human-readable detail (reason + next step,
    /// never a raw error dump, never a credential).
    func getStatus(withReply reply: @escaping (Int, String) -> Void)
    /// Rule tester (DESIGN.md §十八): evaluate one input against a
    /// rule set with the Rust engine. rulesJSON is a JSON array of
    /// Rule; defaultMode is 0 = secure, 1 = split. Reply: direction
    /// code (0 = VPN, 1 = direct, -1 = bad input) + reason code
    /// (see rules::resolve). The App passes its rules explicitly so
    /// the root daemon never has to read the user's App Groups
    /// container, which it cannot reliably resolve.
    func evaluateRule(
        app: String,
        domain: String,
        ip: String,
        rulesJSON: String,
        defaultMode: Int,
        withReply reply: @escaping (Int, String) -> Void
    )
    /// Traffic counters for the Statistics page: bytes in/out on the
    /// tunnel interface, plus the interface name ("" when down).
    func getStats(withReply reply: @escaping (Int64, Int64, String) -> Void)
    /// Leak self-check (UI-DESIGN.md §五诊断页): JSON array of
    /// {item, passed, detail}. Items: default route via tunnel, pf
    /// anchor loaded, gateway reachable via the physical interface,
    /// plus a tunnel-DNS verdict: the engine compares the tunnel DNS
    /// set plumbed from the connect hook against the system resolver
    /// list (DESIGN.md §十九). When the gateway never sent a DNS
    /// set, the DNS row is informational, not a verdict.
    func runLeakCheck(withReply reply: @escaping (String) -> Void)
    /// Live pf allowlist update (DESIGN.md §十九): replace the
    /// networks the connected/blocking pf sets let out directly.
    /// The App calls this right after connect accepts and whenever
    /// the user edits the list in Settings; the Helper reloads the
    /// currently loaded pf set with the new list, no reconnect.
    /// Reply: true when an engine is running and the list was
    /// applied (invalid CIDRs are dropped by the Helper).
    func updateAllowNetworks(_ networks: [String], withReply reply: @escaping (Bool) -> Void)
    /// Session info for the panel and notifications (DESIGN.md
    /// §十九): terminal reason code (0 = none/ongoing, 1 = manual
    /// stop, 2 = credentials rejected, 3 = attempts exhausted,
    /// 4 = trusted bundled component missing) and
    /// retries in the current drop episode (0 when connected or
    /// never dropped). The App queries this after a push lands on
    /// Reconnecting or on a terminal Disconnected, so the panel's
    /// retry count and the rejection notification rest on a code,
    /// never on matching free-form detail text.
    func getSessionInfo(withReply reply: @escaping (Int, Int) -> Void)
    /// Whether the local network is still held closed (DESIGN.md
    /// §20.9): pf state or route state left on disk by a session that
    /// no manual disconnect has undone. True while connected too; the
    /// App uses it when the state is Disconnected — after credentials
    /// were rejected mid-drop, or after a Helper restart reloaded the
    /// blocking set — to offer the manual disconnect that restores
    /// the network instead of showing "本地网络" while still blocked.
    func getNetworkHeld(withReply reply: @escaping (Bool) -> Void)
    /// Kill switch for a tunnel the Helper does not run (Cisco engine,
    /// DESIGN.md §二十一). mode: 0 = off (manual disconnect: unload
    /// pf), 1 = connected (tunnel up: connected set; the Helper also
    /// blocks by itself if tunnelIf disappears), 2 = blocking (tunnel
    /// lost: blocking set + DNS so the session can be re-established).
    /// Empty tunnelIf/gatewayIps keep the last known values.
    /// Reply: (applied, message for the panel's red pf line).
    func setKillSwitch(_ mode: Int, tunnelIf: String, gatewayIps: [String],
                       withReply reply: @escaping (Bool, String) -> Void)
    /// Own-connection engine (DESIGN.md §二十三): the next connect goes
    /// through the App's certificate relay on 127.0.0.1. gatewayIp is
    /// the gateway IPv4 the relay pinned, serverPin the relay's
    /// listener pin (pin-sha256:...). Empty gatewayIp = connect
    /// straight to the gateway again. Reply: the PEM certificate
    /// openconnect will present to the relay (the relay accepts no
    /// other client); "" when the settings were invalid or the
    /// certificate could not be made, and after a clear.
    func prepareRelay(gatewayIp: String, serverPin: String,
                      withReply reply: @escaping (String) -> Void)
    /// Own connection's domain split (DESIGN.md §26.5): the names (and
    /// their subdomains) that go out the local network. Takes effect at
    /// once in a running session, else at the next connect. Reply: true.
    func setDirectDomains(_ domains: [String], withReply reply: @escaping (Bool) -> Void)
    /// What the split did in the running session (DESIGN.md §26.12): the
    /// list entries looked up so far (latest first, at most 20), how
    /// many addresses went out the local network, and whether an
    /// own-connection engine exists at all.
    func getSplitActivity(withReply reply: @escaping ([String], Int, Bool) -> Void)
    /// Live connections (DESIGN.md §28.7): JSON [ConnectionRow].
    func getConnections(withReply reply: @escaping (String) -> Void)
    /// 断线保护 for the own connection (DESIGN.md §26.19): false = the
    /// engine loads no pf set and a drop gives the local network back
    /// while it retries. In force at once in a running session, else
    /// from the next connect. The Cisco engine's switch stays App-side
    /// (setKillSwitch mode 0). Reply: true.
    func setDropProtection(_ on: Bool, withReply reply: @escaping (Bool) -> Void)
    /// Why the network gate last let go on its own (DESIGN.md §25.2):
    /// "app-gone" (no App came back within the grace period after a
    /// crash), "reboot", "upgrade"; "" when it never did. at = seconds
    /// since 1970. The App tells the user once, at its next launch.
    func getLastRelease(withReply reply: @escaping (String, Double) -> Void)
}

/// Upgrade safety for the additive methods above (evaluateRule,
/// getStats, runLeakCheck, updateAllowNetworks, getSessionInfo,
/// getNetworkHeld, setKillSwitch, prepareRelay, getLastRelease,
/// setDirectDomains, getSplitActivity, setDropProtection, getConnections):
/// the Helper is installed independently of the App, so a new App
/// may talk to an old Helper that never replies to them. The App
/// therefore wraps every call in a 3-second timeout and falls back
/// to a "Helper 版本过旧" message instead of hanging. The original
/// three methods (connect/disconnect/getStatus) are unchanged since
/// Phase 1 and need no such guard.

/// Helper -> App. Fire-and-forget pushes (no reply block): the Helper
/// reports every state change the moment it happens; the App never
/// polls.
@objc protocol AlwaysConnectHelperClientProtocol {
    func statusChanged(state: Int, detail: String)
}

import Darwin
import Foundation

/// The kill switch for the Cisco engine's tunnel (DESIGN.md §二十一): the
/// App reports what it sees and the network gate holds the matching set;
/// while connected the tunnel interface is watched, so a drop is blocked
/// within seconds even with no App. Rust (core/src/kill_switch.rs, §32.12);
/// this is the shell with the interface the service always used.
final class KillSwitch {
    static let shared = KillSwitch()

    enum Mode: Int {
        case off = 0
        case connected = 1
        case blocking = 2
    }

    /// Keeps the App's requests in order (a set queued before a disarm
    /// never lands after it), as the Swift kill switch's queue did.
    private let queue = DispatchQueue(label: "com.alwaysconnect.helper.killswitch")

    private init() { _ = NetworkGuard.shared }

    /// Reply: (applied, message). On failure the message is what the
    /// panel's red pf line shows.
    func set(mode: Mode, tunnelIf: String, gatewayIps: [String],
             reply: @escaping (Bool, String) -> Void) {
        queue.async {
            var ok = false
            let message = NetworkGuard.take(ac_ks_set(Int32(mode.rawValue), tunnelIf,
                                                      gatewayIps.joined(separator: ","), &ok)) ?? ""
            reply(ok, message)
        }
    }

    func updateAllowNetworks(_ networks: [String]) {
        queue.async { ac_ks_update_allow_networks(networks.joined(separator: ",")) }
    }

    var isOff: Bool { queue.sync { ac_ks_is_off() } }

    /// What the leak check needs to inspect the Cisco engine's tunnel.
    var snapshot: (tunnelIf: String, gatewayIps: [String], physicalIf: String)? {
        guard let text = queue.sync(execute: { NetworkGuard.take(ac_ks_snapshot()) }) else { return nil }
        let parts = text.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3 else { return nil }
        return (parts[0], parts[1].split(separator: ",").map(String.init), parts[2])
    }

    /// Forget the session, stop watching, release the Cisco hold.
    /// Synchronous, so a caller that releases next never races a load.
    func disarm() { queue.sync { ac_ks_disarm() } }
}

/// IPv4 or IPv6 literal (inet_pton), the only gateway form pf accepts.
func isValidIP(_ value: String) -> Bool {
    var v4 = in_addr()
    var v6 = in6_addr()
    return inet_pton(AF_INET, value, &v4) == 1 || inet_pton(AF_INET6, value, &v6) == 1
}

@_silgen_name("ac_ks_set")
func ac_ks_set(_ mode: Int32, _ tunnelIf: UnsafePointer<CChar>, _ gateways: UnsafePointer<CChar>,
               _ ok: UnsafeMutablePointer<Bool>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_ks_update_allow_networks") func ac_ks_update_allow_networks(_ n: UnsafePointer<CChar>)
@_silgen_name("ac_ks_is_off") func ac_ks_is_off() -> Bool
@_silgen_name("ac_ks_snapshot") func ac_ks_snapshot() -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_ks_disarm") func ac_ks_disarm()

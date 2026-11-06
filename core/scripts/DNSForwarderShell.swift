import Darwin
import Foundation
// The DNS forwarder harness drives the Rust forwarder (core/src/dns_forwarder.rs)
// through this shell; the service uses the forwarder from the Rust engine directly.

/// Domain split, the DNS half (DESIGN.md §26.4, §26.13, §28.3). The
/// forwarder itself — listening, rule matching, upstream exchanges, the
/// address → name memory — is Rust (core/src/dns_forwarder.rs, §32.6:
/// resident logic lives in Rust). This is the Swift shell the
/// orchestrator talks to; its interface is the one the Swift forwarder
/// had, so the session's behaviour is unchanged:
///
/// - A direct name is asked of the local DNS through the physical
///   interface; `onDirect` gets the list entry and its IPv4 addresses
///   before the answer is returned and must return only once they are
///   routed direct (host routes, the network gate's direct table).
/// - Every other name goes to the tunnel's DNS (UDP, then TCP); one whose
///   answer falls in an ipcidr: range is reported the same way.
/// - AAAA answers are empty for every name; HTTPS too for direct names.
final class DNSForwarder {
    struct Config {
        var listenAddress = "127.0.0.1"
        var port: UInt16 = 53
        /// The tunnel's DNS servers (connect hook), for every other name.
        var tunnelServers: [String]
        /// The local network's DNS servers, for direct names.
        var localServers: [String]
        /// Bind the local queries to this interface (the default route
        /// is the tunnel). Nil in tests, where everything is loopback.
        var physicalIf: String?
        /// Upstream port (53; tests use their own).
        var upstreamPort: UInt16 = 53
        var timeout: TimeInterval = 2
    }

    /// Holds the hook for the Rust side, which keeps it (retained) until
    /// its last query in flight has finished, even after this shell is
    /// gone.
    private final class Hook {
        private let lock = NSLock()
        private var handler: ((String, [String]) -> Void)?
        func set(_ h: ((String, [String]) -> Void)?) { lock.lock(); handler = h; lock.unlock() }
        func call(_ entry: String, _ ips: [String]) {
            lock.lock(); let h = handler; lock.unlock()
            h?(entry, ips)
        }
    }

    /// Called with the list entry a direct name matched and its IPv4
    /// addresses before the answer is returned; must return only once
    /// they are routed direct.
    var onDirect: ((String, [String]) -> Void)? {
        didSet { hook.set(onDirect) }
    }

    private let hook = Hook()
    /// The Rust forwarder (the connections page reads its name memory).
    let handle: OpaquePointer

    init(config: Config, directDomains: [String]) {
        let ctx = Unmanaged.passRetained(hook).toOpaque()
        let direct: @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<CChar>?, UnsafePointer<CChar>?) -> Void = {
            ctx, entry, ips in
            guard let ctx, let entry, let ips else { return }
            let list = String(cString: ips).split(separator: ",").map(String.init)
            Unmanaged<Hook>.fromOpaque(ctx).takeUnretainedValue().call(String(cString: entry), list)
        }
        let release: @convention(c) (UnsafeMutableRawPointer?) -> Void = { ctx in
            if let ctx { Unmanaged<Hook>.fromOpaque(ctx).release() }
        }
        guard let handle = ac_dns_new(config.listenAddress, config.port, config.upstreamPort,
                                      UInt32(max(0, config.timeout * 1000)), direct, release, ctx) else {
            fatalError("DNSForwarder: bad listen address \(config.listenAddress)")
        }
        self.handle = handle
        update(directDomains: directDomains)
        update(tunnelServers: config.tunnelServers, localServers: config.localServers,
               physicalIf: config.physicalIf)
    }

    deinit {
        ac_dns_stop(handle)
        ac_dns_free(handle)
    }

    func update(directDomains: [String]) {
        ac_dns_set_rules(handle, directDomains.joined(separator: "\n"))
    }

    func update(tunnelServers: [String], localServers: [String], physicalIf: String?) {
        ac_dns_set_upstreams(handle, tunnelServers.joined(separator: ","),
                             localServers.joined(separator: ","), physicalIf)
    }

    func name(for ip: String) -> String? {
        guard let raw = ac_dns_name_for(handle, ip) else { return nil }
        defer { ac_string_free(raw) }
        return String(cString: raw)
    }

    /// Listens on UDP and TCP; throws when the port is taken (another
    /// DNS proxy), and the session then runs without the split.
    func start() throws {
        let code = ac_dns_start(handle)
        guard code == 0 else { throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO) }
    }

    /// Stops listening; the port is free on return.
    func stop() {
        ac_dns_stop(handle)
    }
}

// The Rust side (core/src/ffi.rs). Declared here because the Helper
// links the staticlib without a bridging header (as PfAnchor does).
@_silgen_name("ac_dns_new")
func ac_dns_new(_ listen: UnsafePointer<CChar>, _ port: UInt16, _ upstreamPort: UInt16, _ timeoutMs: UInt32,
                _ direct: (@convention(c) (UnsafeMutableRawPointer?, UnsafePointer<CChar>?, UnsafePointer<CChar>?) -> Void)?,
                _ release: (@convention(c) (UnsafeMutableRawPointer?) -> Void)?,
                _ ctx: UnsafeMutableRawPointer?) -> OpaquePointer?
@_silgen_name("ac_dns_start")
func ac_dns_start(_ f: OpaquePointer) -> Int32
@_silgen_name("ac_dns_stop")
func ac_dns_stop(_ f: OpaquePointer)
@_silgen_name("ac_dns_free")
func ac_dns_free(_ f: OpaquePointer)
@_silgen_name("ac_dns_set_rules")
func ac_dns_set_rules(_ f: OpaquePointer, _ rules: UnsafePointer<CChar>)
@_silgen_name("ac_dns_set_upstreams")
func ac_dns_set_upstreams(_ f: OpaquePointer, _ tunnel: UnsafePointer<CChar>, _ local: UnsafePointer<CChar>,
                          _ physicalIf: UnsafePointer<CChar>?)
@_silgen_name("ac_dns_name_for")
func ac_dns_name_for(_ f: OpaquePointer, _ ip: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

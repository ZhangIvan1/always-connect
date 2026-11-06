import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Network
import os
import Security

/// Certificate relay for the own-connection engine (DESIGN.md §二十三,
/// proven by the PoC in §22.5–§22.14).
///
/// The company gateway demands a client certificate whose private key
/// sits in the login keychain and cannot be exported, so openconnect
/// (root, in the Helper) cannot present it. This relay runs in the App,
/// inside the user's session where the keychain identity is usable:
///
///     openconnect --resolve host:127.0.0.1 --servercert <pin>
///         └─ local mutual TLS ─▶ relay (127.0.0.1:<gateway port>)
///                                  └─ TLS with the keychain identity
///                                     ─▶ gateway's pinned IPv4, same SNI
///
/// - The private key never leaves the keychain: Network.framework asks
///   it to sign the handshake.
/// - The local side is mutual TLS on loopback: a throwaway listener
///   identity (openconnect pins its public key) and the client
///   certificate the Helper generated for openconnect (anything else is
///   refused), so no other local process can ride the user's identity.
/// - One gateway IPv4 per session: the Helper needs it for the host
///   route and pf (openconnect itself only ever sees 127.0.0.1).
/// - After the CSTP CONNECT is answered 200, each direction is cut back
///   into whole CSTP packets and every packet goes out as its own TLS
///   write: CSTP reads one packet per TLS record, and a plain byte relay
///   merges or splits them (§22.13; measured both ways).
/// - The data channel (DTLS) needs no client certificate: openconnect
///   and the gateway resume a session from the master secret the CSTP
///   CONNECT carries. So the CONNECT answer's X-DTLS-Port is pointed at
///   a local UDP port and the datagrams are forwarded as they are, off
///   the tunnel; PSK-NEGOTIATE (keys bound to each TLS leg) is dropped
///   from the offer (§26.10). Without DTLS everything rode one TCP
///   connection and melted down under load (§26.9).
/// - Nothing here logs request bodies, cookies or addresses.
///
/// Split of work (DESIGN.md §32.7, resident logic in Rust): this file
/// keeps what needs Apple frameworks — the keychain identity, both TLS
/// legs (Network.framework), the listener and the network watch. The
/// plaintext side of each pair (request/answer headers, CSTP packets,
/// the login trace), the DTLS datagram channel and the gateway address
/// choice are Rust (core/src/relay.rs), called through ac_relay_*.
final class CertificateRelay {
    struct ClientIdentity {
        let identity: SecIdentity
        let name: String
        let expires: Date?
        let issued: Date?
        /// Subject and issuer are the same: a device's own identity
        /// (e.g. the MDM enrolment one), never a VPN login certificate.
        let selfSigned: Bool
        /// SHA-256 of the certificate, the stable key saved in settings.
        let digest: String
    }

    struct Prepared {
        let gatewayIp: String
        /// openconnect --servercert value for the listener identity.
        let serverPin: String
        /// Every IPv4 address the gateway's name had (§30.6).
        var addresses: [String] = []
    }

    /// Called on the relay queue after several connections in a row
    /// found the gateway address silent (§30.6), with that address.
    var onGatewayUnreachable: ((String) -> Void)?
    private var silentHandshakes = 0

    enum RelayError: LocalizedError {
        case unsupportedSystem
        case noIdentity
        case badAddress
        case unresolved
        case certificate
        case listener(String)

        var errorDescription: String? {
            switch self {
            case .unsupportedSystem: return "自建连接需要 macOS 15 或更新"
            case .noIdentity: return "钥匙串里没有可用的公司证书，请在设置里选择证书"
            case .badAddress: return "服务器地址无效"
            case .unresolved: return "解析不到网关地址，请检查网络"
            case .certificate: return "生成本地临时证书失败"
            case .listener(let reason): return reason
            }
        }
    }

    private static let log = Logger(subsystem: "com.alwaysconnect.app", category: "relay")

    let host: String
    let port: UInt16
    private let clientIdentity: SecIdentity
    private let upstreamPort: UInt16
    private let anchor: SecCertificate?
    private let queue = DispatchQueue(label: "com.alwaysconnect.app.relay")
    private var listenerIdentity: sec_identity_t?
    private var gatewayIp: String?
    private var listener: NWListener?
    private var pairs: [ObjectIdentifier: Pair] = [:]
    private var pairCount = 0

    /// `upstreamPort` and `anchor` exist for the harness only (a mock
    /// gateway on another loopback port, trusted through its test CA);
    /// the App keeps the gateway's own port and the system trust store.
    init(host: String, port: UInt16, identity: SecIdentity,
         upstreamPort: UInt16? = nil, anchor: SecCertificate? = nil) {
        self.host = host
        self.port = port
        self.clientIdentity = identity
        self.upstreamPort = upstreamPort ?? port
        self.anchor = anchor
    }

    // MARK: - Keychain identities

    /// Client-authentication identities in the keychain, without
    /// touching their private keys (no prompt).
    static func clientIdentities() -> [ClientIdentity] {
        let context = LAContext()
        context.interactionNotAllowed = true
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true,
            kSecMatchPolicy as String: SecPolicyCreateSSL(false, nil),
            kSecMatchValidOnDate as String: Date(),
            kSecUseAuthenticationContext as String: context,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let entries = result as? [SecIdentity] else { return [] }
        let clientAuth = Data([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02])
        var seen = Set<String>()
        return entries.compactMap { identity in
            var certificate: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess,
                  let certificate,
                  let values = SecCertificateCopyValues(
                    certificate,
                    [kSecOIDExtendedKeyUsage, kSecOIDX509V1ValidityNotAfter,
                     kSecOIDX509V1ValidityNotBefore] as CFArray,
                    nil) as? [String: Any],
                  let eku = values[kSecOIDExtendedKeyUsage as String] as? [String: Any],
                  let usages = eku[kSecPropertyKeyValue as String] as? [Data],
                  usages.contains(clientAuth)
            else { return nil }
            let digest = SHA256.hash(data: SecCertificateCopyData(certificate) as Data)
                .map { String(format: "%02x", $0) }.joined()
            guard seen.insert(digest).inserted else { return nil }
            func date(_ oid: CFString) -> Date? {
                ((values[oid as String] as? [String: Any])?[kSecPropertyKeyValue as String] as? NSNumber)
                    .map { Date(timeIntervalSinceReferenceDate: $0.doubleValue) }
            }
            let subject = SecCertificateCopyNormalizedSubjectSequence(certificate) as Data?
            let issuer = SecCertificateCopyNormalizedIssuerSequence(certificate) as Data?
            return ClientIdentity(
                identity: identity,
                name: SecCertificateCopySubjectSummary(certificate) as String? ?? "证书",
                expires: date(kSecOIDX509V1ValidityNotAfter),
                issued: date(kSecOIDX509V1ValidityNotBefore),
                selfSigned: subject != nil && subject == issuer,
                digest: digest)
        }.sorted { $0.name < $1.name }
    }

    /// Certificates that can be the VPN login one: issued by someone
    /// else (a CA), newest first. Renewals share a name; the newest
    /// valid one wins (DESIGN.md §23.10).
    static func loginCandidates() -> [ClientIdentity] {
        clientIdentities().filter { !$0.selfSigned }.sorted {
            ($0.expires ?? .distantPast, $0.issued ?? .distantPast)
                > ($1.expires ?? .distantPast, $1.issued ?? .distantPast)
        }
    }

    /// The user's manual choice when there is one, else the automatic
    /// pick: the newest login candidate.
    static func selectedIdentity(digest: String?) -> ClientIdentity? {
        if let digest, let match = clientIdentities().first(where: { $0.digest == digest }) {
            return match
        }
        return digest == nil ? loginCandidates().first : nil
    }

    // MARK: - Lifecycle

    /// Blocking (openssl + DNS): call off the main thread. Makes the
    /// throwaway listener identity and pins one gateway IPv4.
    /// The gateway's name often has several addresses, handed out in
    /// turn (§30.6): `prefer` (the one the last session used) is kept
    /// while it is still among them, `avoid` (one that stopped
    /// answering) is skipped while another exists, and `known` (the
    /// addresses seen before) stands in when the name does not resolve
    /// right now (DNS points into a dead tunnel during a drop).
    func prepare(prefer: String? = nil, avoid: String? = nil, known: [String] = []) throws -> Prepared {
        guard #available(macOS 15.0, *) else { throw RelayError.unsupportedSystem }
        let (identity, pin) = try Self.makeListenerIdentity()
        let resolved = Self.resolveAllIPv4(host, port: upstreamPort)
        guard let ip = Self.pick(resolved.isEmpty ? known : resolved, prefer: prefer, avoid: avoid)
        else { throw RelayError.unresolved }
        queue.sync {
            listenerIdentity = identity
            gatewayIp = ip
        }
        return Prepared(gatewayIp: ip, serverPin: pin, addresses: resolved)
    }

    /// The address for this session (§30.6; the rule is in Rust,
    /// core/src/relay.rs): the preferred one while the name still has it,
    /// never `avoid` while another exists.
    static func pick(_ addresses: [String], prefer: String?, avoid: String?) -> String? {
        guard let raw = ac_relay_pick(addresses.joined(separator: ","), prefer, avoid) else { return nil }
        defer { ac_string_free(raw) }
        return String(cString: raw)
    }

    /// Listens on 127.0.0.1:<port>, accepting only `clientCertificate`
    /// (DER, from the Helper). Completion on the relay queue.
    func start(clientCertificate: Data, completion: @escaping (Error?) -> Void) {
        queue.async {
            guard let identity = self.listenerIdentity, self.gatewayIp != nil else {
                completion(RelayError.certificate)
                return
            }
            let tls = NWProtocolTLS.Options()
            let options = tls.securityProtocolOptions
            sec_protocol_options_set_local_identity(options, identity)
            sec_protocol_options_set_peer_authentication_required(options, true)
            sec_protocol_options_set_verify_block(options, { _, trust, complete in
                let object = sec_trust_copy_ref(trust).takeRetainedValue()
                let leaf = (SecTrustCopyCertificateChain(object) as? [SecCertificate])?.first
                complete(leaf.map { SecCertificateCopyData($0) as Data == clientCertificate } ?? false)
            }, self.queue)
            let parameters = NWParameters(tls: tls)
            parameters.requiredLocalEndpoint = .hostPort(
                host: "127.0.0.1", port: NWEndpoint.Port(rawValue: self.port)!)
            let listener: NWListener
            do {
                listener = try NWListener(using: parameters)
            } catch {
                completion(RelayError.listener("本机转接启动失败"))
                return
            }
            var reported = false
            listener.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    if !reported { reported = true; completion(nil) }
                case .failed(let error):
                    Self.log.error("relay listener failed: \(String(describing: error), privacy: .public)")
                    let reason: String
                    if case .posix(let code) = error, code == .EADDRINUSE {
                        reason = "本机 \(self?.port ?? 0) 端口被其他程序占用，转接无法启动"
                    } else {
                        reason = "本机转接启动失败"
                    }
                    if !reported { reported = true; completion(RelayError.listener(reason)) }
                    self?.stopLocked()
                default:
                    break
                }
            }
            listener.newConnectionHandler = { [weak self] connection in
                self?.accept(connection)
            }
            self.listener = listener
            listener.start(queue: self.queue)
            self.watchNetwork()
        }
    }

    func stop() {
        queue.async { self.stopLocked() }
    }

    /// A connection to the gateway that starts while the Mac changes
    /// network is bound to the address it is leaving and never gets an
    /// answer: switching from a phone hotspot back to Wi-Fi, one waited
    /// out its whole timeout and the phone approval came 27 s after the
    /// switch instead of 3 (§30.10). When the network changes, every
    /// pair still in its handshake is given up at once; openconnect
    /// tries again straight away, over the new network.
    private var pathMonitor: NWPathMonitor?
    private var lastPath: String?

    private func watchNetwork() {
        // The physical network only: our own tunnel coming and going is
        // not a change of network (the relay itself needs macOS 15).
        let monitor: NWPathMonitor
        if #available(macOS 14.0, *) {
            monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other])
        } else {
            monitor = NWPathMonitor()
        }
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let signature = "\(path.status) \(path.availableInterfaces.map(\.name)) \(path.gateways.map(\.debugDescription))"
            defer { self.lastPath = signature }
            guard let last = self.lastPath, last != signature else { return }
            for pair in self.pairs.values where pair.handshaking {
                pair.close("network changed during the handshake")
            }
        }
        monitor.start(queue: queue)
        pathMonitor = monitor
    }

    private func stopLocked() {
        pathMonitor?.cancel()
        pathMonitor = nil
        lastPath = nil
        listener?.cancel()
        listener = nil
        for pair in pairs.values { pair.close("relay stopped") }
        pairs.removeAll()
    }

    private func accept(_ incoming: NWConnection) {
        guard let ip = gatewayIp else { incoming.cancel(); return }
        let tls = NWProtocolTLS.Options()
        let options = tls.securityProtocolOptions
        sec_protocol_options_set_local_identity(options, sec_identity_create(clientIdentity)!)
        sec_protocol_options_set_tls_server_name(options, host)
        let anchor = self.anchor
        sec_protocol_options_set_verify_block(options, { _, trust, complete in
            let object = sec_trust_copy_ref(trust).takeRetainedValue()
            var configured = true
            if let anchor {
                configured = SecTrustSetAnchorCertificates(object, [anchor] as CFArray) == errSecSuccess
                    && SecTrustSetAnchorCertificatesOnly(object, true) == errSecSuccess
                    && SecTrustSetNetworkFetchAllowed(object, false) == errSecSuccess
            }
            // System trust and the gateway's host name, as any client.
            let accepted = configured && SecTrustEvaluateWithError(object, nil)
            if !accepted { Self.log.error("relay: gateway certificate rejected") }
            complete(accepted)
        }, queue)
        let parameters = NWParameters(tls: tls)
        // Never through a tunnel, our own included: once the tunnel is
        // the default route, a connection to the gateway that is not
        // kept off utun loses viability and its sends stall while
        // receives still trickle in (first real full-tunnel run, §23.6).
        parameters.prohibitedInterfaceTypes = [.other]
        let outgoing = NWConnection(
            host: NWEndpoint.Host(ip), port: NWEndpoint.Port(rawValue: upstreamPort)!,
            using: parameters)
        pairCount += 1
        let pair = Pair(incoming: incoming, outgoing: outgoing, queue: queue, number: pairCount,
                        gatewayIp: ip)
        let key = ObjectIdentifier(pair)
        pair.onClose = { [weak self] outcome in
            guard let self else { return }
            self.pairs.removeValue(forKey: key)
            switch outcome {
            case .carried: self.silentHandshakes = 0
            case .gatewaySilent:
                // openconnect was there, the gateway never answered: three
                // in a row (about a minute) and this address is given up.
                self.silentHandshakes += 1
                if self.silentHandshakes == 3 { self.onGatewayUnreachable?(ip) }
            case .other: break
            }
        }
        pairs[key] = pair
        pair.start()
    }

    // MARK: - Helpers

    /// Throwaway listener identity: a self-signed RSA certificate made
    /// by the system's openssl, imported into memory only (never the
    /// keychain), files removed at once. Returns the openconnect pin
    /// (pin-sha256 of the public key).
    @available(macOS 15.0, *)
    static func makeListenerIdentity() throws -> (sec_identity_t, String) {
        let fm = FileManager.default
        let dir = fm.temporaryDirectory.appendingPathComponent("ac-relay-\(UUID().uuidString)")
        try fm.createDirectory(at: dir, withIntermediateDirectories: false,
                               attributes: [.posixPermissions: 0o700])
        defer { try? fm.removeItem(at: dir) }
        let pass = UUID().uuidString
        let key = dir.appendingPathComponent("k.pem").path
        let cert = dir.appendingPathComponent("c.pem").path
        let p12 = dir.appendingPathComponent("i.p12").path
        let spki = dir.appendingPathComponent("p.der").path
        guard openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                       "-subj", "/CN=localhost",
                       "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                       "-addext", "extendedKeyUsage=serverAuth",
                       "-keyout", key, "-out", cert]),
              // The encoding Apple's PKCS#12 import accepts (an EC key
              // or LibreSSL's defaults crash the memory-only import).
              openssl(["pkcs12", "-export", "-inkey", key, "-in", cert, "-out", p12,
                       "-passout", "env:AC_RELAY_PASS", "-keypbe", "PBE-SHA1-3DES",
                       "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1"],
                      environment: ["AC_RELAY_PASS": pass]),
              // SubjectPublicKeyInfo, which pin-sha256 hashes. (LibreSSL's
              // x509 -pubkey ignores -out under -noout.)
              openssl(["pkey", "-in", key, "-pubout", "-outform", "DER", "-out", spki]),
              let p12Data = fm.contents(atPath: p12),
              let spkiData = fm.contents(atPath: spki)
        else { throw RelayError.certificate }
        var items: CFArray?
        let options = [kSecImportExportPassphrase as String: pass,
                       kSecImportToMemoryOnly as String: true] as CFDictionary
        guard SecPKCS12Import(p12Data as CFData, options, &items) == errSecSuccess,
              let first = (items as? [[String: Any]])?.first,
              let value = first[kSecImportItemIdentity as String],
              let identity = sec_identity_create(value as! SecIdentity)
        else { throw RelayError.certificate }
        let pin = "pin-sha256:" + Data(SHA256.hash(data: spkiData)).base64EncodedString()
        return (identity, pin)
    }

    private static func openssl(_ arguments: [String], environment: [String: String] = [:]) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = arguments
        process.environment = environment
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        guard (try? process.run()) != nil else { return false }
        process.waitUntilExit()
        return process.terminationStatus == 0
    }

    static func resolveIPv4(_ host: String, port: UInt16) -> String? {
        resolveAllIPv4(host, port: port).first
    }

    static func resolveAllIPv4(_ host: String, port: UInt16) -> [String] {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &result) == 0, let result else { return [] }
        defer { freeaddrinfo(result) }
        var out: [String] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = result
        while let entry = cursor {
            defer { cursor = entry.pointee.ai_next }
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(entry.pointee.ai_addr, entry.pointee.ai_addrlen,
                              &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0
            else { continue }
            let ip = String(cString: buffer)
            if !out.contains(ip) { out.append(ip) }
        }
        return out
    }
}

// MARK: - One relayed connection

/// openconnect's connection on one side, the gateway on the other. Both
/// handshakes must finish within 20 s; after that the pair lives as
/// long as either side keeps it open. Every pair's end goes to RelayLog
/// with who ended it and how much it carried.
private final class Pair {
    let incoming: NWConnection
    let outgoing: NWConnection
    let queue: DispatchQueue
    let number: Int
    let gatewayIp: String
    enum Outcome { case carried, gatewaySilent, other }
    var onClose: ((Outcome) -> Void)?
    /// The plaintext side — request and answer headers, CSTP packets,
    /// the login trace, the DTLS channel — is Rust (core/src/relay.rs,
    /// §32.7); this class keeps the two TLS connections.
    private let stream: OpaquePointer
    private var incomingReady = false
    private var outgoingReady = false
    private var started = false
    private var closed = false
    private var viable = true
    private let opened = Date()

    init(incoming: NWConnection, outgoing: NWConnection, queue: DispatchQueue, number: Int,
         gatewayIp: String) {
        self.incoming = incoming
        self.outgoing = outgoing
        self.queue = queue
        self.number = number
        self.gatewayIp = gatewayIp
        // gatewayIp is always a resolved IPv4 address.
        stream = ac_relay_stream_new(UInt32(number), gatewayIp, nil)
            ?? ac_relay_stream_new(UInt32(number), "0.0.0.0", nil)!
    }

    deinit { ac_relay_stream_free(stream) }

    func start() {
        RelayLog.write("pair \(number) opened")
        // A network change or sleep leaves the gateway connection dead
        // while openconnect's link to us stays healthy, so openconnect
        // kept waiting on it (half an hour once, §28.1). When the path
        // goes away for a few seconds, or a different network takes
        // over, end the pair: openconnect reconnects at once, and its
        // attempt-reconnect moves the gateway route first.
        outgoing.viabilityUpdateHandler = { [weak self] viable in
            guard let self else { return }
            RelayLog.write("pair \(self.number) gateway connection viable=\(viable)")
            self.viable = viable
            guard !viable else { return }
            self.queue.asyncAfter(deadline: .now() + 8) { [weak self] in
                guard let self, !self.closed, !self.viable else { return }
                self.close("gateway path gone (network changed or asleep)")
            }
        }
        outgoing.betterPathUpdateHandler = { [weak self] better in
            guard let self, better else { return }
            RelayLog.write("pair \(self.number) gateway connection: better path available")
            self.queue.asyncAfter(deadline: .now() + 3) { [weak self] in
                guard let self, !self.closed else { return }
                self.close("another network took over")
            }
        }
        incoming.stateUpdateHandler = { [weak self] state in self?.state(state, incoming: true) }
        outgoing.stateUpdateHandler = { [weak self] state in self?.state(state, incoming: false) }
        incoming.start(queue: queue)
        outgoing.start(queue: queue)
        // The gateway answers within a second or two (relay log); one that
        // has not after 10 s while openconnect is there is not going to.
        queue.asyncAfter(deadline: .now() + 10) { [weak self] in
            guard let self, !self.started, self.incomingReady, !self.outgoingReady else { return }
            self.close("handshake timeout (openconnect ready: true, gateway ready: false)")
        }
        queue.asyncAfter(deadline: .now() + 20) { [weak self] in
            guard let self, !self.started else { return }
            self.close("handshake timeout (openconnect ready: \(self.incomingReady), gateway ready: \(self.outgoingReady))")
        }
    }

    /// Both sides not yet connected and relaying.
    var handshaking: Bool { !started && !closed }

    private func side(_ incoming: Bool) -> String { incoming ? "openconnect" : "gateway" }

    private func state(_ state: NWConnection.State, incoming: Bool) {
        switch state {
        case .ready:
            if incoming { incomingReady = true } else {
                outgoingReady = true
                // The DTLS channel leaves through the interface this TLS
                // connection uses (never a tunnel, §23.6).
                let path = outgoing.currentPath
                var local: String?
                if case .hostPort(let host, _)? = path?.localEndpoint, case .ipv4(let address) = host {
                    local = "\(address)".split(separator: "%").first.map(String.init)
                }
                let interface = path?.availableInterfaces.first { $0.type != .other }?.name
                ac_relay_stream_set_path(stream, local, interface)
            }
            if incomingReady, outgoingReady, !started {
                started = true
                pump(self.incoming, self.outgoing)
                pump(self.outgoing, self.incoming)
            }
        case .failed(let error):
            close("\(side(incoming)) failed: \(error)")
        case .waiting(let error):
            close("\(side(incoming)) waiting: \(error)")
        case .cancelled:
            close("\(side(incoming)) cancelled")
        default:
            break
        }
    }

    private func pump(_ source: NWConnection, _ destination: NWConnection) {
        let fromClient = source === incoming
        source.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, end, error in
            guard let self, !self.closed else { return }
            if let error { self.close("receive from \(self.side(fromClient)): \(error)"); return }
            var chunks: [Data] = []
            if let data, !data.isEmpty {
                let count = data.withUnsafeBytes { raw in
                    ac_relay_stream_feed(self.stream, fromClient,
                                         raw.baseAddress?.assumingMemoryBound(to: UInt8.self), raw.count)
                }
                guard count >= 0 else {
                    let why = count == -2 ? "oversized" : "invalid"
                    self.close("framing \(self.side(fromClient)) -> \(self.side(!fromClient)): \(why)")
                    return
                }
                chunks.reserveCapacity(Int(count))
                for index in 0..<Int(count) {
                    var bytes: UnsafePointer<UInt8>?
                    let length = ac_relay_stream_chunk(self.stream, fromClient, index, &bytes)
                    if let bytes { chunks.append(Data(bytes: bytes, count: length)) }
                }
            }
            self.send(chunks, at: 0, to: destination, end: end) { [weak self] error in
                guard let self, !self.closed else { return }
                if let error {
                    self.close("send to \(self.side(!fromClient)): \(error)")
                } else if end {
                    self.close("end of stream from \(self.side(fromClient))")
                } else {
                    self.pump(source, destination)
                }
            }
        }
    }

    private func send(_ chunks: [Data], at index: Int, to destination: NWConnection, end: Bool,
                      completion: @escaping (NWError?) -> Void) {
        guard index < chunks.count else { completion(nil); return }
        let last = end && index == chunks.count - 1
        // One TLS write per chunk: after CONNECT a chunk is one packet.
        destination.send(content: chunks[index], contentContext: last ? .finalMessage : .defaultMessage,
                         isComplete: true, completion: .contentProcessed { [weak self] error in
            if let error { completion(error); return }
            self?.send(chunks, at: index + 1, to: destination, end: end, completion: completion)
        })
    }

    func close(_ reason: String) {
        guard !closed else { return }
        closed = true
        let age = Int(Date().timeIntervalSince(opened))
        var counters = ""
        if let raw = ac_relay_stream_close(stream) {
            counters = String(cString: raw)
            ac_string_free(raw)
        }
        RelayLog.write("pair \(number) closed after \(age)s (\(counters)): \(reason)")
        incoming.cancel()
        outgoing.cancel()
        let outcome: Outcome = started ? .carried
            : (incomingReady && !outgoingReady && reason.hasPrefix("handshake timeout")) ? .gatewaySilent : .other
        onClose?(outcome)
    }
}

/// Why relayed connections end, readable without administrator rights
/// (~/Library/Logs/AlwaysConnect/relay.log, bounded). Written by Rust
/// (core/src/relay_log.rs, §32.9), off the caller's queue cost: one
/// append per line. Reasons and counts only: no addresses, no content.
enum RelayLog {
    static func write(_ line: String) { ac_relay_log(line) }
}

// The Rust side (core/src/ffi.rs). Declared here: the App links the
// staticlib without a bridging header (as the Helper does).
@_silgen_name("ac_relay_stream_new")
func ac_relay_stream_new(_ pair: UInt32, _ gatewayIp: UnsafePointer<CChar>,
                         _ log: (@convention(c) (UnsafePointer<CChar>?) -> Void)?) -> OpaquePointer?
@_silgen_name("ac_relay_stream_set_path")
func ac_relay_stream_set_path(_ s: OpaquePointer, _ localIp: UnsafePointer<CChar>?, _ interface: UnsafePointer<CChar>?)
@_silgen_name("ac_relay_stream_feed")
func ac_relay_stream_feed(_ s: OpaquePointer, _ fromClient: Bool, _ data: UnsafePointer<UInt8>?, _ len: Int) -> Int32
@_silgen_name("ac_relay_stream_chunk")
func ac_relay_stream_chunk(_ s: OpaquePointer, _ fromClient: Bool, _ index: Int,
                           _ data: UnsafeMutablePointer<UnsafePointer<UInt8>?>) -> Int
@_silgen_name("ac_relay_stream_close")
func ac_relay_stream_close(_ s: OpaquePointer) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_relay_stream_free")
func ac_relay_stream_free(_ s: OpaquePointer)
@_silgen_name("ac_relay_pick")
func ac_relay_pick(_ addresses: UnsafePointer<CChar>, _ prefer: UnsafePointer<CChar>?,
                   _ avoid: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_relay_log")
func ac_relay_log(_ line: UnsafePointer<CChar>)
@_silgen_name("ac_string_free")
func ac_string_free(_ s: UnsafeMutablePointer<CChar>?)

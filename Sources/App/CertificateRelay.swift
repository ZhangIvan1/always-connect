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
/// - No request bodies, cookies or keys are logged. Owner-only local
///   diagnostics include connection targets; public exports remove them.
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
    var onRedirect: ((RelayRedirect) -> Void)?
    var onProgress: ((RelayProgress) -> Void)?
    var onFatalIssue: ((RelayIssue) -> Void)?
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
    /// The keychain certificate the next gateway connection presents;
    /// read and swapped on `queue` only (§45).
    private var clientIdentity: SecIdentity
    private var clientExpires: Date?
    private let renewal: (() -> ClientIdentity?)?
    private var reportedNoRenewal = false
    private let upstreamPort: UInt16
    private let anchor: SecCertificate?
    private let queue = DispatchQueue(label: "com.alwaysconnect.app.relay")
    private var listenerIdentity: sec_identity_t?
    private var gatewayIp: String?
    private var listener: NWListener?
    private var pairs: [ObjectIdentifier: Pair] = [:]
    private var pairCount = 0
    private var stopped = false
    private let sessionId: String
    private let attempt: Int
    private let session = ac_relay_session_new()!
    private var isActive: Bool { !stopped && ac_relay_session_active(session) }

    /// `upstreamPort` and `anchor` exist for the harness only (a mock
    /// gateway on another loopback port, trusted through its test CA);
    /// the App keeps the gateway's own port and the system trust store.
    /// `renewal` (the automatic choice only) names the certificate to
    /// use once `expires` has passed (§45).
    init(host: String, port: UInt16, identity: SecIdentity, expires: Date? = nil,
         renewal: (() -> ClientIdentity?)? = nil,
         upstreamPort: UInt16? = nil, anchor: SecCertificate? = nil,
         sessionId: String = UUID().uuidString, attempt: Int = 0) {
        self.host = host
        self.port = port
        self.sessionId = sessionId
        self.attempt = attempt
        self.clientIdentity = identity
        self.clientExpires = expires
        self.renewal = renewal
        self.upstreamPort = upstreamPort ?? port
        self.anchor = anchor
    }

    deinit { ac_relay_session_cancel(session); ac_relay_session_free(session) }

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
    func prepare(prefer: String? = nil, avoid: String? = nil, known: [String] = [], resolved: [String]? = nil,
                 resolutionSource: String? = nil) throws -> Prepared {
        guard #available(macOS 15.0, *) else { throw RelayError.unsupportedSystem }
        let (identity, pin) = try Self.makeListenerIdentity()
        let source = resolutionSource ?? (resolved == nil ? "system" : "provided")
        let resolved = resolved ?? Self.resolveAllIPv4(host, port: upstreamPort)
        guard let ip = Self.pick(resolved.isEmpty ? known : resolved, prefer: prefer, avoid: avoid)
        else { throw RelayError.unresolved }
        RelayLog.write("session=\(sessionId) attempt=\(attempt) stage=dns source=\(resolved.isEmpty ? "cache" : "resolved") candidates=\(resolved.count) port=\(upstreamPort)")
        RelayLog.event(session: sessionId, attempt: attempt, pair: 0,
                       fields: ["stage": "dns", "dns_source": resolved.isEmpty ? "cache" : source, "port": upstreamPort])
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
            guard self.isActive else { completion(RelayError.listener("连接已取消")); return }
            guard let identity = self.listenerIdentity, self.gatewayIp != nil else {
                completion(RelayError.certificate)
                return
            }
            let tls = NWProtocolTLS.Options()
            let options = tls.securityProtocolOptions
            sec_protocol_options_set_local_identity(options, identity)
            sec_protocol_options_set_peer_authentication_required(options, true)
            sec_protocol_options_set_verify_block(options, { [weak self] _, trust, complete in
                let object = sec_trust_copy_ref(trust).takeRetainedValue()
                let leaf = (SecTrustCopyCertificateChain(object) as? [SecCertificate])?.first
                complete(self?.isActive == true && (leaf.map { SecCertificateCopyData($0) as Data == clientCertificate } ?? false))
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
                guard let self else { return }
                if case .cancelled = state {
                    self.listener = nil
                    let completions = self.stopCompletions
                    self.stopCompletions.removeAll()
                    completions.forEach { $0() }
                    return
                }
                guard self.isActive else { return }
                switch state {
                case .ready:
                    if !reported {
                        reported = true
                        self.onProgress?(RelayProgress(stage: .localTLS))
                        completion(nil)
                    }
                case .failed(let error):
                    Self.log.error("relay listener failed: \(String(describing: error), privacy: .public)")
                    let reason: String
                    if case .posix(let code) = error, code == .EADDRINUSE {
                        reason = "本机 \(self.port) 端口被其他程序占用，转接无法启动"
                    } else {
                        reason = "本机转接启动失败"
                    }
                    if !reported { reported = true; completion(RelayError.listener(reason)) }
                    self.stopLocked()
                default:
                    break
                }
            }
            listener.newConnectionHandler = { [weak self] connection in
                guard let self, self.isActive else { connection.cancel(); return }
                self.accept(connection)
            }
            self.listener = listener
            listener.start(queue: self.queue)
            self.watchNetwork()
        }
    }

    private var stopCompletions: [() -> Void] = []

    func stop(completion: (() -> Void)? = nil) {
        if ac_relay_session_active(session) {
            RelayLog.event(session: sessionId, attempt: attempt, pair: 0, fields: ["stage": "cancelled"])
        }
        ac_relay_session_cancel(session)
        queue.async {
            if let completion { self.stopCompletions.append(completion) }
            self.stopLocked()
            if self.listener == nil {
                let completions = self.stopCompletions
                self.stopCompletions.removeAll()
                completions.forEach { $0() }
            }
        }
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
            guard let self, self.isActive else { return }
            let signature = "\(path.status) \(path.availableInterfaces.map(\.name)) \(path.gateways.map(\.debugDescription))"
            defer { self.lastPath = signature }
            guard let last = self.lastPath, last != signature else { return }
            for pair in Array(self.pairs.values) where pair.handshaking {
                pair.close("network changed during the handshake")
            }
        }
        monitor.start(queue: queue)
        pathMonitor = monitor
    }

    private func stopLocked() {
        ac_relay_session_cancel(session)
        stopped = true
        pathMonitor?.cancel()
        pathMonitor = nil
        lastPath = nil
        listener?.cancel()
        let closing = Array(pairs.values)
        pairs.removeAll()
        for pair in closing { pair.close("relay stopped") }
    }

    /// The certificate for the next gateway connection (§45). The relay
    /// lives as long as the session, reconnects included, so a
    /// certificate that expires on the way would be presented on every
    /// retry and refused. With the automatic choice, an expired one is
    /// swapped for the newest valid one (a renewal the device
    /// management put in the keychain) at the next connection. A date
    /// comparison per connection; the keychain is read only after expiry.
    private func identityForNextConnection() -> SecIdentity {
        guard let expires = clientExpires, expires <= Date(), let renewal else { return clientIdentity }
        if let fresh = renewal(), (fresh.expires ?? .distantFuture) > Date() {
            clientIdentity = fresh.identity
            clientExpires = fresh.expires
            reportedNoRenewal = false
            RelayLog.write("client certificate expired: switched to the newest valid one in the keychain")
        } else if !reportedNoRenewal {
            reportedNoRenewal = true
            RelayLog.write("client certificate expired and the keychain has no valid one")
        }
        return clientIdentity
    }

    private func fatal(_ issue: RelayIssue) {
        guard isActive else { return }
        ac_relay_session_cancel(session)
        onFatalIssue?(issue)
    }

    private func accept(_ incoming: NWConnection) {
        guard isActive, let ip = gatewayIp else { incoming.cancel(); return }
        pairCount += 1
        guard let raw = ac_relay_session_admit(session, UInt32(pairCount)) else { incoming.cancel(); fatal(.relayUnavailable); return }
        let admission = try? JSONDecoder().decode(RelayAdmission.self, from: Data(String(cString: raw).utf8))
        ac_string_free(raw)
        guard let admission else { incoming.cancel(); fatal(.relayUnavailable); return }
        guard admission.allowed else {
            incoming.cancel()
            if admission.notify {
                RelayLog.event(session: sessionId, attempt: attempt, pair: pairCount,
                    fields: ["stage": "backoff", "retry_after_ms": admission.retryAfterMs,
                             "reason": admission.retryAfterMs == 0 ? "capacity" : "transport_failure"])
                if admission.retryAfterMs > 0 { onProgress?(RelayProgress(stage: .backoff, retryAfterMs: admission.retryAfterMs)) }
            }
            return
        }
        // Full targets stay in the owner-only local log. Exported relay
        // diagnostics identify the session, never an address.
        Self.log.info("session=\(self.sessionId, privacy: .public) attempt=\(self.attempt) pair=\(self.pairCount) relay target host=\(self.host, privacy: .private) port=\(self.upstreamPort) ip=\(ip, privacy: .private) sni=\(self.host, privacy: .private)")
        let number = pairCount
        RelayLog.event(session: sessionId, attempt: attempt, pair: number,
            fields: ["stage": "target", "host": host, "sni": host, "port": upstreamPort, "ip": ip])
        let pair = Pair(incoming: incoming, upstream: { [weak self] in self?.upstream(ip: ip, number: number) },
                        queue: queue, number: number,
                        gatewayIp: ip, sessionId: sessionId, host: host, port: port, session: session, attempt: attempt)
        let key = ObjectIdentifier(pair)
        pair.onProgress = { [weak self] progress in
            guard let self, self.isActive else { return }
            self.onProgress?(progress)
        }
        pair.onRedirect = { [weak self] event in
            guard let self, self.isActive else { return }
            ac_relay_session_cancel(self.session)
            self.onRedirect?(event)
        }
        pair.onClose = { [weak self] outcome in
            guard let self else { return }
            self.pairs.removeValue(forKey: key)
            guard self.isActive else { return }
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

    /// Only called after local mutual TLS authenticated the Helper client.
    private func upstream(ip: String, number: Int) -> NWConnection? {
        guard isActive else { return nil }
        let pairId = "session=\(sessionId) attempt=\(attempt) pair=\(number)"
        let identity = identityForNextConnection()
        var target: [String: Any] = ["stage": "target", "host": host, "sni": host, "port": upstreamPort, "ip": ip]
        if let expires = clientExpires { target["client_expired"] = expires <= Date() }
        RelayLog.event(session: sessionId, attempt: attempt, pair: number, fields: target)
        if let expires = clientExpires, expires <= Date() {
            RelayLog.event(session: sessionId, attempt: attempt, pair: number,
                           fields: ["stage": "target", "reason": "identity_expired", "client_expired": true])
            fatal(.identityExpired); return nil
        }
        guard let localIdentity = sec_identity_create(identity) else {
            RelayLog.event(session: sessionId, attempt: attempt, pair: number,
                           fields: ["stage": "target", "identity_configured": false, "reason": "identity_unavailable"])
            fatal(.identityUnavailable); return nil
        }
        RelayLog.event(session: sessionId, attempt: attempt, pair: number,
                       fields: ["stage": "target", "identity_configured": true])
        RelayLog.write("\(pairId) stage=upstream_tls port=\(upstreamPort) certificate_expired=\(clientExpires.map { String($0 <= Date()) } ?? "unknown")")
        let tls = NWProtocolTLS.Options()
        let options = tls.securityProtocolOptions
        sec_protocol_options_set_local_identity(options, localIdentity)
        sec_protocol_options_set_tls_server_name(options, host)
        let anchor = self.anchor
        let expectedHost = host
        let pairNumber = UInt32(number)
        sec_protocol_options_set_verify_block(options, { [weak self] _, trust, complete in
            let object = sec_trust_copy_ref(trust).takeRetainedValue()
            var configured = SecTrustSetPolicies(object, SecPolicyCreateSSL(true, expectedHost as CFString)) == errSecSuccess
            if let anchor {
                configured = configured && SecTrustSetAnchorCertificates(object, [anchor] as CFArray) == errSecSuccess
                    && SecTrustSetAnchorCertificatesOnly(object, true) == errSecSuccess
                    && SecTrustSetNetworkFetchAllowed(object, false) == errSecSuccess
            }
            // System trust and the gateway's host name, as any client.
            var trustError: CFError?
            let accepted = configured && SecTrustEvaluateWithError(object, &trustError)
            let code = trustError.map { CFErrorGetCode($0) } ?? 0
            RelayLog.write("\(pairId) stage=server_trust accepted=\(accepted) code=\(code)")
            if let self {
                RelayLog.event(session: self.sessionId, attempt: self.attempt, pair: Int(pairNumber),
                    fields: ["stage": "server_trust", "domain": "trust", "accepted": accepted, "code": code])
                if !accepted { self.fatal(.gatewayCertificate) }
            }
            if !accepted { Self.log.error("relay: gateway certificate rejected") }
            complete(accepted && self?.isActive == true)
        }, queue)
        let parameters = NWParameters(tls: tls)
        // Never through a tunnel, our own included: once the tunnel is
        // the default route, a connection to the gateway that is not
        // kept off utun loses viability and its sends stall while
        // receives still trickle in (first real full-tunnel run, §23.6).
        parameters.prohibitedInterfaceTypes = [.other]
        return NWConnection(
            host: NWEndpoint.Host(ip), port: NWEndpoint.Port(rawValue: upstreamPort)!,
            using: parameters)
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
    private var outgoing: NWConnection?
    private let makeOutgoing: () -> NWConnection?
    let queue: DispatchQueue
    let number: Int
    let gatewayIp: String
    let sessionId: String
    let attempt: Int
    enum Outcome { case carried, gatewaySilent, other }
    var onClose: ((Outcome) -> Void)?
    var onRedirect: ((RelayRedirect) -> Void)?
    var onProgress: ((RelayProgress) -> Void)?
    /// The plaintext side — request and answer headers, CSTP packets,
    /// the login trace, the DTLS channel — is Rust (core/src/relay.rs,
    /// §32.7); this class keeps the two TLS connections.
    private let stream: OpaquePointer
    private var incomingReady = false
    private var outgoingReady = false
    private var outgoingStarted = false
    private var outgoingOpened: Date?
    private var started = false
    private var closed = false
    private var viable = true
    private let opened = Date()

    init(incoming: NWConnection, upstream: @escaping () -> NWConnection?, queue: DispatchQueue, number: Int,
         gatewayIp: String, sessionId: String, host: String, port: UInt16, session: OpaquePointer, attempt: Int) {
        self.incoming = incoming
        self.makeOutgoing = upstream
        self.queue = queue
        self.number = number
        self.gatewayIp = gatewayIp
        self.sessionId = sessionId
        self.attempt = attempt
        // gatewayIp is always a resolved IPv4 address.
        stream = ac_relay_stream_new(UInt32(number), gatewayIp, nil)
            ?? ac_relay_stream_new(UInt32(number), "0.0.0.0", nil)!
        ac_relay_stream_set_target(stream, host, port)
        ac_relay_stream_set_session(stream, session)
        ac_relay_stream_set_context(stream, sessionId, UInt32(attempt))
    }

    deinit { ac_relay_stream_free(stream) }

    private func trace(_ line: String) {
        RelayLog.write("session=\(sessionId) attempt=\(attempt) \(line)")
    }

    private func event(_ fields: [String: Any]) {
        RelayLog.event(session: sessionId, attempt: attempt, pair: number, fields: fields)
    }

    private func elapsed(_ since: Date) -> UInt32 {
        UInt32(min(3_600_000, max(0, Date().timeIntervalSince(since) * 1000)))
    }

    private func configure(_ outgoing: NWConnection) {
        outgoing.viabilityUpdateHandler = { [weak self] viable in
            guard let self, !self.closed else { return }
            self.trace("pair \(self.number) gateway connection viable=\(viable)")
            self.viable = viable
            guard !viable else { return }
            self.queue.asyncAfter(deadline: .now() + 8) { [weak self] in
                guard let self, !self.closed, !self.viable else { return }
                self.close("gateway path gone (network changed or asleep)")
            }
        }
        outgoing.betterPathUpdateHandler = { [weak self] better in
            guard let self, !self.closed, better else { return }
            self.trace("pair \(self.number) gateway connection: better path available")
            self.queue.asyncAfter(deadline: .now() + 3) { [weak self] in
                guard let self, !self.closed else { return }
                self.close("another network took over")
            }
        }
        outgoing.stateUpdateHandler = { [weak self] state in self?.state(state, incoming: false) }
    }

    func start() {
        guard !closed else { return }
        event(["stage": "local_tls", "elapsed_ms": 0])
        trace("pair \(number) opened")
        // A network change or sleep leaves the gateway connection dead
        // while openconnect's link to us stays healthy, so openconnect
        // kept waiting on it (half an hour once, §28.1). When the path
        // goes away for a few seconds, or a different network takes
        // over, end the pair: openconnect reconnects at once, and its
        // attempt-reconnect moves the gateway route first.
        incoming.stateUpdateHandler = { [weak self] state in self?.state(state, incoming: true) }
        incoming.start(queue: queue)
        // Only an authenticated local client may start an upstream connection.
        // The gateway answers within a second or two (relay log); one that
        // has not after 10 s while openconnect is there is not going to.
        queue.asyncAfter(deadline: .now() + 20) { [weak self] in
            guard let self, !self.closed, !self.started else { return }
            self.event(["stage": self.incomingReady ? "upstream_tls" : "local_tls", "domain": "timeout",
                        "reason": "handshake_timeout", "accepted": false, "elapsed_ms": self.elapsed(self.opened)])
            self.close("handshake timeout (openconnect ready: \(self.incomingReady), gateway ready: \(self.outgoingReady))",
                       upstreamFailure: self.outgoingStarted && !self.outgoingReady)
        }
    }

    /// Both sides not yet connected and relaying.
    var handshaking: Bool { !started && !closed }

    private func side(_ incoming: Bool) -> String { incoming ? "openconnect" : "gateway" }

    private func state(_ state: NWConnection.State, incoming: Bool) {
        guard !closed else { return }
        guard ac_relay_stream_active(stream) else { close("session cancelled"); return }
        switch state {
        case .ready:
            trace("pair \(number) stage=\(incoming ? "local_tls" : "upstream_tls") ready elapsed_ms=\(Int(Date().timeIntervalSince(opened) * 1000))")
            if incoming {
                incomingReady = true
                event(["stage": "local_tls", "accepted": true, "elapsed_ms": elapsed(opened)])
                if !outgoingStarted {
                    guard ac_relay_stream_active(stream) else { close("session cancelled"); return }
                    guard let outgoing = makeOutgoing() else { close("upstream preparation failed"); return }
                    self.outgoing = outgoing
                    configure(outgoing)
                    outgoingStarted = true
                    outgoingOpened = Date()
                    onProgress?(RelayProgress(stage: .upstreamTLS))
                    event(["stage": "upstream_tls", "elapsed_ms": 0])
                    guard ac_relay_stream_active(stream) else { close("session cancelled"); return }
                    outgoing.start(queue: queue)
                    queue.asyncAfter(deadline: .now() + 10) { [weak self] in
                        guard let self, !self.closed, !self.outgoingReady else { return }
                        self.event(["stage": "upstream_tls", "domain": "timeout", "reason": "handshake_timeout",
                                    "accepted": false, "elapsed_ms": self.elapsed(self.outgoingOpened ?? self.opened)])
                        self.close("handshake timeout (openconnect ready: true, gateway ready: false)", upstreamFailure: true)
                    }
                }
            } else {
                outgoingReady = true
                // The DTLS channel leaves through the interface this TLS
                // connection uses (never a tunnel, §23.6).
                var fields: [String: Any] = ["stage": "upstream_tls", "accepted": true,
                    "elapsed_ms": elapsed(outgoingOpened ?? opened)]
                addPhysicalPath(to: &fields)
                event(fields)
            }
            if incomingReady, outgoingReady, !started, let outgoing {
                started = true
                ac_relay_stream_finish_handshake(stream, 0)
                onProgress?(RelayProgress(stage: .authentication))
                event(["stage": "authentication"])
                pump(self.incoming, outgoing)
                pump(outgoing, self.incoming)
            }
        case .failed(let error), .waiting(let error):
            let domain: String
            let code: Int32?
            switch error {
            case .ssl(let value): domain = "ssl"; code = value
            case .posix(let value): domain = "posix"; code = value.rawValue
            case .dns(let value): domain = "dns"; code = value
            @unknown default: domain = "unknown"; code = nil
            }
            var fields: [String: Any] = ["stage": incoming ? "local_tls" : "upstream_tls", "domain": domain,
                "reason": "transport_failure", "accepted": false,
                "elapsed_ms": elapsed(incoming ? opened : (outgoingOpened ?? opened))]
            if let code { fields["code"] = code }
            if !incoming { addPhysicalPath(to: &fields) }
            event(fields)
            close("\(side(incoming)) failed: \(domain) \(code.map { String($0) } ?? "unknown")", upstreamFailure: !incoming && !outgoingReady)
        case .cancelled:
            close("\(side(incoming)) cancelled")
        default:
            break
        }
    }

    /// The concrete path, when Network.framework exposes it, is useful even
    /// when TLS fails before ready. Never infer an interface from the gateway IP.
    private func addPhysicalPath(to fields: inout [String: Any]) {
        let path = outgoing?.currentPath
        var local: String?
        if case .hostPort(let host, _)? = path?.localEndpoint, case .ipv4(let address) = host {
            local = "\(address)".split(separator: "%").first.map(String.init)
        }
        let interface = path?.availableInterfaces.first { $0.type != .other }?.name
        ac_relay_stream_set_path(stream, local, interface)
        if let raw = ac_relay_stream_interface(stream) {
            fields["interface"] = String(cString: raw); ac_string_free(raw)
        }
    }

    private func pump(_ source: NWConnection, _ destination: NWConnection) {
        let fromClient = source === incoming
        source.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, end, error in
            guard let self, !self.closed else { return }
            guard ac_relay_stream_active(self.stream) else { self.close("session cancelled"); return }
            if let error { self.close("receive from \(self.side(fromClient)): \(error)"); return }
            var chunks: [Data] = []
            if let data, !data.isEmpty {
                let count = data.withUnsafeBytes { raw in
                    ac_relay_stream_feed(self.stream, fromClient,
                                         raw.baseAddress?.assumingMemoryBound(to: UInt8.self), raw.count)
                }
                guard count >= 0 else {
                    if count == -3, let raw = ac_relay_stream_take_redirect(self.stream) {
                        defer { ac_string_free(raw) }
                        // The Location stays private; only fixed metadata is logged.
                        let data = Data(String(cString: raw).utf8)
                        if let event = try? JSONDecoder().decode(RelayRedirect.self, from: data) {
                            self.trace("pair \(self.number) stage=redirect status=\(event.status) replay_unsafe=\(event.replayUnsafe)")
                            self.event(["stage": "redirect", "status": event.status, "replay_unsafe": event.replayUnsafe])
                            self.onRedirect?(event)
                        }
                    }
                    let why = count == -4 ? "session cancelled" : count == -3 ? "cross-origin redirect blocked" : count == -2 ? "oversized" : "invalid"
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
        guard !closed else { return }
        guard ac_relay_stream_active(stream) else { close("session cancelled"); return }
        guard index < chunks.count else { completion(nil); return }
        let last = end && index == chunks.count - 1
        // One TLS write per chunk: after CONNECT a chunk is one packet.
        destination.send(content: chunks[index], contentContext: last ? .finalMessage : .defaultMessage,
                         isComplete: true, completion: .contentProcessed { [weak self] error in
            if let error { completion(error); return }
            self?.send(chunks, at: index + 1, to: destination, end: end, completion: completion)
        })
    }

    func close(_ reason: String, upstreamFailure: Bool = false) {
        guard !closed else { return }
        closed = true
        ac_relay_stream_finish_handshake(stream, upstreamFailure ? 1 : 2)
        let age = Int(Date().timeIntervalSince(opened))
        var counters = ""
        if let raw = ac_relay_stream_close(stream) {
            counters = String(cString: raw)
            ac_string_free(raw)
        }
        trace("pair \(number) closed after \(age)s (\(counters)): \(reason)")
        incoming.cancel()
        outgoing?.cancel()
        let outcome: Outcome = started ? .carried
            : (incomingReady && !outgoingReady && reason.hasPrefix("handshake timeout")) ? .gatewaySilent : .other
        onClose?(outcome)
    }
}

/// Why relayed connections end, readable without administrator rights
/// (~/Library/Logs/AlwaysConnect/relay.log, bounded). Written by Rust
/// (core/src/relay_log.rs, §32.9), off the caller's queue cost: one
/// append per line. Typed targets are owner-only local metadata; the public
/// export reconstructs events without targets. No credential content.
enum RelayLog {
    static func write(_ line: String) { ac_relay_log(line) }
    static func event(session: String, attempt: Int, pair: Int, fields: [String: Any]) {
        var event = fields
        event["session"] = session; event["attempt"] = attempt; event["pair"] = pair
        guard let data = try? JSONSerialization.data(withJSONObject: event),
              let text = String(data: data, encoding: .utf8) else { return }
        ac_relay_diagnostic_write(text)
    }
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

@_silgen_name("ac_relay_stream_set_target")
func ac_relay_stream_set_target(_ s: OpaquePointer, _ host: UnsafePointer<CChar>, _ port: UInt16)

/// Private protocol event. Do not log Location or include it in public exports.
struct RelayRedirect: Codable {
    let status: UInt16
    let location: String
    let replayUnsafe: Bool
    enum CodingKeys: String, CodingKey {
        case status, location
        case replayUnsafe = "replay_unsafe"
    }
}
@_silgen_name("ac_relay_session_new")
func ac_relay_session_new() -> OpaquePointer?
@_silgen_name("ac_relay_session_cancel")
func ac_relay_session_cancel(_ s: OpaquePointer)
@_silgen_name("ac_relay_session_active")
func ac_relay_session_active(_ s: OpaquePointer) -> Bool
@_silgen_name("ac_relay_session_free")
func ac_relay_session_free(_ s: OpaquePointer)
@_silgen_name("ac_relay_stream_set_session")
func ac_relay_stream_set_session(_ s: OpaquePointer, _ session: OpaquePointer)
@_silgen_name("ac_relay_stream_take_redirect")
func ac_relay_stream_take_redirect(_ s: OpaquePointer) -> UnsafeMutablePointer<CChar>?

@_silgen_name("ac_relay_stream_set_context")
private func ac_relay_stream_set_context(_ s: OpaquePointer, _ session: UnsafePointer<CChar>, _ attempt: UInt32)

struct RelayProgress {
    enum Stage: String { case localTLS = "local_tls", upstreamTLS = "upstream_tls", authentication, backoff }
    let stage: Stage
    var retryAfterMs: UInt32 = 0
}
enum RelayIssue: String {
    case identityExpired = "identity_expired", identityUnavailable = "identity_unavailable"
    case gatewayCertificate = "gateway_certificate", relayUnavailable = "relay_unavailable"
    var message: String {
        switch self {
        case .identityExpired: return "选定的客户端证书已过期，请更新或重新选择证书"
        case .identityUnavailable: return "客户端证书身份不可用，请重新选择证书"
        case .gatewayCertificate: return "无法验证 VPN 网关证书，连接已停止"
        case .relayUnavailable: return "本机安全转接无法初始化，连接已停止"
        }
    }
}
private struct RelayAdmission: Decodable {
    let allowed: Bool
    let notify: Bool
    let retryAfterMs: UInt32
    enum CodingKeys: String, CodingKey { case allowed, notify; case retryAfterMs = "retry_after_ms" }
}
@_silgen_name("ac_relay_session_admit") private func ac_relay_session_admit(_ s: OpaquePointer, _ pair: UInt32) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_relay_session_finish") private func ac_relay_session_finish(_ s: OpaquePointer, _ pair: UInt32, _ outcome: UInt32)
@_silgen_name("ac_relay_stream_active") private func ac_relay_stream_active(_ s: OpaquePointer) -> Bool
@_silgen_name("ac_relay_stream_finish_handshake") private func ac_relay_stream_finish_handshake(_ s: OpaquePointer, _ outcome: UInt32)
@_silgen_name("ac_relay_stream_interface") private func ac_relay_stream_interface(_ s: OpaquePointer) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_relay_diagnostic_write") private func ac_relay_diagnostic_write(_ event: UnsafePointer<CChar>)

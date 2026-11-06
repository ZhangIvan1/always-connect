import Foundation

/// The own-connection engine's certificate relay, Helper side
/// (DESIGN.md §二十三). The relay itself runs in the App (the keychain
/// identity is only usable in the user's session); the Helper's part is
/// pointing openconnect at it and remembering the gateway's real
/// address, which openconnect never sees.
struct RelaySettings: Equatable {
    /// The gateway IPv4 the relay pinned: host route and pf use it.
    var gatewayIp: String
    /// openconnect --servercert for the relay's throwaway listener.
    var serverPin: String
    var certificatePath: String
    var keyPath: String

    /// openconnect arguments for a run through the relay. Native
    /// authentication: STRAP signs the current TLS channel, which
    /// cannot survive two TLS legs (§22.6). DTLS on: the relay points
    /// openconnect at a local UDP port and forwards the datagrams
    /// (§26.10); a single TCP channel melted down under load (§26.9),
    /// and openconnect falls back to TLS by itself if DTLS fails. MTU
    /// values are the ones the real-gateway proof ran with (§22.14).
    func arguments(server: String) -> [String] {
        let host = GatewayAddress(server)?.host ?? server
        return [
            "--resolve=\(host):127.0.0.1",
            "--servercert=\(serverPin)",
            "--certificate=\(certificatePath)",
            "--sslkey=\(keyPath)",
            "--no-external-auth",
            "--base-mtu=1500",
            "--mtu=1300",
        ]
    }

    static func isValidPin(_ pin: String) -> Bool {
        guard pin.hasPrefix("pin-sha256:") else { return false }
        let value = pin.dropFirst("pin-sha256:".count)
        return Data(base64Encoded: String(value))?.count == 32
    }
}

/// The client certificate openconnect presents to the relay. Made by
/// the system's openssl in the Helper's root-only directory; the
/// private key never leaves it. The App gets the certificate (public)
/// and accepts no other client.
enum RelayClientIdentity {
    struct Files {
        var certificatePath: String
        var keyPath: String
        var certificatePEM: String
    }

    /// Reuses the pair while it is valid for another day, else makes a
    /// new one.
    static func ensure(supportDir: URL) throws -> Files {
        let fm = FileManager.default
        let dir = supportDir.appendingPathComponent("relay")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        let cert = dir.appendingPathComponent("client.pem").path
        let key = dir.appendingPathComponent("client.key").path
        let usable = fm.fileExists(atPath: key)
            && openssl(["x509", "-in", cert, "-noout", "-checkend", "86400"])
        if !usable {
            try? fm.removeItem(atPath: cert)
            try? fm.removeItem(atPath: key)
            let previous = umask(0o077)
            defer { umask(previous) }
            guard openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
                           "-subj", "/CN=AlwaysConnect relay client",
                           "-addext", "extendedKeyUsage=clientAuth",
                           "-keyout", key, "-out", cert])
            else { throw CocoaError(.fileWriteUnknown) }
        }
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: key)
        guard let pem = try? String(contentsOfFile: cert, encoding: .utf8) else {
            throw CocoaError(.fileReadUnknown)
        }
        return Files(certificatePath: cert, keyPath: key, certificatePEM: pem)
    }

    private static func openssl(_ arguments: [String]) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        guard (try? process.run()) != nil else { return false }
        process.waitUntilExit()
        return process.terminationStatus == 0
    }
}

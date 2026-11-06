import Foundation

/// Persistent session-cookie cache for the Helper (DESIGN.md §16.7).
///
/// Mirrors the Rust core's SessionRecord (core/src/session.rs):
/// usable_for() only checks gateway match and a non-empty cookie — it
/// never guesses expiry. A stale cookie is detected by the server
/// rejecting it, which drops this record and falls back to password auth.
///
/// Storage: a single JSON file, 0600, parent dir 0700. On macOS the
/// daemon path is /Library/Application Support/AlwaysConnect/; tests
/// inject a temp path. The cookie is a session token, not the password:
/// it never goes to the App, the UI, or diagnostics (see redact() in
/// CLIOrchestrator).
struct CookieStore {
    struct Record: Codable {
        var cookie: String
        var gateway: String
        var serverFingerprint: String
        var savedAtUnix: Int64
    }

    let fileURL: URL

    static var defaultFileURL: URL {
        if let dir = TestSeam.supportDir { return dir.appendingPathComponent("session.json") }
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .localDomainMask)
            .first!
            .appendingPathComponent("AlwaysConnect/session.json")
    }

    func load() -> Record? {
        guard let data = try? Data(contentsOf: fileURL),
              let record = try? JSONDecoder().decode(Record.self, from: data)
        else { return nil }
        return record
    }

    func usableRecord(for gateway: String) -> Record? {
        guard let record = load(),
              record.gateway == gateway,
              !record.cookie.isEmpty
        else { return nil }
        return record
    }

    func save(cookie: String, gateway: String, serverFingerprint: String = "") {
        let record = Record(
            cookie: cookie,
            gateway: gateway,
            serverFingerprint: serverFingerprint,
            savedAtUnix: Int64(Date().timeIntervalSince1970)
        )
        do {
            let dir = fileURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(
                at: dir, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            let data = try JSONEncoder().encode(record)
            try data.write(to: fileURL, options: [.atomic])
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        } catch {
            // A failed cache write must not break the connection: the
            // next start just falls back to password auth.
            fputs("CookieStore: save failed, continuing without cache\n", stderr)
        }
    }

    func clear() {
        try? FileManager.default.removeItem(at: fileURL)
    }
}

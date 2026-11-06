import CryptoKit
import Foundation
import Security

/// Keychain storage for VPN credentials.
/// - One generic-password item per server+username (account
///   "username@server"); the password never touches a plaintext file,
///   a log, or diagnostics.
/// - Accessibility AfterFirstUnlock: launch-time auto-connect works
///   without unlocking the device first.
/// - Touch ID gating belongs in the Settings UI for viewing/editing
///   (Phase 2); it must never gate auto-login itself, or launch-time
///   auto-connect would be interrupted.
enum KeychainStore {
    private static let service = "com.alwaysconnect.app"
    /// Since servers can be switched (DESIGN.md §21.13), the password
    /// belongs to the account, not to one server: it is stored under
    /// this server key. Items saved per server by older builds are
    /// still found (and moved here) by the callers' fallback.
    static let accountKey = "account"

    private static func query(server: String, username: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "\(username)@\(server)",
        ]
    }

    static func save(server: String, username: String, password: String) -> Bool {
        var item = query(server: server, username: username)
        item[kSecValueData as String] = Data(password.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        var status = SecItemAdd(item as CFDictionary, nil)
        if status == errSecDuplicateItem {
            let update: [String: Any] = [kSecValueData as String: Data(password.utf8)]
            status = SecItemUpdate(
                query(server: server, username: username) as CFDictionary,
                update as CFDictionary
            )
        }
        return status == errSecSuccess
    }

    /// Whether a password is stored, WITHOUT reading it: an
    /// attributes-only query needs no access to the secret, so it never
    /// raises the keychain password prompt. Use this for every "do we
    /// have credentials?" check; read() only when actually connecting
    /// (DESIGN.md §21.12 — the owner got a prompt per panel refresh).
    static func exists(server: String, username: String) -> Bool {
        var q = query(server: server, username: username)
        q[kSecReturnAttributes as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        return SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess
    }

    /// Returns nil when absent or unreadable; callers treat nil as
    /// "no stored password". May prompt for keychain access: call only
    /// to connect.
    static func read(server: String, username: String) -> String? {
        var q = query(server: server, username: username)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    static func delete(server: String, username: String) -> Bool {
        let status = SecItemDelete(query(server: server, username: username) as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    /// Every password this App ever stored, whatever the account (the
    /// uninstaller, DESIGN.md §31). Repeated because one call may remove
    /// only one item; stops at the first "nothing left" or error.
    static func deleteAll() {
        let all: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        var rounds = 0
        while rounds < 20, SecItemDelete(all as CFDictionary) == errSecSuccess {
            rounds += 1
        }
    }

    // MARK: - Clean re-bind to the stable signer (DESIGN.md §21.16)

    /// Each "Always Allow" given to an ad-hoc build added one entry to
    /// the item's access list (and its cdhash to the partition list);
    /// they all went stale with the next rebuild. Once the App runs with
    /// a stable signer (§21.15), rebuild the item a single time so that
    /// signer is its only owner, and drop the per-server items older
    /// builds left behind. Safe ordering: the new item is written under
    /// a temporary account first, so a failure at any step leaves the
    /// password stored somewhere it is still found.
    static func rebindIfSignerChanged(username: String, password: String, legacyServers: [String]) {
        guard let signer = currentSignerHash() else { return }  // ad-hoc: nothing stable to bind to
        let flag = "keychainBoundSigner"
        guard UserDefaults.standard.string(forKey: flag) != signer else { return }
        let temporary = accountKey + ".rebind"
        guard save(server: temporary, username: username, password: password) else { return }
        _ = delete(server: accountKey, username: username)
        let rename: [String: Any] = [kSecAttrAccount as String: "\(username)@\(accountKey)"]
        if SecItemUpdate(query(server: temporary, username: username) as CFDictionary,
                         rename as CFDictionary) != errSecSuccess {
            guard save(server: accountKey, username: username, password: password) else { return }
            _ = delete(server: temporary, username: username)
        }
        for server in Set(legacyServers) where server != accountKey {
            _ = delete(server: server, username: username)
        }
        UserDefaults.standard.set(signer, forKey: flag)
    }

    /// SHA-1 of this App's signing certificate; nil when ad-hoc signed.
    private static func currentSignerHash() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
              let staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(
                staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any],
              let certs = dict[kSecCodeInfoCertificates as String] as? [SecCertificate],
              let leaf = certs.first
        else { return nil }
        return Insecure.SHA1.hash(data: SecCertificateCopyData(leaf) as Data)
            .map { String(format: "%02x", $0) }.joined()
    }
}

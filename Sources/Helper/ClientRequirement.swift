import CryptoKit
import Foundation
import Security

/// Which processes may talk to the root background service
/// (DESIGN.md §36.3).
///
/// The requirement is derived from how the background service itself
/// is signed, so it needs no configuration and follows whoever builds
/// it: a client must be the App (identifier com.alwaysconnect.app,
/// shared by the menu-bar App and its settings window) signed with the
/// SAME certificate as the background service.
///
/// - Developer-team signature: same team, Apple-anchored.
/// - Certificate without a team (the self-signed "AlwaysConnect Local
///   Dev" identity every release and local build uses, §35.5): same
///   leaf certificate, by its SHA-1, the form codesign itself writes.
/// - No certificate at all (ad-hoc or unsigned): nil, and nobody is
///   accepted. The old check compared team identifiers, which both
///   self-signed and ad-hoc builds lack, so it let every local process
///   in (§36.3).
enum ClientRequirement {
    static let appIdentifier = "com.alwaysconnect.app"

    /// The requirement for clients of this running process.
    static let forThisProcess: String? = {
        var selfCode: SecCode?
        guard SecCodeCopySelf([], &selfCode) == errSecSuccess, let selfCode else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(selfCode, [], &staticCode) == errSecSuccess,
              let staticCode
        else { return nil }
        return derived(from: staticCode)
    }()

    /// The requirement for clients of the background service signed as
    /// `code`; nil when that signature carries no certificate.
    static func derived(from code: SecStaticCode) -> String? {
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(
                code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any]
        else { return nil }
        let team = dict[kSecCodeInfoTeamIdentifier as String] as? String
        let leaf = (dict[kSecCodeInfoCertificates as String] as? [SecCertificate])?.first
        return make(team: team, leafDER: leaf.map { SecCertificateCopyData($0) as Data })
    }

    static func make(team: String?, leafDER: Data?) -> String? {
        let identifier = "identifier \"\(appIdentifier)\""
        if let team, !team.isEmpty, team.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }) {
            return "\(identifier) and anchor apple generic and certificate leaf[subject.OU] = \"\(team)\""
        }
        guard let leafDER, !leafDER.isEmpty else { return nil }
        let hex = Insecure.SHA1.hash(data: leafDER).map { String(format: "%02x", $0) }.joined()
        return "\(identifier) and certificate leaf = H\"\(hex)\""
    }

    /// Whether the code on disk satisfies `requirement` (harness, and
    /// the shape of the live check below).
    static func staticCode(_ code: SecStaticCode, satisfies requirement: String) -> Bool {
        guard let compiled = compile(requirement) else { return false }
        return SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), compiled)
            == errSecSuccess
    }

    /// Early refusal at the listener, by pid. A pid can be reused, so
    /// this is not the guarantee: NSXPCConnection.setCodeSigningRequirement
    /// with the same string checks every message by audit token.
    static func runningProcess(pid: pid_t, satisfies requirement: String) -> Bool {
        guard let compiled = compile(requirement) else { return false }
        let attributes = [kSecGuestAttributePid: pid] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code
        else { return false }
        return SecCodeCheckValidity(code, [], compiled) == errSecSuccess
    }

    private static func compile(_ requirement: String) -> SecRequirement? {
        var compiled: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &compiled) == errSecSuccess
        else { return nil }
        return compiled
    }
}

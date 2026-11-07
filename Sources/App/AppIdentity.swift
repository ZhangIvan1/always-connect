import CryptoKit
import Foundation
import Security

/// Security.framework shell for the running App and its short-lived children.
enum AppIdentity {
    private static func ownCode() -> (SecCode, SecStaticCode)? {
        var code: SecCode?
        var disk: SecStaticCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCheckValidity(code, [], nil) == errSecSuccess,
              SecCodeCopyStaticCode(code, [], &disk) == errSecSuccess, let disk else { return nil }
        return (code, disk)
    }

    /// Always pin the leaf, including Apple team signatures. No certificate
    /// means no automatic root execution; ad-hoc builds can still be tested.
    static var leafRequirement: String? {
        guard let (code, disk) = ownCode() else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(disk, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any],
              let leaf = (dict[kSecCodeInfoCertificates as String] as? [SecCertificate])?.first else { return nil }
        let hash = Insecure.SHA1.hash(data: SecCertificateCopyData(leaf) as Data)
            .map { String(format: "%02x", $0) }.joined()
        let text = "identifier \"com.alwaysconnect.app\" and certificate leaf = H\"\(hash)\""
        guard let requirement = compile(text),
              SecCodeCheckValidity(code, [], requirement) == errSecSuccess else { return nil }
        return text
    }

    private static func compile(_ text: String) -> SecRequirement? {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess else { return nil }
        return requirement
    }

    /// Check the actual parent before reading any script or settings input.
    /// A retained dynamic SecCode checks the running process; checking ppid
    /// again prevents accepting an orphan or a changed parent. Ad-hoc local
    /// children must match this exact code-directory hash and executable path.
    static func hasAppParent() -> Bool {
        let pid = getppid()
        guard pid > 1, let (_, disk) = ownCode(),
              let executable = Bundle.main.executableURL?.resolvingSymlinksInPath() else { return false }
        var requirement: SecRequirement?
        if let leaf = leafRequirement {
            requirement = compile(leaf)
        } else {
            var info: CFDictionary?
            guard SecCodeCopySigningInformation(disk, [], &info) == errSecSuccess,
                  let dict = info as? [String: Any],
                  let flags = dict[kSecCodeInfoFlags as String] as? NSNumber,
                  flags.uint32Value & SecCodeSignatureFlags.adhoc.rawValue != 0 else { return false }
            guard SecCodeCopyDesignatedRequirement(disk, [], &requirement) == errSecSuccess else { return false }
        }
        guard let requirement else { return false }
        var parent: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &parent) == errSecSuccess,
              let parent, SecCodeCheckValidity(parent, [], requirement) == errSecSuccess else { return false }
        var parentDisk: SecStaticCode?
        var info: CFDictionary?
        guard SecCodeCopyStaticCode(parent, [], &parentDisk) == errSecSuccess, let parentDisk,
              SecCodeCopySigningInformation(parentDisk, [], &info) == errSecSuccess,
              let dict = info as? [String: Any],
              let path = dict[kSecCodeInfoMainExecutable as String] as? URL,
              path.resolvingSymlinksInPath() == executable,
              SecCodeCheckValidity(parent, [], requirement) == errSecSuccess,
              getppid() == pid else { return false }
        return true
    }
}

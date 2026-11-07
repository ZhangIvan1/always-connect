import Foundation

@main struct PrivilegedBundleTest {
    static func main() throws {
        let bundle = "/example/a ' quoted/AlwaysConnect.app"
        let requirement = "identifier \"com.alwaysconnect.app\" and certificate leaf = H\"0123456789abcdef0123456789abcdef01234567\""
        let script = PrivilegedBundle.bootstrap(bundle: bundle, requirement: requirement,
                                               resource: "dev-helper.sh", arguments: ["install"], helper: true)
        let copy = script.range(of: "/usr/bin/ditto ")!
        let verify = script.range(of: "/usr/bin/codesign --verify --strict --deep -R=")!
        let execute = script.range(of: "/bin/bash \"$app/Contents/Resources/dev-helper.sh\"")!
        precondition(copy.lowerBound < verify.lowerBound && verify.lowerBound < execute.lowerBound)
        precondition(script.contains("umask 077") && script.contains("/bin/chmod 700 \"$stage\""))
        precondition(script.contains(PrivilegedBundle.shellQuoted(bundle)))
        precondition(script.contains(PrivilegedBundle.shellQuoted(requirement)))
        precondition(script.contains("\"$app/Contents/Library/LaunchDaemons/AlwaysConnectHelper\""))
        precondition(script.contains("exit 1"))
        let output = URL(fileURLWithPath: CommandLine.arguments[1])
        try script.write(to: output, atomically: true, encoding: .utf8)
        // Compile the complete AppleScript, including both shell and AppleScript
        // quoting. Never execute it or request administrator authorization.
        let source = "do shell script " + PrivilegedBundle.appleScriptString("/bin/bash -c " + PrivilegedBundle.shellQuoted(script))
            + " with prompt " + PrivilegedBundle.appleScriptString("包含 \"引号\" 的提示") + " with administrator privileges"
        var error: NSDictionary?
        guard let appleScript = NSAppleScript(source: source), appleScript.compileAndReturnError(&error) else {
            fputs("FAIL AppleScript compilation\n", stderr); exit(1)
        }
        print("PASS copy/verify/execute ordering, private staging, shell and AppleScript quoting")
    }
}

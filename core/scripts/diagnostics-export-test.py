#!/usr/bin/env python3
"""Production fake CLI -> production Swift shell -> unchanged diagnosticsText.
Only the UI/configuration data are stubs; no App or real VPN is launched.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
parser.add_argument("--sample", type=Path)
parser.add_argument("--unsafe-detail-control", action="store_true")
args = parser.parse_args()
root = args.root.resolve()

fixture = r'''
import AppKit
import Foundation
struct Server { var name: String; var address: String; var ciscoName: String? }
enum Mode { case secure, split }
struct Profile {
    var server = "gateway-canary.example"
    var group = "GROUP_CANARY_7"
    var servers = [Server(name: "SERVER_NAME_CANARY_8", address: "https://gateway-canary.example", ciscoName: "CISCO_NAME_CANARY_8")]
    var defaultMode = Mode.secure
    var autoConnectOnLaunch = true
}
enum Direction { case viaVPN, direct }
enum RuleType: String { case injected = "RULE_TYPE_CANARY_8" }
struct Rule {
    var type = RuleType.injected
    var target = "RULE_TARGET_CANARY_8.example"
    var direction = Direction.viaVPN
    var isEnabled = true
}
enum ProfileStore { static func loadRules() -> [Rule] { [Rule()] } }
final class HelperClient {
    enum State: Int, CustomStringConvertible {
        case disconnected = 0, connecting, authenticating, awaitingApproval, connected, reconnecting
        var description: String { "STATE_DESCRIPTION_CANARY_8" }
    }
    var state = State.disconnected
    var detail = ""
    var helperAvailable = true
    var dropHistory = [DropRecord(droppedAt: Date(timeIntervalSince1970: 0),
        recoveredAt: Date(timeIntervalSince1970: 60), outcome: .failed, retries: 2,
        approvals: 1, engine: "ENGINE_CANARY_8", failureReason: "HISTORY_CANARY_8 USER_CANARY_7 203.0.113.73 backup-canary.example")]
    func ciscoTimelineForDiagnostics(_ done: @escaping (String) -> Void) { done("") }
}
enum CiscoProfiles {
    static func resolve(_ value: String) -> String { "" }
    static func hostEntries() -> [String: String] { [:] }
}
@_silgen_name("ac_string_free") func ac_string_free(_ value: UnsafeMutablePointer<CChar>?)
@main struct FullExportTest {
    static func main() {
        let client = HelperClient()
        let profile = Profile()
        CiscoEngine.cliPath = CommandLine.arguments[1]
        CiscoEngine.physicalAvailability = { true }
        CiscoEngine.monitorInterval = 60
        let engine = CiscoEngine()
        engine.credentialsProvider = { .init(entry: profile.server, username: "USER_CANARY_7", password: "synthetic-only") }
        var got = false
        engine.onState = { state, detail in
            client.state = state
            client.detail = detail
            if detail.contains("RAW_CANARY_7") { got = true }
        }
        engine.connect()
        let deadline = Date().addingTimeInterval(10)
        while !got && Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.03)) }
        let timeline = engine.timelineText
        let exported = DiagnosticsExporter.fixtureText(client, profile, timeline)
        let malformed = DiagnosticsExporter.fixtureText(client, profile, timeline + "TIMELINE_CANARY_8\n")
        let tokens = ["gateway-canary.example", "GROUP_CANARY_7", "USER_CANARY_7", "203.0.113.73",
            "RAW_CANARY_7", "backup-canary.example", "SERVER_NAME_CANARY_8", "CISCO_NAME_CANARY_8",
            "RULE_TYPE_CANARY_8", "RULE_TARGET_CANARY_8.example", "STATE_DESCRIPTION_CANARY_8",
            "ENGINE_CANARY_8", "HISTORY_CANARY_8", "TIMELINE_CANARY_8"]
        let leaks = tokens.filter { exported.contains($0) || malformed.contains($0) }
        var done = false
        engine.disconnect { done = true }
        let stopped = Date().addingTimeInterval(10)
        while !done && Date() < stopped { RunLoop.main.run(until: Date().addingTimeInterval(0.03)) }
        if CommandLine.arguments.count > 2 {
            try! exported.write(toFile: CommandLine.arguments[2], atomically: true, encoding: .utf8)
        }
        print("production CLI -> production state callback -> unchanged diagnosticsText")
        print("fake error delivered=\(got); local stop completed=\(done); full bundle leaks=\(leaks)")
        let useful = exported.contains("Cisco 引擎时间线：") && exported.contains("request-connect")
            && exported.contains("重试 2 次") && exported.contains("认证中")
        exit(got && done && useful && leaks.isEmpty ? 0 : 1)
    }
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix="diagnostics-export-") as temporary:
        work = Path(temporary)
        source = (root / "Sources/App/DiagnosticsExporter.swift").read_text()
        if args.unsafe_detail_control:
            needle = "let detail = DiagnosticsRedaction.classify(.detail, manager.detail)"
            assert source.count(needle) == 1
            source = source.replace(needle, "let detail = manager.detail")
        # Same-file extension can call the private method without rewriting it.
        source += '''\nextension DiagnosticsExporter {
    static func fixtureText(_ manager: HelperClient, _ profile: Profile, _ timeline: String) -> String {
        diagnosticsText(manager: manager, profile: profile, ciscoTimeline: timeline)
    }
}\n'''
        exporter = work / "DiagnosticsExporter.swift"
        exporter.write_text(source)
        swift = work / "Fixture.swift"
        swift.write_text(fixture)
        cli = work / "vpn"
        cli.write_text("""#!/bin/sh
case "$1" in
state) echo '>> state: Disconnected';;
-s) echo '>> error: RAW_CANARY_7 gateway-canary.example USER_CANARY_7 203.0.113.73 GROUP_CANARY_7 backup-canary.example';;
disconnect) echo '>> state: Disconnected';;
esac
""")
        cli.chmod(0o700)
        executable = work / "test"
        subprocess.run(["swiftc", "-O", "-parse-as-library",
            str(root / "Sources/Shared/PhysicalConnectivity.swift"),
            str(root / "Sources/App/CiscoEngine.swift"), str(root / "Sources/App/DropHistory.swift"),
            str(root / "Sources/App/DiagnosticsRedaction.swift"), str(exporter), str(swift),
            str(root / "core/target/release/libalwaysconnect_core.a"), "-o", str(executable)], check=True)
        command = [str(executable), str(cli)]
        if args.sample:
            command.append(str(args.sample))
        return subprocess.run(command, timeout=45).returncode

if __name__ == "__main__":
    raise SystemExit(main())

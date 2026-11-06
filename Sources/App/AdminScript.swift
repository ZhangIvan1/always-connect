import AppKit
import Foundation

/// AppleScript "do shell script … with administrator privileges" run in a
/// short-lived child process (DESIGN.md §32.16): the AppleScript runtime
/// stays loaded in whatever process ran it (~15 MB, measured), and the
/// menu-bar App would carry that for the rest of the day after one
/// background-service update or network reset. The child is the App's
/// own binary (`--admin-script`), so the password dialog still names
/// AlwaysConnect; it reads the script on stdin, answers one JSON line on
/// stdout and exits.
enum AdminScript {
    struct Result {
        var output: String
        /// nil = success; -128 = the user cancelled.
        var errorNumber: Int?
        var errorMessage: String?
    }

    static let flag = "--admin-script"
    static var isChild: Bool { CommandLine.arguments.contains(flag) }

    /// Runs `source`; `completion` on the main queue.
    static func run(_ source: String, completion: @escaping (Result) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            let result = runInChild(source) ?? runHere(source)
            DispatchQueue.main.async { completion(result) }
        }
    }

    private static func runInChild(_ source: String) -> Result? {
        guard let executable = Bundle.main.executableURL else { return nil }
        let p = Process()
        p.executableURL = executable
        p.arguments = [flag]
        let input = Pipe(), output = Pipe()
        p.standardInput = input
        p.standardOutput = output
        p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return nil }
        try? input.fileHandleForWriting.write(contentsOf: Data(source.utf8))
        try? input.fileHandleForWriting.close()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
        return Result(output: json["output"] as? String ?? "",
                      errorNumber: json["errorNumber"] as? Int,
                      errorMessage: json["errorMessage"] as? String)
    }

    private static func runHere(_ source: String) -> Result {
        var error: NSDictionary?
        let value = NSAppleScript(source: source)?.executeAndReturnError(&error)
        guard let error else { return Result(output: value?.stringValue ?? "") }
        return Result(output: "",
                      errorNumber: error[NSAppleScript.errorNumber] as? Int ?? 0,
                      errorMessage: error[NSAppleScript.errorMessage] as? String)
    }

    /// The child: one script from stdin, one answer, exit.
    static func serveAndExit() -> Never {
        let source = String(decoding: FileHandle.standardInput.readDataToEndOfFile(), as: UTF8.self)
        let result = runHere(source)
        var json: [String: Any] = ["output": result.output]
        if let n = result.errorNumber { json["errorNumber"] = n }
        if let m = result.errorMessage { json["errorMessage"] = m }
        let data = (try? JSONSerialization.data(withJSONObject: json)) ?? Data("{}".utf8)
        FileHandle.standardOutput.write(data)
        exit(0)
    }
}

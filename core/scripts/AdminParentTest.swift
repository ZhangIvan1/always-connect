import Foundation

@main struct AdminParentTest {
    static func main() {
        if CommandLine.arguments.contains("--admin-script") { AdminScript.serveAndExit() }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: CommandLine.arguments.dropFirst().first ?? CommandLine.arguments[0])
        p.arguments = ["--admin-script"]
        let input = Pipe(), output = Pipe()
        p.standardInput = input
        p.standardOutput = output
        do { try p.run() } catch { exit(1) }
        try? input.fileHandleForWriting.write(contentsOf: Data("return \"ok\"".utf8))
        try? input.fileHandleForWriting.close()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        if CommandLine.arguments.count > 1 {
            guard p.terminationStatus == 77 else { exit(1) }
        } else {
            guard p.terminationStatus == 0,
                  let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                  json["output"] as? String == "ok" else {
                fputs("child status=\(p.terminationStatus), reply=\(String(decoding: data, as: UTF8.self))\n", stderr)
                exit(1)
            }
        }
    }
}

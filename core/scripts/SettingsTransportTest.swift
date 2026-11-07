import Foundation
import Darwin

@main struct SettingsTransportTest {
    static var channels: [SettingsTransport] = []
    static func pair() -> [Int32] {
        var fds: [Int32] = [-1, -1]
        precondition(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        return fds
    }
    static var child: Process?
    static func main() {
        if CommandLine.arguments.contains("--child") {
            let channel = SettingsTransport(input: STDIN_FILENO, output: STDOUT_FILENO, receive: { message in
                precondition(message["type"] == "request")
                channels[0].send(["type": "reply"])
            }, ended: { exit(0) })
            channels = [channel]
        } else {
            let fds = pair()
            let p = Process()
            let handle = FileHandle(fileDescriptor: fds[1], closeOnDealloc: true)
            _ = fcntl(fds[0], F_SETFD, FD_CLOEXEC)
            _ = fcntl(fds[1], F_SETFD, FD_CLOEXEC)
            p.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
            p.arguments = ["--child"]
            p.standardInput = handle
            p.standardOutput = handle
            p.terminationHandler = { ended in
                DispatchQueue.main.async {
                    precondition(ended.terminationStatus == 0)
                    print("PASS child inherits private stdin/stdout; parent close exits child")
                    runInProcessTests()
                }
            }
            do { try p.run() } catch { exit(1) }
            try? handle.close()
            child = p
            let channel = SettingsTransport(input: fds[0], output: dup(fds[0]), receive: { message in
                precondition(message["type"] == "reply")
                channels[0].close()
            }, ended: {})
            channels = [channel]
            channel.send(["type": "request"])
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) { fputs("FAIL timeout\n", stderr); exit(1) }
        dispatchMain()
    }
    static func runInProcessTests() {
        let fds = pair()
        let count = 100
        var replies = 0
        let left = SettingsTransport(input: fds[0], output: dup(fds[0]), receive: { message in
            precondition(message["type"] == "reply")
            replies += 1
            if replies == count {
                print("PASS ordered private request/reply with escaped newlines")
                testMalformed()
            }
        }, ended: {})
        let right = SettingsTransport(input: fds[1], output: dup(fds[1]), receive: { message in
            precondition(message["arg"] == "first\nsecond")
            channels[1].send(["type": "reply"])
        }, ended: {})
        channels = [left, right]
        for _ in 0..<count { left.send(["type": "action", "arg": "first\nsecond"]) }
    }
    static func testMalformed() {
        channels.forEach { $0.close() }
        let fds = pair()
        let channel = SettingsTransport(input: fds[0], output: dup(fds[0]), receive: { _ in
            fputs("FAIL malformed input accepted\n", stderr); exit(1)
        }, ended: {
            Darwin.close(fds[1])
            print("PASS malformed input closes transport")
            testBound()
        })
        channels = [channel]
        let data = Data("{broken}\n".utf8)
        _ = data.withUnsafeBytes { Darwin.write(fds[1], $0.baseAddress, $0.count) }
    }
    static func testBound() {
        let fds = pair()
        let channel = SettingsTransport(input: fds[0], output: dup(fds[0]), receive: { _ in }, ended: {
            Darwin.close(fds[1])
            print("PASS outgoing buffer is bounded; close returns descriptors")
            testEOF()
        })
        channels = [channel]
        channel.send(["json": String(repeating: "x", count: 1024 * 1024 + 1)])
    }
    static func testEOF() {
        let fds = pair()
        let channel = SettingsTransport(input: fds[0], output: dup(fds[0]), receive: { _ in }, ended: {
            print("PASS parent EOF closes the settings channel")
            exit(0)
        })
        channels = [channel]
        Darwin.close(fds[1])
    }
}

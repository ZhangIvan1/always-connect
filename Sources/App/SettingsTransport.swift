import Foundation
import Darwin

/// Anonymous socket inherited only by the settings child as stdin/stdout.
/// Event-driven, bounded JSON lines; no named endpoint, broadcast or secret.
final class SettingsTransport {
    private let queue = DispatchQueue(label: "com.alwaysconnect.settings.pipe")
    private let input: Int32
    private let output: Int32
    private var reader: DispatchSourceRead?
    private var writer: DispatchSourceWrite?
    private var received = Data()
    private var pending = Data()
    private var closed = false
    private let receive: ([String: String]) -> Void
    private let ended: () -> Void
    private static let limit = 1024 * 1024

    init(input: Int32, output: Int32, receive: @escaping ([String: String]) -> Void,
         ended: @escaping () -> Void) {
        self.input = input
        self.output = output
        self.receive = receive
        self.ended = ended
        for fd in [input, output] {
            _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
            _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
            var yes: Int32 = 1
            _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size))
        }
        let source = DispatchSource.makeReadSource(fileDescriptor: input, queue: queue)
        source.setEventHandler { [weak self] in self?.readReady() }
        source.setCancelHandler { Darwin.close(input) }
        reader = source
        source.resume()
    }

    func send(_ message: [String: String]) {
        guard var bytes = try? JSONSerialization.data(withJSONObject: message) else { return }
        bytes.append(10)
        queue.async { [self, bytes] in
            guard !closed else { return }
            guard pending.count + bytes.count <= Self.limit else { closeLocked(); return }
            pending.append(bytes)
            writeReady()
        }
    }

    func close() { queue.async { [self] in closeLocked() } }

    private func readReady() {
        guard !closed else { return }
        var buffer = [UInt8](repeating: 0, count: 8192)
        while true {
            let count = Darwin.read(input, &buffer, buffer.count)
            if count < 0 && errno == EINTR { continue }
            if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) { return }
            guard count > 0 else { closeLocked(); return }
            received.append(contentsOf: buffer.prefix(count))
            guard received.count <= Self.limit else { closeLocked(); return }
            while let newline = received.firstIndex(of: 10) {
                let line = Data(received[..<newline])
                received.removeSubrange(...newline)
                guard let message = (try? JSONSerialization.jsonObject(with: line)) as? [String: String] else {
                    closeLocked(); return
                }
                DispatchQueue.main.async { [receive] in receive(message) }
            }
        }
    }

    private func writeReady() {
        guard !closed else { return }
        while !pending.isEmpty {
            let count = pending.withUnsafeBytes { Darwin.write(output, $0.baseAddress!, $0.count) }
            if count < 0 && errno == EINTR { continue }
            if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                if writer == nil {
                    let source = DispatchSource.makeWriteSource(fileDescriptor: output, queue: queue)
                    source.setEventHandler { [weak self] in self?.writeReady() }
                    writer = source
                    source.resume()
                }
                return
            }
            guard count > 0 else { closeLocked(); return }
            pending.removeFirst(count)
        }
        writer?.cancel()
        writer = nil
    }

    private func closeLocked() {
        guard !closed else { return }
        closed = true
        reader?.cancel()
        reader = nil
        if let writer {
            let fd = output
            writer.setCancelHandler { Darwin.close(fd) }
            writer.cancel()
            self.writer = nil
        } else {
            Darwin.close(output)
        }
        received = Data()
        pending = Data()
        DispatchQueue.main.async(execute: ended)
    }
}

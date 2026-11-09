// Harness for the DNS forwarder (DESIGN.md §26.4, §32.6). Loopback only:
// fake upstream DNS servers on their own ports stand in for the local
// network's DNS and the tunnel's. Compiled with the Swift shell
// Sources/Helper/DNSForwarder.swift and linked with the Rust staticlib
// that does the work; the rule kinds and wire format have Rust unit tests
// (core/src/dns_forwarder.rs).
import Darwin
import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String) {
    print((ok ? "ok   " : "FAIL ") + what)
    if !ok { failures += 1 }
}

enum DNSMessage {
    static let typeA: UInt16 = 1
    static let typeAAAA: UInt16 = 28
    static let typeHTTPS: UInt16 = 65

    /// The A records of an answer built by `answer(to:ip:)` below.
    static func ipv4Answers(_ m: [UInt8]) -> [String] {
        guard m.count >= 12, m[7] > 0, m.count >= 4 else { return [] }
        let ip = m.suffix(4)
        return [ip.map(String.init).joined(separator: ".")]
    }
}

enum Framed {
    static func read(_ fd: Int32) -> [UInt8]? {
        guard let head = exactly(fd, 2) else { return nil }
        let length = Int(head[0]) << 8 | Int(head[1])
        return length > 0 ? exactly(fd, length) : nil
    }

    private static func exactly(_ fd: Int32, _ count: Int) -> [UInt8]? {
        var out = [UInt8](repeating: 0, count: count)
        var got = 0
        while got < count {
            let n = out.withUnsafeMutableBytes { recv(fd, $0.baseAddress! + got, count - got, 0) }
            guard n > 0 else { return nil }
            got += n
        }
        return out
    }

    static func write(_ fd: Int32, _ message: [UInt8]) {
        let framed = [UInt8(message.count >> 8), UInt8(message.count & 0xff)] + message
        _ = framed.withUnsafeBytes { send(fd, $0.baseAddress!, framed.count, 0) }
    }
}

func query(_ name: String, type: UInt16, id: UInt16 = 0x1234) -> [UInt8] {
    var m: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xff), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
    for label in name.split(separator: ".") { m.append(UInt8(label.utf8.count)); m += Array(label.utf8) }
    m += [0, UInt8(type >> 8), UInt8(type & 0xff), 0, 1]
    return m
}

/// An HTTPS record's data: priority 1, TargetName ".", alpn h3.
let httpsKept: [UInt8] = [0, 1, 0, 0, 1, 0, 3, 2, 0x68, 0x33]

/// The question echoed back with one A record (compressed name pointer);
/// an HTTPS question gets an HTTPS record with alpn and an ipv4hint.
func answer(to q: [UInt8], ip: [UInt8], truncated: Bool = false) -> [UInt8] {
    var m = q
    if !truncated, q.count >= 2, Array(q.suffix(4).prefix(2)) == [0, UInt8(DNSMessage.typeHTTPS)] {
        let data = httpsKept + [0, 4, 0, 4] + ip
        m[2] = 0x81; m[3] = 0x80; m[6] = 0; m[7] = 1
        return m + [0xC0, 0x0C, 0, 65, 0, 1, 0, 0, 1, 44, 0, UInt8(data.count)] + data
    }
    m[2] = 0x81 | (truncated ? 0x02 : 0); m[3] = 0x80
    m[6] = 0; m[7] = truncated ? 0 : 1
    if !truncated { m += [0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4] + ip }
    return m
}

final class FakeServer {
    let port: UInt16
    var udpQueries = 0
    var tcpQueries = 0
    init(port: UInt16, udp: Bool, tcp: Bool, ip: [UInt8], truncateUDP: Bool = false) {
        self.port = port
        if udp {
            let fd = socket(AF_INET, SOCK_DGRAM, 0)
            bindLoopback(fd, port)
            Thread.detachNewThread { [self] in
                var buf = [UInt8](repeating: 0, count: 2048)
                var from = sockaddr_storage(); var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
                while true {
                    let n = withUnsafeMutablePointer(to: &from) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buf, buf.count, 0, $0, &len) } }
                    guard n > 0 else { continue }
                    udpQueries += 1
                    let a = answer(to: Array(buf[0..<n]), ip: ip, truncated: truncateUDP)
                    _ = withUnsafePointer(to: &from) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, a, a.count, 0, $0, len) } }
                }
            }
        }
        if tcp {
            let fd = socket(AF_INET, SOCK_STREAM, 0)
            var one: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
            bindLoopback(fd, port)
            listen(fd, 8)
            Thread.detachNewThread { [self] in
                while true {
                    let c = accept(fd, nil, nil)
                    guard c >= 0 else { continue }
                    if let q = Framed.read(c) {
                        tcpQueries += 1
                        Framed.write(c, answer(to: q, ip: ip))
                    }
                    close(c)
                }
            }
        }
    }
}

func bindLoopback(_ fd: Int32, _ port: UInt16) {
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET); addr.sin_port = port.bigEndian
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr)
    _ = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
}

/// Ask the forwarder over UDP like the system resolver does.
func ask(_ q: [UInt8], port: UInt16) -> [UInt8]? {
    let fd = socket(AF_INET, SOCK_DGRAM, 0)
    defer { close(fd) }
    var tv = timeval(tv_sec: 6, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
    var addr = sockaddr_in(); addr.sin_family = sa_family_t(AF_INET); addr.sin_port = port.bigEndian
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr)
    _ = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, q, q.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
    var buf = [UInt8](repeating: 0, count: 4096)
    let n = recv(fd, &buf, buf.count, 0)
    return n > 0 ? Array(buf[0..<n]) : nil
}

func askTCP(_ q: [UInt8], port: UInt16) -> [UInt8]? {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    defer { close(fd) }
    var addr = sockaddr_in(); addr.sin_family = sa_family_t(AF_INET); addr.sin_port = port.bigEndian
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr)
    let ok = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
    guard ok == 0 else { return nil }
    Framed.write(fd, q)
    return Framed.read(fd)
}

@main
struct DNSForwarderTest {
    static func main() {
        let local = FakeServer(port: 5401, udp: true, tcp: true, ip: [203, 0, 113, 1])
        let tunnelGood = FakeServer(port: 5403, udp: true, tcp: true, ip: [198, 51, 100, 2])
        let tunnelTrunc = FakeServer(port: 5404, udp: true, tcp: true, ip: [198, 51, 100, 4], truncateUDP: true)
        usleep(200_000)

        var events: [String] = []
        let eventLock = NSLock()
        func note(_ e: String) { eventLock.lock(); events.append(e); eventLock.unlock() }
        let fwd = DNSForwarder(config: .init(listenAddress: "127.0.0.1", port: 5400,
                                             tunnelServers: ["127.0.0.1:5402", "127.0.0.1:5403"],
                                             localServers: ["127.0.0.1:5401"], physicalIf: nil,
                                             upstreamPort: 53, timeout: 0.5),
                               directDomains: ["sitea.com"])
        fwd.onDirect = { entry, ips in
            usleep(100_000)
            note("direct " + ips.joined(separator: ","))
            if entry != "sitea.com" { note("wrong entry " + entry) }
        }
        do { try fwd.start() } catch { check(false, "forwarder listens: \(error)"); exit(1) }

        // 1 a direct name: local DNS, routed before the answer comes back
        let a1 = ask(query("www.sitea.com", type: DNSMessage.typeA), port: 5400)
        note("answer")
        check(a1.map(DNSMessage.ipv4Answers) == ["203.0.113.1"], "direct name answered by the local DNS")
        check(events == ["direct 203.0.113.1", "answer"], "its addresses routed direct before the answer (\(events))")
        check(local.udpQueries == 1 && tunnelGood.udpQueries == 0, "only the local DNS was asked")

        // 2 IPv4 only for direct names
        let a2 = ask(query("www.sitea.com", type: DNSMessage.typeAAAA), port: 5400)
        check(a2 != nil && a2![7] == 0 && a2![3] & 0x0F == 0, "direct AAAA: empty NOERROR answer")
        check(local.udpQueries == 1, "AAAA never reached the local DNS")
        let a3 = ask(query("www.sitea.com", type: DNSMessage.typeHTTPS), port: 5400)
        let hintless = [0xC0, 0x0C, 0, 65, 0, 1, 0, 0, 1, 44, 0, UInt8(httpsKept.count)] + httpsKept
        check(a3 != nil && a3![7] == 1 && Array(a3!.suffix(hintless.count)) == hintless
              && a3!.count == query("www.sitea.com", type: DNSMessage.typeHTTPS).count + hintless.count,
              "direct HTTPS record: passed on from the local DNS without its address hint")
        check(local.udpQueries == 2, "the HTTPS question went to the local DNS")

        // 3 everything else: tunnel DNS, next server when the first is down
        events.removeAll()
        let a4 = ask(query("intranet.example", type: DNSMessage.typeA), port: 5400)
        check(a4.map(DNSMessage.ipv4Answers) == ["198.51.100.2"], "other names: second tunnel server after the first failed")
        check(events.isEmpty, "nothing routed direct for them")

        // 3b IPv4 only for every name in split mode (§28.3)
        let before = tunnelGood.udpQueries
        let a4v6 = ask(query("intranet.example", type: DNSMessage.typeAAAA), port: 5400)
        check(a4v6 != nil && a4v6![7] == 0 && a4v6![3] & 0x0F == 0, "other names' AAAA: empty NOERROR answer")
        check(tunnelGood.udpQueries == before, "...without asking the tunnel's DNS")
        let a4h = ask(query("intranet.example", type: DNSMessage.typeHTTPS), port: 5400)
        check(a4h != nil && a4h![7] == 1 && Array(a4h!.suffix(hintless.count)) == hintless,
              "other names' HTTPS record: passed on without its address hint")

        // 4 truncated over UDP: the same server again over TCP
        fwd.update(tunnelServers: ["127.0.0.1:5404"], localServers: ["127.0.0.1:5401"], physicalIf: nil)
        let a5 = ask(query("big.example", type: DNSMessage.typeA), port: 5400)
        check(a5.map(DNSMessage.ipv4Answers) == ["198.51.100.4"] && tunnelTrunc.tcpQueries == 1,
              "truncated UDP answer retried over TCP")

        // 5 clients may ask over TCP too
        let a6 = askTCP(query("m.sitea.com", type: DNSMessage.typeA, id: 0x4321), port: 5400)
        check(a6.map(DNSMessage.ipv4Answers) == ["203.0.113.1"], "TCP client answered")

        // 6 the list changes live
        fwd.update(directDomains: [])
        events.removeAll()
        _ = ask(query("www.sitea.com", type: DNSMessage.typeA), port: 5400)
        check(events.isEmpty, "a removed domain is no longer routed direct")

        // 7 geoip (§26.13): asked through the tunnel, routed direct when
        // the answer falls in a listed range; AAAA left alone
        fwd.update(directDomains: ["ipcidr:198.51.100.0/24"])
        events.removeAll()
        let a7 = ask(query("www.siteb.com", type: DNSMessage.typeA), port: 5400)
        note("answer")
        check(a7.map(DNSMessage.ipv4Answers) == ["198.51.100.4"], "answered by the tunnel's DNS")
        check(events == ["direct 198.51.100.4", "wrong entry siteb.com", "answer"],
              "an answer in the range is routed direct before it is returned (\(events))")
        fwd.update(directDomains: ["ipcidr:192.0.2.0/24"])
        events.removeAll()
        _ = ask(query("www.example.com", type: DNSMessage.typeA), port: 5400)
        check(events.isEmpty, "an answer outside the ranges stays in the tunnel")

        fwd.stop()
        print("dns-forwarder FAILS=\(failures)")
        exit(failures == 0 ? 0 : 1)
    }
}

// Declared by PfAnchor.swift in the Helper; this harness links only the
// forwarder's shell.
@_silgen_name("ac_string_free")
func ac_string_free(_ s: UnsafeMutablePointer<CChar>?)

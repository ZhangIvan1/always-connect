import SwiftUI

/// Settings → 连接 (DESIGN.md §28.7, UI-DESIGN.md): every live connection
/// on this Mac, which program, which address (the name when the split
/// forwarder saw it), and whether it goes through the VPN or out the
/// local network, with the reason. Same program + address + way are one
/// row with a count, so a browser's dozen sockets read as one line.
struct ConnectionsPage: View {
    struct Row: Identifiable, Hashable {
        var process: String
        var address: String
        /// "HTTPS (TCP 443)", "QUIC (UDP 443)", "DNS (UDP 53)", ...
        var protocolName: String
        var via: String
        var reason: String
        var count: Int
        var id: String { process + "|" + address + "|" + protocolName + "|" + via + "|" + reason }
    }

    enum Filter: String, CaseIterable, Identifiable {
        case all = "全部", vpn = "走 VPN", direct = "直连"
        var id: String { rawValue }
    }

    /// Fixed data instead of the background service (screenshots).
    var preview: [ConnectionRow]? = nil
    @State private var rows: [Row] = []
    @State private var filter: Filter = .all
    @State private var search = ""
    @State private var message: String?
    @State private var updated: Date?
    private let timer = Timer.publish(every: 5, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                Picker("", selection: $filter) {
                    ForEach(Filter.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 220)
                TextField("搜程序或地址", text: $search)
                    .textFieldStyle(.roundedBorder)
                Button("刷新", action: refresh)
            }
            Text(summary)
                .font(.caption)
                .foregroundStyle(.secondary)
            Table(shown) {
                TableColumn("程序") { row in
                    Text(row.process).lineLimit(1)
                }
                .width(105)
                TableColumn("地址") { row in
                    Text(row.address + (row.count > 1 ? "  ×\(row.count)" : ""))
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .help(row.address)
                }
                .width(min: 120, ideal: 165)
                TableColumn("协议") { row in
                    Text(row.protocolName).lineLimit(1).help(row.protocolName)
                }
                .width(125)
                TableColumn("走向") { row in
                    Text(row.via == "vpn" ? "VPN" : row.via == "local" ? "本机" : "直连")
                        .foregroundStyle(row.via == "vpn" ? Color.green : row.via == "local" ? Color.secondary : Color.orange)
                }
                .width(42)
                TableColumn("原因") { row in
                    Text(row.reason).foregroundStyle(.secondary).lineLimit(1)
                }
                .width(min: 60, ideal: 80)
            }
            if let message {
                Text(message).font(.caption).foregroundStyle(.orange)
            }
            Text("只列正在通信的连接（含所有程序）。开着按网站分流时，地址会显示访问的域名；其他情况显示 IP。每 5 秒自动刷新。")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(16)
        .onAppear {
            if let preview { rows = Self.group(preview); updated = Date() } else { refresh() }
        }
        .onReceive(timer) { _ in if preview == nil { refresh() } }
    }

    private var shown: [Row] {
        rows.filter { row in
            switch filter {
            case .all: return true
            case .vpn: return row.via == "vpn"
            case .direct: return row.via == "direct"
            }
        }.filter { row in
            search.isEmpty || row.process.localizedCaseInsensitiveContains(search)
                || row.address.localizedCaseInsensitiveContains(search)
                || row.protocolName.localizedCaseInsensitiveContains(search)
        }
    }

    private var summary: String {
        let vpn = rows.filter { $0.via == "vpn" }.reduce(0) { $0 + $1.count }
        let direct = rows.filter { $0.via == "direct" }.reduce(0) { $0 + $1.count }
        let local = rows.filter { $0.via == "local" }.reduce(0) { $0 + $1.count }
        guard updated != nil else { return "读取中…" }
        return "走 VPN \(vpn) 条 · 直连 \(direct) 条 · 本机内部 \(local) 条"
    }

    private func refresh() {
        HelperClient.shared.fetchConnections { result in
            guard let result else {
                message = "后台服务没有回复：可能是旧版本（面板上点「更新」），或者还没装。"
                return
            }
            message = nil
            updated = Date()
            rows = Self.group(result)
        }
    }

    static func group(_ connections: [ConnectionRow]) -> [Row] {
        var grouped: [String: Row] = [:]
        for c in connections {
            // One row per program and address; ports would split a
            // browser's parallel connections into many lines.
            let address = c.host.map { "\($0) (\(c.remote))" } ?? c.remote
            let proto = protocolName(c.proto, c.port)
            let key = c.process + "|" + address + "|" + proto + "|" + c.via + "|" + c.reason
            if var row = grouped[key] {
                row.count += 1
                grouped[key] = row
            } else {
                grouped[key] = Row(process: c.process, address: address, protocolName: proto,
                                   via: c.via, reason: c.reason, count: 1)
            }
        }
        // VPN-less first is what people look for: direct, then VPN, then local.
        let order = ["direct": 0, "vpn": 1, "local": 2]
        return grouped.values.sorted {
            (order[$0.via] ?? 3, $0.process.lowercased(), $0.address) < (order[$1.via] ?? 3, $1.process.lowercased(), $1.address)
        }
    }

    /// What runs on top of TCP/UDP, from the remote port (the usual
    /// assignments; a guess, not packet inspection).
    static func protocolName(_ transport: String, _ port: Int) -> String {
        let udp = transport.uppercased() == "UDP"
        let name: String?
        switch (udp, port) {
        case (false, 443), (false, 8443): name = "HTTPS"
        case (true, 443): name = "QUIC (HTTP/3)"
        case (false, 80), (false, 8080): name = "HTTP"
        case (_, 53): name = "DNS"
        case (false, 853): name = "DNS over TLS"
        case (false, 22): name = "SSH"
        case (false, 993): name = "IMAPS"
        case (false, 465), (false, 587): name = "SMTP"
        case (false, 995): name = "POP3S"
        case (false, 5223): name = "Apple 推送"
        case (true, 123): name = "NTP"
        case (true, 3478), (true, 3479), (true, 19302): name = "STUN（音视频）"
        case (true, 5353): name = "mDNS"
        case (false, 3389): name = "远程桌面"
        case (false, 5900): name = "屏幕共享"
        case (false, 1080), (false, 7890): name = "代理"
        default: name = nil
        }
        let base = "\(udp ? "UDP" : "TCP") \(port)"
        return name.map { "\($0) · \(base)" } ?? base
    }
}

import SwiftUI
import Network

/// Connection policy belongs on 连接; 分流 remains about traffic paths.
struct OnDemandSettings: View {
    @State private var enabled = ProfileStore.loadAppSettings().onDemandEnabled == true
    @State private var rules = ProfileStore.loadAppSettings().onDemandRules ?? []
    @State private var editing: OnDemandRule?
    @State private var testResult: String?
    @State private var testing = false
    @State private var testGeneration = 0
    @State private var testMonitor: NWPathMonitor?
    @State private var testProbe: OnDemandNetworkProbe?
    @State private var testFacts: NetworkFacts?

    var body: some View {
        Section {
            Toggle("按规则自动连接", isOn: $enabled).onChange(of: enabled) { _ in save() }
            ForEach(Array(rules.enumerated()), id: \.element.id) { index, rule in
                OnDemandRuleRow(rule: rule, first: index == 0, last: index + 1 == rules.count,
                    move: { offset in
                        rules.swapAt(index, index + offset)
                        save()
                    }, edit: { editing = rule }, remove: {
                        rules.remove(at: index)
                        save()
                    })
            }
            if let draft = editing {
                OnDemandRuleEditor(rule: draft, cancel: { editing = nil }) { rule in
                    if let index = rules.firstIndex(where: { $0.id == rule.id }) {
                        rules[index] = rule
                    } else {
                        rules.append(rule)
                    }
                    editing = nil
                    save()
                }
                .id(draft.id)
            } else {
                Button { editing = OnDemandRule() } label: {
                    Label("添加规则", systemImage: "plus.circle.fill")
                }
                .buttonStyle(.borderless)
            }
            HStack {
                Button(testing ? "正在测试…" : "测试当前网络", action: test).disabled(testing || !enabled)
                Spacer()
                HoverHelp(action: {}) {
                    Text("从上到下匹配第一条规则；条件之间为且，同类多个值为或。断开后使用本地网络。\n"
                         + "Wi-Fi、网络类型和 DNS 条件可被伪造，建议增加受系统信任的 HTTPS 探针。\n"
                         + "仅在开启时读取网络；匹配 Wi-Fi 名称需要定位授权。")
                        .font(.caption).frame(width: 300, alignment: .leading)
                }
            }
            if let testResult { Text(testResult).font(.caption).textSelection(.enabled) }
        } header: {
            Text("按需连接")
        } footer: {
            Text("按顺序匹配规则；未命中时连接 VPN。")
                .font(.caption).foregroundStyle(.secondary)
        }
        .onDisappear {
            testing = false
            testGeneration += 1
            testProbe?.cancel()
            testProbe = nil
            testMonitor?.pathUpdateHandler = nil
            testMonitor?.cancel()
            testMonitor = nil
            testFacts = nil
        }
    }
    private func save() {
        var settings = ProfileStore.loadAppSettings()
        settings.onDemandEnabled = enabled
        settings.onDemandRules = rules
        ProfileStore.saveAppSettings(settings)
        HelperClient.shared.onDemandSettingsChanged()
        testGeneration += 1
        testProbe?.cancel()
        testProbe = nil
        testing = false
        testResult = nil
        testMonitor?.pathUpdateHandler = nil
        testMonitor?.cancel()
        testMonitor = nil
        testFacts = nil
    }
    private func test() {
        guard enabled else { return }
        testGeneration += 1
        let token = testGeneration
        testing = true
        // Settings child owns this read-only, short-lived monitor. It never
        // changes VPN state; the normal policy is evaluated by the App.
        let monitor = NWPathMonitor()
        testMonitor = monitor
        let reader = NetworkFacts()
        testFacts = reader
        monitor.pathUpdateHandler = { path in
            DispatchQueue.main.async {
                guard token == testGeneration else { return }
                monitor.pathUpdateHandler = nil
                monitor.cancel()
                testMonitor = nil
                let facts = reader.collect(path: path, needsSSID: rules.contains { !$0.ssids.isEmpty })
                let network = facts.network == "wifi" ? "Wi-Fi" : facts.network == "wired" ? "有线" : "未知"
                let description = [
                    "网络：\(network)",
                    "Wi-Fi 名称：\(facts.ssid ?? reader.locationDescription)",
                    "搜索域：\(facts.domains.joined(separator: ", "))",
                    "DNS 服务器：\(facts.servers.joined(separator: ", "))",
                ].joined(separator: "\n")
                testDecision(facts, reader: reader, description: description, token: token)
            }
        }
        monitor.start(queue: DispatchQueue(label: "com.alwaysconnect.on-demand.test"))
    }
    private func testDecision(_ facts: OnDemandFacts, reader: NetworkFacts, description: String, token: Int) {
        guard token == testGeneration else { return }
        let result = OnDemandCore.decide(enabled: true, rules: rules, facts: facts)
        if let probe = result.probe, let id = result.rule_id {
            let task = OnDemandNetworkProbe()
            testProbe = task
            task.run(probe, interface: reader.interface, servers: facts.servers) { matched in
                _ = task
                guard token == testGeneration else { return }
                testProbe = nil
                var facts = facts
                facts.probes[id] = matched
                testDecision(facts, reader: reader, description: description, token: token)
            }
        } else {
            let name = rules.first { $0.id == result.rule_id }?.name ?? "未命中规则"
            testResult = description + "\n结果：\(name) · \(actionName(result.action))（测试不会更改连接）"
            testing = false
            testFacts = nil
        }
    }
}
private func actionName(_ action: String) -> String {
    action == "disconnect" ? "断开 VPN，使用本地网络" : action == "ignore" ? "忽略，保持当前状态" : "连接 VPN"
}

/// Uses the same grouped Form row metrics and controls as the server and direct lists.
struct OnDemandRuleRow: View {
    var rule: OnDemandRule
    var first: Bool
    var last: Bool
    var move: (Int) -> Void
    var edit: () -> Void
    var remove: () -> Void
    private var tint: Color {
        rule.action == "disconnect" ? .orange : rule.action == "connect" ? .accentColor : .secondary
    }
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "network").foregroundStyle(.secondary).frame(width: 18)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(rule.name).lineLimit(1)
                    Text(rule.action == "disconnect" ? "断开" : rule.action == "ignore" ? "忽略" : "连接")
                        .font(.caption2).padding(.horizontal, 5).padding(.vertical, 1)
                        .background(Capsule().fill(tint.opacity(0.15))).foregroundStyle(tint)
                    let validation = OnDemandCore.validate(rule)
                    if !validation.valid || validation.weak {
                        HStack(spacing: 4) {
                            Text(validation.valid ? "可被伪造" : "需要修改").font(.caption).foregroundStyle(.orange)
                            HoverHelp(action: edit) {
                                Text(validation.error ?? "这些条件可被伪造，命中后流量走本地网络；可加受系统信任的 HTTPS 探针。")
                                    .font(.caption).frame(width: 260, alignment: .leading)
                            }
                        }
                    }
                }
                Text(summary).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail)
            }
            Spacer()
            Menu {
                Button("上移") { move(-1) }.disabled(first)
                Button("下移") { move(1) }.disabled(last)
            } label: {
                Image(systemName: "arrow.up.arrow.down")
            }
            .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize().help("调整规则顺序")
            Button(action: edit) { Image(systemName: "pencil") }
                .buttonStyle(.borderless).help("编辑规则")
            Button(action: remove) { Image(systemName: "minus.circle.fill").foregroundStyle(.red) }
                .buttonStyle(.borderless).help("删除规则")
        }
    }
    private var summary: String {
        var parts: [String] = []
        if rule.network != "any" { parts.append(rule.network == "wifi" ? "Wi-Fi" : "有线") }
        parts += rule.ssids
        parts += rule.domains
        parts += rule.servers
        if let probe = rule.probe { parts.append(probe.target) }
        return parts.isEmpty ? "任意网络" : parts.joined(separator: " · ")
    }
}

private struct OnDemandRuleEditor: View {
    @State var rule: OnDemandRule
    var cancel: () -> Void
    var save: (OnDemandRule) -> Void
    @State private var ssids = ""
    @State private var domains = ""
    @State private var servers = ""
    @State private var probeKind = "none"
    @State private var probeTarget = ""
    @State private var error: String?
    @State private var filling = false
    @State private var fillGeneration = 0
    @State private var fillMonitor: NWPathMonitor?
    @State private var fillReader: NetworkFacts?
    @State private var fillNote: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                TextField("规则名称", text: $rule.name)
                Button(filling ? "正在读取…" : "填入当前网络", action: fillCurrentNetwork).disabled(filling)
            }
            if let fillNote { Text(fillNote).font(.caption).foregroundStyle(.secondary) }
            Picker("网络类型", selection: $rule.network) {
                Text("任意").tag("any")
                Text("Wi-Fi").tag("wifi")
                Text("有线").tag("wired")
            }
            TextField("Wi-Fi 名称，每行一个，例如 Office-WiFi", text: $ssids, axis: .vertical)
            TextField("DNS 搜索域，例如 *.example.com", text: $domains)
            TextField("DNS 服务器，例如 10.0.0.53", text: $servers)
            Text("Wi-Fi 名称每行一个，精确匹配；其他值用换行或逗号分隔。留空表示不限制。")
                .font(.caption).foregroundStyle(.secondary)
            Picker("探针", selection: $probeKind) {
                Text("不使用").tag("none")
                Text("URL 返回 200").tag("url")
                Text("域名能解析").tag("dns")
            }
            if probeKind != "none" {
                TextField(
                    probeKind == "url" ? "https://intranet.example.com/" : "intranet.example.com", text: $probeTarget)
                Text("仅经物理网卡，3 秒超时；VPN 或断线保护拦截时视为不命中。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Picker("命中后", selection: $rule.action) {
                Text("连接").tag("connect")
                Text("断开").tag("disconnect")
                Text("忽略").tag("ignore")
            }
            if OnDemandCore.validate(draft).weak {
                Text("条件可被伪造，建议加受系统信任的内网 HTTPS 探针。")
                    .font(.caption).foregroundStyle(.orange)
            }
            if let error { Text(error).font(.caption).foregroundStyle(.orange) }
            HStack {
                Spacer()
                Button("取消", action: cancel)
                Button("保存", action: commit)
            }
        }
        .textFieldStyle(.roundedBorder)
        .padding(10).background(Color.primary.opacity(0.04)).cornerRadius(8)
        .onAppear {
            ssids = rule.ssids.joined(separator: "\n")
            domains = rule.domains.joined(separator: ", ")
            servers = rule.servers.joined(separator: ", ")
            probeKind = rule.probe?.kind ?? "none"
            probeTarget = rule.probe?.target ?? ""
        }
        .onDisappear(perform: stopFill)
    }
    private func fillCurrentNetwork() {
        fillGeneration += 1
        let token = fillGeneration
        filling = true
        let monitor = NWPathMonitor()
        let reader = NetworkFacts()
        fillMonitor = monitor
        fillReader = reader
        monitor.pathUpdateHandler = { path in
            DispatchQueue.main.async {
                guard token == fillGeneration, filling else { return }
                stopFill()
                // One shot, no probes and no new location request.
                let facts = reader.collect(path: path, needsSSID: true, requestLocationAuthorization: false)
                if rule.network == "any", let network = facts.network { rule.network = network }
                ssids = OnDemandRuleInput.merge(ssids.components(separatedBy: .newlines), facts.ssid.map { [$0] } ?? [])
                    .joined(separator: "\n")
                domains = OnDemandRuleInput.merge(values(domains), facts.domains, caseInsensitive: true)
                    .joined(separator: ", ")
                servers = OnDemandRuleInput.merge(values(servers), facts.servers).joined(separator: ", ")
                fillNote = facts.network == nil ? "未读取到物理网络，已有条件已保留。" : "已合并当前网络，已有条件已保留。"
            }
        }
        monitor.start(queue: DispatchQueue(label: "com.alwaysconnect.on-demand.fill"))
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
            guard token == fillGeneration, filling else { return }
            stopFill()
            fillNote = "读取超时，已有条件已保留。"
        }
    }
    private func stopFill() {
        filling = false
        fillGeneration += 1
        fillMonitor?.pathUpdateHandler = nil
        fillMonitor?.cancel()
        fillMonitor = nil
        fillReader = nil
    }
    private func values(_ text: String) -> [String] {
        text.components(separatedBy: CharacterSet(charactersIn: ",\n"))
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }
    private var draft: OnDemandRule {
        var draft = rule
        draft.name = draft.name.trimmingCharacters(in: .whitespacesAndNewlines)
        draft.ssids = ssids.components(separatedBy: .newlines).filter { !$0.isEmpty }
        draft.domains = values(domains)
        draft.servers = values(servers)
        draft.probe =
            probeKind == "none"
            ? nil : OnDemandProbe(kind: probeKind, target: probeTarget.trimmingCharacters(in: .whitespacesAndNewlines))
        return draft
    }
    private func commit() {
        let draft = draft
        guard !draft.name.isEmpty else {
            error = "请给规则起一个名字。"
            return
        }
        let answer = OnDemandCore.validate(draft)
        guard answer.valid else {
            error = answer.error
            return
        }
        save(draft)
    }
}

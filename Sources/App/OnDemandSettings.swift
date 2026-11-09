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
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                Toggle("按需连接", isOn: $enabled).onChange(of: enabled) { _ in save() }
                Text("从上到下第一条命中生效；条件之间为且，同类多个值为或。未命中时连接 VPN。")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(Array(rules.enumerated()), id: \.element.id) { index, rule in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(rule.name)
                            Text(actionName(rule.action)).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("上移") { rules.swapAt(index, index - 1); save() }.disabled(index == 0)
                        Button("下移") { rules.swapAt(index, index + 1); save() }.disabled(index + 1 == rules.count)
                        Button("编辑") { editing = rule }
                        Button("删除", role: .destructive) { rules.remove(at: index); save() }
                    }
                }
                if let draft = editing {
                    OnDemandRuleEditor(rule: draft, cancel: { editing = nil }) { rule in
                        if let index = rules.firstIndex(where: { $0.id == rule.id }) { rules[index] = rule }
                        else { rules.append(rule) }
                        editing = nil; save()
                    }
                    .id(draft.id)
                } else {
                    Button("添加规则") { editing = OnDemandRule() }
                }
                HStack {
                    Button(testing ? "正在测试…" : "测试当前网络", action: test).disabled(testing || !enabled)
                    Text("仅在开启时读取网络；Wi-Fi 名称需要定位授权。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if let testResult { Text(testResult).font(.caption).textSelection(.enabled) }
            }.padding(6)
        }
        .onDisappear {
            testGeneration += 1
            testProbe?.cancel(); testProbe = nil
            testMonitor?.pathUpdateHandler = nil; testMonitor?.cancel(); testMonitor = nil; testFacts = nil
        }
    }
    private func save() {
        var settings = ProfileStore.loadAppSettings()
        settings.onDemandEnabled = enabled; settings.onDemandRules = rules
        ProfileStore.saveAppSettings(settings)
        HelperClient.shared.onDemandSettingsChanged()
        testGeneration += 1; testProbe?.cancel(); testProbe = nil; testing = false; testResult = nil
        testMonitor?.pathUpdateHandler = nil; testMonitor?.cancel(); testMonitor = nil; testFacts = nil
    }
    private func test() {
        guard enabled else { return }
        testGeneration += 1; let token = testGeneration
        testing = true
        // Settings child owns this read-only, short-lived monitor. It never
        // changes VPN state; the normal policy is evaluated by the App.
        let monitor = NWPathMonitor(); testMonitor = monitor
        let reader = NetworkFacts(); testFacts = reader
        monitor.pathUpdateHandler = { path in
            DispatchQueue.main.async {
                guard token == testGeneration else { return }
                monitor.pathUpdateHandler = nil; monitor.cancel(); testMonitor = nil
                let facts = reader.collect(path: path, needsSSID: rules.contains { !$0.ssids.isEmpty })
                let description = "网络：\(facts.network == "wifi" ? "Wi-Fi" : facts.network == "wired" ? "有线" : "未知")\nWi-Fi 名称：\(facts.ssid ?? reader.locationDescription)\n搜索域：\(facts.domains.joined(separator: ", "))\nDNS 服务器：\(facts.servers.joined(separator: ", "))"
                testDecision(facts, reader: reader, description: description, token: token)
            }
        }
        monitor.start(queue: DispatchQueue(label: "com.alwaysconnect.on-demand.test"))
    }
    private func testDecision(_ facts: OnDemandFacts, reader: NetworkFacts, description: String, token: Int) {
        guard token == testGeneration else { return }
        let result = OnDemandCore.decide(enabled: true, rules: rules, facts: facts)
        if let probe = result.probe, let id = result.rule_id {
            let task = OnDemandNetworkProbe(); testProbe = task
            task.run(probe, interface: reader.interface, servers: facts.servers) { matched in
                _ = task
                guard token == testGeneration else { return }
                testProbe = nil
                var facts = facts; facts.probes[id] = matched
                testDecision(facts, reader: reader, description: description, token: token)
            }
        } else {
            let name = rules.first { $0.id == result.rule_id }?.name ?? "未命中规则"
            testResult = description + "\n结果：\(name) · \(actionName(result.action))（测试不会更改连接）"
            testing = false; testFacts = nil
        }
    }
}
private func actionName(_ action: String) -> String {
    action == "disconnect" ? "断开 VPN，使用本地网络" : action == "ignore" ? "忽略，保持当前状态" : "连接 VPN"
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
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            TextField("规则名称", text: $rule.name)
            Picker("网络类型", selection: $rule.network) {
                Text("任意").tag("any"); Text("Wi-Fi").tag("wifi"); Text("有线").tag("wired")
            }
            TextField("Wi-Fi 名称，每行一个，例如 Office-WiFi", text: $ssids, axis: .vertical)
            TextField("DNS 搜索域，例如 *.example.com", text: $domains)
            TextField("DNS 服务器，例如 10.0.0.53", text: $servers)
            Text("Wi-Fi 名称每行一个，精确匹配；其他值用换行或逗号分隔。留空表示不限制。")
                .font(.caption).foregroundStyle(.secondary)
            Picker("探针", selection: $probeKind) {
                Text("不使用").tag("none"); Text("URL 返回 200").tag("url"); Text("域名能解析").tag("dns")
            }
            if probeKind != "none" {
                TextField(probeKind == "url" ? "https://intranet.example.com/" : "intranet.example.com", text: $probeTarget)
                Text("仅经物理网卡，3 秒超时；VPN 或断线保护拦截时视为不命中。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Picker("命中后", selection: $rule.action) {
                Text("连接").tag("connect"); Text("断开").tag("disconnect"); Text("忽略").tag("ignore")
            }
            if let error { Text(error).font(.caption).foregroundStyle(.orange) }
            HStack { Spacer(); Button("取消", action: cancel); Button("保存", action: commit) }
        }
        .textFieldStyle(.roundedBorder)
        .padding(10).background(Color.primary.opacity(0.04)).cornerRadius(8)
        .onAppear {
            ssids = rule.ssids.joined(separator: "\n"); domains = rule.domains.joined(separator: ", ")
            servers = rule.servers.joined(separator: ", ")
            probeKind = rule.probe?.kind ?? "none"; probeTarget = rule.probe?.target ?? ""
        }
    }
    private func values(_ text: String) -> [String] {
        text.components(separatedBy: CharacterSet(charactersIn: ",\n"))
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }
    private func commit() {
        var draft = rule
        draft.name = draft.name.trimmingCharacters(in: .whitespacesAndNewlines)
        draft.ssids = ssids.components(separatedBy: .newlines).filter { !$0.isEmpty }; draft.domains = values(domains); draft.servers = values(servers)
        draft.probe = probeKind == "none" ? nil : OnDemandProbe(kind: probeKind, target: probeTarget.trimmingCharacters(in: .whitespacesAndNewlines))
        guard !draft.name.isEmpty else { error = "请给规则起一个名字。"; return }
        struct Validation: Decodable { var valid: Bool }
        let answer: Validation? = OnDemandCore.call(ac_on_demand_validate, draft)
        guard answer?.valid == true else { error = "至少填写一个条件；请检查域名、DNS 地址和探针地址。"; return }
        save(draft)
    }
}
@_silgen_name("ac_on_demand_validate")
private func ac_on_demand_validate(_ q: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

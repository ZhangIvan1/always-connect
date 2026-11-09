import Foundation
import Network
import CoreWLAN
import CoreLocation
import SystemConfiguration
import Security

/// Only physical-service keys are read; Global/DNS belongs to the tunnel
/// while a VPN is connected. No preferences or network state are written.
final class NetworkFacts: NSObject, CLLocationManagerDelegate {
    private var location: CLLocationManager?
    private var store: SCDynamicStore?
    private var source: CFRunLoopSource?
    var networkChanged: () -> Void = {}
    var interface: NWInterface?
    var locationDescription: String {
        switch location?.authorizationStatus ?? .notDetermined {
        case .authorizedAlways, .authorized: return "定位已授权"
        case .denied, .restricted: return "未授权定位，读不到 Wi-Fi 名称。请在系统设置 → 隐私与安全性 → 定位服务中允许 AlwaysConnect。"
        default: return "Wi-Fi 名称未知；启用按需连接并保存 Wi-Fi 名称条件后会请求定位授权。"
        }
    }
    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) { networkChanged() }
    func watch(enabled: Bool) {
        if !enabled {
            if let source { CFRunLoopRemoveSource(CFRunLoopGetMain(), source, .commonModes) }
            source = nil; store = nil; interface = nil; location = nil
            return
        }
        guard store == nil else { return }
        var context = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(), retain: nil, release: nil, copyDescription: nil)
        store = SCDynamicStoreCreate(nil, "AlwaysConnect on demand" as CFString, { _, _, info in
            guard let info else { return }
            Unmanaged<NetworkFacts>.fromOpaque(info).takeUnretainedValue().networkChanged()
        }, &context)
        if let store {
            SCDynamicStoreSetNotificationKeys(store, nil, ["State:/Network/Service/[^/]+/(DNS|IPv4|IPv6)"] as CFArray)
            source = SCDynamicStoreCreateRunLoopSource(nil, store, 0)
            if let source { CFRunLoopAddSource(CFRunLoopGetMain(), source, .commonModes) }
        }
    }
    func collect(path: NWPath, needsSSID: Bool) -> OnDemandFacts {
        // NWPath's default can be utun. Select a physical en* interface
        // with its own active service instead of using the default route.
        guard let store = SCDynamicStoreCreate(nil, "AlwaysConnect facts" as CFString, nil, nil),
              let keys = SCDynamicStoreCopyKeyList(store, "State:/Network/Service/[^/]+/IPv[46]" as CFString) as? [String]
        else { interface = nil; return OnDemandFacts() }
        var candidates: [(NWInterface, String)] = []
        for key in keys.sorted() {
            guard let state = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any],
                  let name = state["InterfaceName"] as? String, name.hasPrefix("en"),
                  let i = path.availableInterfaces.first(where: { $0.name == name && ($0.type == .wifi || $0.type == .wiredEthernet) })
            else { continue }
            candidates.append((i, String(key.dropLast(5))))
        }
        // Prefer the physical primary service; Global/IPv4 is used only
        // to choose an interface, never to obtain DNS.
        let global = SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString) as? [String: Any]
        let primary = global?["PrimaryInterface"] as? String
        let setup = SCDynamicStoreCopyValue(store, "Setup:/Network/Global/IPv4" as CFString) as? [String: Any]
        let order = setup?["ServiceOrder"] as? [String] ?? []
        candidates.sort { a, b in
            let rankA = order.firstIndex(of: a.1.components(separatedBy: "/").last ?? "") ?? Int.max
            let rankB = order.firstIndex(of: b.1.components(separatedBy: "/").last ?? "") ?? Int.max
            return rankA < rankB
        }
        let chosen = candidates.first { $0.0.name == primary } ?? candidates.first
        guard let (i, prefix) = chosen else { interface = nil; return OnDemandFacts() }
        interface = i
        var facts = OnDemandFacts(network: i.type == .wifi ? "wifi" : "wired")
        facts.interface_name = i.name
        let ip = SCDynamicStoreCopyValue(store, (prefix + "/IPv4") as CFString) as? [String: Any] ?? [:]
        facts.link_addresses = (ip["Addresses"] as? [String] ?? []) + ((ip["Router"] as? String).map { [$0] } ?? [])
        let dns = SCDynamicStoreCopyValue(store, (prefix + "/DNS") as CFString) as? [String: Any] ?? [:]
        facts.domains = (dns["SearchDomains"] as? [String] ?? []) + ((dns["DomainName"] as? String).map { [$0] } ?? [])
        facts.servers = dns["ServerAddresses"] as? [String] ?? []
        if !needsSSID { location = nil }
        if needsSSID {
            if location == nil { location = CLLocationManager(); location?.delegate = self }
            if location?.authorizationStatus == .notDetermined { location?.requestWhenInUseAuthorization() }
            if location?.authorizationStatus == .authorizedAlways || location?.authorizationStatus == .authorized {
                facts.ssid = CWWiFiClient.shared().interface(withName: i.name)?.ssid()
            }
        }
        return facts
    }
    deinit { if let source { CFRunLoopRemoveSource(CFRunLoopGetMain(), source, .commonModes) } }
}

/// A short-lived, bounded probe. Every DNS and HTTP socket requires the
/// selected en* interface. HTTP host resolution also uses physical DNS,
/// never the system resolver. No redirects, authentication or cookies.
final class OnDemandNetworkProbe {
    struct Plan: Decodable { var host: String; var port: UInt16; var tls: Bool; var request: [UInt8]; var dns_query: [UInt8]; var dns_query_v6: [UInt8] }
    struct Reply: Decodable { var matched: Bool; var addresses: [String]? }
    struct Parse: Encodable { var kind: String; var bytes: [UInt8] }
    private let queue = DispatchQueue(label: "com.alwaysconnect.on-demand.probe")
    private var connection: NWConnection?
    private var timeout: DispatchWorkItem?
    private var finish: ((Bool) -> Void)?
    private var plan: Plan?
    private var interface: NWInterface?
    func run(_ p: OnDemandProbe, interface: NWInterface?, servers: [String], done: @escaping (Bool) -> Void) {
        guard let interface,
              let plan: Plan = OnDemandCore.call(ac_on_demand_probe, p) else { done(false); return }
        self.interface = interface; self.plan = plan
        queue.async {
            self.finish = done
            let timeout = DispatchWorkItem { self.complete(false) }
            self.timeout = timeout; self.queue.asyncAfter(deadline: .now() + 3, execute: timeout)
            if p.kind == "url", IPv4Address(plan.host) != nil { self.http(plan.host); return }
            self.resolve(servers, kind: p.kind)
        }
    }
    func cancel() { queue.async { self.complete(false) } }

    private func resolve(_ servers: [String], kind: String, ipv6: Bool = false) {
        guard finish != nil, let plan, let server = servers.first, IPv4Address(server) != nil || IPv6Address(server) != nil else { complete(false); return }
        let params = NWParameters.udp; params.requiredInterface = interface
        let c = NWConnection(host: NWEndpoint.Host(server), port: 53, using: params)
        connection = c
        c.stateUpdateHandler = { [self] state in
            guard self.finish != nil, self.connection === c else { return }
            switch state {
            case .ready:
                c.send(content: Data(ipv6 ? plan.dns_query_v6 : plan.dns_query), completion: .contentProcessed { [self] error in
                    if error != nil { complete(false); return }
                    c.receiveMessage { [self] data, _, _, _ in
                        let reply: Reply? = OnDemandCore.call(ac_on_demand_probe, Parse(kind: "dns", bytes: Array(data ?? Data())))
                        c.stateUpdateHandler = nil
                        c.cancel()
                        guard finish != nil else { return }
                        if let ip = reply?.addresses?.first {
                            if kind == "dns" { complete(true) } else { http(ip) }
                        } else if !ipv6 { resolve(servers, kind: kind, ipv6: true) }
                        else if servers.count > 1 { resolve(Array(servers.dropFirst()), kind: kind) }
                        else { complete(false) }
                    }
                })
            case .failed: c.cancel(); complete(false)
            default: break
            }
        }
        c.start(queue: queue)
    }
    private func http(_ ip: String) {
        guard let plan, finish != nil else { return }
        let params: NWParameters
        if plan.tls {
            let tls = NWProtocolTLS.Options()
            sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, plan.host)
            // Network.framework performs normal certificate/hostname validation.
            params = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        } else { params = .tcp }
        params.requiredInterface = interface
        let c = NWConnection(host: NWEndpoint.Host(ip), port: NWEndpoint.Port(rawValue: plan.port)!, using: params)
        connection = c
        c.stateUpdateHandler = { [self] state in
            guard self.finish != nil, self.connection === c else { return }
            switch state {
            case .ready:
                c.send(content: Data(plan.request), completion: .contentProcessed { [self] error in
                    if error != nil { complete(false) } else { receiveHeader(c, bytes: Data()) }
                })
            case .failed: complete(false)
            default: break
            }
        }
        c.start(queue: queue)
    }
    private func receiveHeader(_ c: NWConnection, bytes: Data) {
        c.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [self] data, _, ended, error in
            var bytes = bytes; bytes.append(data ?? Data())
            if bytes.contains(10) {
                let reply: Reply? = OnDemandCore.call(ac_on_demand_probe, Parse(kind: "url", bytes: Array(bytes)))
                complete(reply?.matched == true)
            } else if bytes.count >= 8192 || ended || error != nil { complete(false) }
            else { receiveHeader(c, bytes: bytes) }
        }
    }
    private func complete(_ matched: Bool) {
        guard let finish else { return }
        self.finish = nil; timeout?.cancel(); timeout = nil
        connection?.stateUpdateHandler = nil; connection?.cancel(); connection = nil
        DispatchQueue.main.async { finish(matched) }
    }
}

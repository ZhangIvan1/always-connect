import Foundation

/// Privileged helper (LaunchDaemon, installed once with admin authorization).
/// Owns the pf fallback rules: the second line of fail-closed defense.
///
/// Rules (see DESIGN.md §6/§13):
/// - Outbound on the physical interface: default DENY.
/// - Always allowed: the --allow networks, DHCP (67/68), loopback,
///   link-local multicast (mDNS/Bonjour/AirDrop discovery).
/// - IPv6 outbound on the physical interface: default DENY, except
///   fe80::/10 link-local, unless the gateway provides an IPv6 tunnel.
/// - Rules are REMOVED only on intentional user disconnect, never on an
///   unexpected drop — even if the tunnel provider process dies, the pf
///   rules keep holding the line.
///
/// Subcommands:
///   generate-pf ...  (see usage below; verifies pf text generation
///                     without touching the live packet filter)
///   run-once ...     Engine test entry: runs one CLI-orchestrated
///                     session in the foreground. The PRODUCT path
///                     passes credentials over XPC (Phase 1 step 3);
///                     run-once reads the password from stdin purely
///                     so the engine can be exercised without the App.
///                     Never use run-once as the product login path.
///   dump-script      Print the vpnc-script text (VpncScript.text)
///                     exactly as the engine installs it, so CI can
///                     exercise the script's branches on the real
///                     bytes instead of a re-parsed copy.
@main
struct HelperMain {
    static func main() {
        // A child that exits before reading its stdin credential would
        // otherwise SIGPIPE the whole root daemon on the write; ignored,
        // the write fails with EPIPE and the exit is classified normally.
        signal(SIGPIPE, SIG_IGN)
        var args = CommandLine.arguments.dropFirst()
        guard let command = args.first else {
            usage()
            exit(2)
        }
        args = args.dropFirst()
        switch command {
        case "generate-pf":
            generatePf(args: args)
        case "run-once":
            runOnce(args: args)
        case "daemon":
            daemon()
        case "dump-script":
            dumpScript()
        case "relay-client-cert":
            relayClientCert(args: args)
        default:
            usage()
            exit(2)
        }
    }

    // MARK: - dump-script

    /// Print the vpnc-script exactly as installed (no added newline:
    /// the text already ends with one). CI runs the printed script's
    /// branches against the flag-path contract (DESIGN.md §16.4).
    static func dumpScript() {
        print(VpncScript.text, terminator: "")
    }

    // MARK: - daemon

    /// LaunchDaemon entry: serve XPC on AlwaysConnectHelperMachService
    /// until killed. Installed via SMAppService + a launchd plist
    /// (Mac-proof item: needs signing; see DESIGN.md §16.9). The
    /// daemon owns the tunnel and the reconnect loop, so quitting the
    /// App never tears the session down.
    private static var retainedDaemon: HelperDaemon?
    private static var retainedSignal: DispatchSourceSignal?

    static func daemon() {
        HelperSession.trimLog()
        let daemon = HelperDaemon()
        retainedDaemon = daemon
        // launchd stops the daemon with SIGTERM (an update, an uninstall)
        // and does not take openconnect down with it: an orphaned child
        // kept retrying through a relay that no longer existed (§23.7).
        signal(SIGTERM, SIG_IGN)
        let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
        term.setEventHandler {
            daemon.shutdown()
            exit(0)
        }
        term.resume()
        retainedSignal = term
        daemon.start()
        dispatchMain()
    }

    // MARK: - generate-pf

    /// Usage:
    ///   AlwaysConnectHelper generate-pf --phys <if> --tun <if>
    ///       --gateway <ip[,ip...]> [--allow <cidr[,cidr...]>]
    ///       [--connected] [--allow-dns] [--dns <ip[,ip...]>] [--direct-table]
    /// --connected emits the connected set (physical outbound passes,
    /// DESIGN.md §17.5); without it the blocking set is emitted.
    /// Exit codes: 0 success, 1 generation rejected, 2 usage error.
    static func generatePf(args: ArraySlice<String>) {
        var args = args
        var phys: String?
        var tun: String?
        var gateway: String?
        var allow: String?
        var connected = false
        var allowDNS = false
        var directTable = false
        var dnsServers: String?
        while let flag = args.first {
            args = args.dropFirst()
            if flag == "--direct-table" {
                directTable = true
                continue
            }
            if flag == "--connected" {
                connected = true
                continue
            }
            if flag == "--allow-dns" {
                allowDNS = true
                continue
            }
            guard let value = args.first else {
                fputs("missing value for \(flag)\n", stderr)
                exit(2)
            }
            args = args.dropFirst()
            switch flag {
            case "--phys": phys = value
            case "--tun": tun = value
            case "--gateway": gateway = value
            case "--allow": allow = value
            case "--dns": dnsServers = value
            default:
                fputs("unknown flag: \(flag)\n", stderr)
                exit(2)
            }
        }
        guard let phys, let tun, let gateway else {
            fputs("required: --phys, --tun, --gateway\n", stderr)
            exit(2)
        }
        let gateways = gateway.split(separator: ",").map(String.init)
        let allows = (allow ?? "").split(separator: ",").map(String.init)
        guard let text = PfAnchor.generate(
            physicalIf: phys,
            tunnelIf: tun,
            gatewayIps: gateways,
            allowNetworks: allows,
            allowDirectEgress: connected,
            allowDNS: allowDNS,
            localDNSServers: (dnsServers ?? "").split(separator: ",").map(String.init),
            directTable: directTable
        ) else {
            fputs("pf generation rejected (bad interface, empty gateway, or invalid network/IP)\n", stderr)
            exit(1)
        }
        print(text, terminator: "")
    }

    // MARK: - relay-client-cert

    /// Test entry (DESIGN.md §二十三): make or reuse the relay client
    /// identity under --support-dir and print its certificate, as
    /// prepareRelay replies it to the App.
    static func relayClientCert(args: ArraySlice<String>) {
        guard args.count == 2, args.first == "--support-dir", let dir = args.last,
              let files = try? RelayClientIdentity.ensure(supportDir: URL(fileURLWithPath: dir))
        else {
            fputs("usage: relay-client-cert --support-dir <path>\n", stderr)
            exit(2)
        }
        print(files.certificatePEM, terminator: "")
    }

    // MARK: - run-once

    /// Usage:
    ///   AlwaysConnectHelper run-once --server <url> --user <name>
    ///       [--group <group>] [--phys <if>] [--allow <cidr,...>]
    ///       [--cookie-store <path>] [--support-dir <path>]
    ///       [--openconnect <path>] [--cafile <path>] [--script <path>]
    ///       [--max-attempts <n>] [--no-routes]
    ///       [--relay-ip <ipv4> --relay-pin <pin-sha256:...>]
    ///   Password is read as one line from stdin (piped, not prompted).
    /// Exit codes: 0 manual stop (SIGINT/SIGTERM), 1 auth failure,
    /// 2 usage error, 3 attempt limit reached.
    static func runOnce(args: ArraySlice<String>) {
        var args = args
        var server: String?
        var group = ""
        var user: String?
        var phys = "en0"
        var allow = ""
        var cookieStorePath: String?
        var supportDirPath: String?
        var openconnectPath: String?
        var cafile: String?
        var scriptPath: String?
        var maxAttempts: Int?
        var noRoutes = false
        var debugChildOutput = false
        var relayIp: String?
        var relayPin: String?
        while let flag = args.first {
            args = args.dropFirst()
            if flag == "--no-routes" {
                noRoutes = true
                continue
            }
            if flag == "--debug-child-output" {
                debugChildOutput = true
                continue
            }
            guard let value = args.first else {
                fputs("missing value for \(flag)\n", stderr)
                exit(2)
            }
            args = args.dropFirst()
            switch flag {
            case "--server": server = value
            case "--group": group = value
            case "--user": user = value
            case "--phys": phys = value
            case "--allow": allow = value
            case "--cookie-store": cookieStorePath = value
            case "--support-dir": supportDirPath = value
            case "--openconnect": openconnectPath = value
            case "--cafile": cafile = value
            case "--script": scriptPath = value
            case "--max-attempts": maxAttempts = Int(value)
            case "--relay-ip": relayIp = value
            case "--relay-pin": relayPin = value
            default:
                fputs("unknown flag: \(flag)\n", stderr)
                exit(2)
            }
        }
        guard let server, let user else {
            fputs("required: --server, --user\n", stderr)
            exit(2)
        }
        // One password line from stdin. No prompt, no echo control:
        // this is a piped test harness, not a login UI.
        guard let passwordData = FileHandle.standardInput.availableData as Data?,
              let password = String(data: passwordData, encoding: .utf8)?
                .split(separator: "\n", maxSplits: 1).first.map(String.init),
              !password.isEmpty
        else {
            fputs("run-once: password line required on stdin\n", stderr)
            exit(2)
        }

        let script: String
        do {
            if let given = scriptPath {
                script = given
            } else {
                script = try VpncScript.install()
            }
        } catch {
            fputs("run-once: vpnc-script install failed: \(error)\n", stderr)
            exit(1)
        }

        let storeURL = cookieStorePath.map { URL(fileURLWithPath: $0) }
            ?? CookieStore.defaultFileURL
        var config = CLIOrchestrator.Config(
            server: server,
            group: group,
            username: user,
            password: password,
            openconnectPath: openconnectPath,
            cafile: cafile,
            scriptPath: script,
            cookieStore: CookieStore(fileURL: storeURL),
            physicalIf: phys,
            allowNetworks: allow.split(separator: ",").map(String.init),
            maxAttempts: maxAttempts,
            noRoutes: noRoutes,
            supportDir: supportDirPath.map { URL(fileURLWithPath: $0) },
            debugChildOutput: debugChildOutput
        )
        if let relayIp, let relayPin {
            // The relay itself is the App's (here: the harness's); the
            // client identity lives under the support dir, as in the daemon.
            let dir = supportDirPath.map { URL(fileURLWithPath: $0) } ?? CLIOrchestrator.defaultSupportDir
            guard RelaySettings.isValidPin(relayPin),
                  let files = try? RelayClientIdentity.ensure(supportDir: dir) else {
                fputs("run-once: invalid relay settings\n", stderr)
                exit(2)
            }
            config.relay = RelaySettings(gatewayIp: relayIp, serverPin: relayPin,
                                         certificatePath: files.certificatePath, keyPath: files.keyPath)
        }
        let engine = CLIOrchestrator(config: config)
        let done = DispatchSemaphore(value: 0)
        var exitCode: Int32 = 0
        engine.onState = { state, detail in
            print("STATE \(stateName(state)) \(detail)")
            fflush(stdout)
        }
        engine.onTerminal = { reason in
            switch reason {
            case .stoppedManual:
                print("TERMINAL manual-stop")
                exitCode = 0
            case .authFailure:
                print("TERMINAL auth-failure")
                exitCode = 1
            case .componentMissing:
                print("TERMINAL component-missing")
                exitCode = 4
            case .attemptsExhausted:
                print("TERMINAL attempts-exhausted")
                exitCode = 3
            }
            done.signal()
        }
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)
        // NOTE: the signal sources must NOT sit on .main: the main
        // thread below blocks in done.wait(), so a .main-queue source
        // would never fire (its handler needs the main dispatch loop
        // to run). A dedicated queue delivers while we wait.
        let signalQueue = DispatchQueue(label: "com.alwaysconnect.runonce.signals")
        for sig in [SIGINT, SIGTERM] {
            let source = DispatchSource.makeSignalSource(signal: sig, queue: signalQueue)
            source.setEventHandler { engine.stop() }
            source.resume()
        }
        engine.start()
        done.wait()
        exit(exitCode)
    }

    private static func stateName(_ state: SessionDriverClient.State) -> String {
        switch state {
        case .disconnected: return "disconnected"
        case .connecting: return "connecting"
        case .authenticating: return "authenticating"
        case .awaitingApproval: return "awaiting-approval"
        case .connected: return "connected"
        case .reconnecting: return "reconnecting"
        }
    }

    private static func usage() {
        fputs("Usage:\n", stderr)
        fputs("  AlwaysConnectHelper generate-pf --phys <if> --tun <if> --gateway <ip[,ip...]> [--allow <cidr[,cidr...]>] [--connected] [--allow-dns]\n", stderr)
        fputs("  AlwaysConnectHelper run-once --server <url> --user <name> [--group <group>] [--phys <if>] [--allow <cidr,...>] [--cookie-store <path>] [--support-dir <path>] [--openconnect <path>] [--cafile <path>] [--script <path>] [--max-attempts <n>] [--no-routes] [--relay-ip <ipv4> --relay-pin <pin>]\n", stderr)
        fputs("  AlwaysConnectHelper relay-client-cert --support-dir <path>\n", stderr)
        fputs("  AlwaysConnectHelper daemon\n", stderr)
        fputs("  AlwaysConnectHelper dump-script\n", stderr)
    }
}

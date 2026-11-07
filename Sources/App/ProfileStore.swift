import Foundation

/// Non-secret persistence in the App Groups container (shared with the
/// extensions): profile, rules, and the username. Secrets NEVER go
/// here — the password lives in the Keychain (KeychainStore) and
/// reaches the provider via providerConfiguration.
enum ProfileStore {
    private static let suite = AppGroups.suiteName
    private static let profileKey = AppGroups.profileKey
    private static let rulesKey = AppGroups.rulesKey
    private static let usernameKey = AppGroups.usernameKey

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: suite)
    }

    static func loadProfile() -> Profile {
        guard let data = defaults?.data(forKey: profileKey),
              let profile = try? JSONDecoder().decode(Profile.self, from: data) else {
            return Profile()
        }
        return profile
    }

    /// The user's server list (DESIGN.md §21.13), always containing the
    /// selected server. An empty list is filled from the Mac's Cisco
    /// profiles first (§三十八); the full sync runs at launch and when
    /// the list is shown, not on every read.
    static func loadServers() -> [ServerEntry] {
        let profile = loadProfile()
        let selectedListed = profile.servers.contains { $0.target == profile.server }
        if profile.servers.isEmpty || (!profile.server.isEmpty && !selectedListed) {
            syncWithCisco()
            return loadProfile().servers
        }
        return profile.servers
    }

    /// What one sync with Cisco did (names as the list shows them).
    struct CiscoSync {
        var added: [String]
        var updated: [String]
        var detached: [String]
        /// Entries in Cisco's profiles; 0 = Cisco not readable or empty.
        var found: Int
        /// Cisco's last-used server as the list names it ("" = none).
        var last_used: String
        var changed: Bool
    }

    private struct SyncServer: Codable {
        var id: String
        var name: String
        var address: String
        var cisco_name: String?
    }

    private struct SyncRequest: Encodable {
        var servers: [SyncServer]
        var selected: String
        var dismissed: [String]
        var force: Bool
        var profile_dirs: [String]
        var preference_files: [String]
    }

    private struct SyncAnswer: Decodable {
        var servers: [SyncServer]
        var selected: String
        var dismissed: [String]
        var added: [String]
        var updated: [String]
        var detached: [String]
        var found: Int
        var last_used: String
        var changed: Bool
    }

    /// Bring the server list in step with the Mac's Cisco profiles
    /// (DESIGN.md §三十八; the merge is the Rust core's,
    /// core/src/cisco_import.rs): new entries added, changed addresses
    /// followed, entries gone from Cisco kept as plain ones, Cisco's last
    /// server selected when nothing is. `force` (the "从 Cisco 重新导入"
    /// button) also brings back entries the user removed. Cisco's files
    /// are only read. nil = the core gave no answer.
    @discardableResult
    static func syncWithCisco(force: Bool = false) -> CiscoSync? {
        var profile = loadProfile()
        let request = SyncRequest(
            servers: profile.servers.map {
                SyncServer(id: $0.id.uuidString, name: $0.name, address: $0.address, cisco_name: $0.ciscoName)
            },
            selected: profile.server,
            dismissed: profile.dismissedCisco,
            force: force,
            profile_dirs: CiscoProfiles.directories,
            preference_files: CiscoProfiles.preferenceFiles)
        guard let answer: SyncAnswer = CiscoProfiles.callJSON(ac_cisco_sync, request) else { return nil }
        let servers = answer.servers.map {
            ServerEntry(id: UUID(uuidString: $0.id) ?? UUID(), name: $0.name,
                        address: $0.address, ciscoName: $0.cisco_name)
        }
        if servers != profile.servers || answer.selected != profile.server
            || answer.dismissed != profile.dismissedCisco {
            profile.servers = servers
            profile.server = answer.selected
            profile.dismissedCisco = answer.dismissed
            saveProfile(profile)
        }
        return CiscoSync(added: answer.added, updated: answer.updated, detached: answer.detached,
                         found: answer.found, last_used: answer.last_used, changed: answer.changed)
    }

    /// The user removed a server, or turned a Cisco entry into a plain
    /// one: the automatic sync must not bring the Cisco entry back.
    static func dismissCisco(_ keys: [String]) {
        var profile = loadProfile()
        for key in keys where !key.isEmpty && !profile.dismissedCisco.contains(key) {
            profile.dismissedCisco.append(key)
        }
        saveProfile(profile)
    }

    static func saveServers(_ servers: [ServerEntry], selected: String? = nil) {
        var profile = loadProfile()
        profile.servers = servers
        if let selected {
            profile.server = selected
        } else if !servers.contains(where: { $0.target == profile.server }) {
            profile.server = servers.first?.target ?? ""
        }
        saveProfile(profile)
    }

    /// Display name of the selected server.
    static func selectedServerName() -> String {
        let profile = loadProfile()
        return loadServers().first { $0.target == profile.server }?.name ?? profile.server
    }

    static func saveProfile(_ profile: Profile) {
        if let data = try? JSONEncoder().encode(profile) {
            defaults?.set(data, forKey: profileKey)
        }
    }

    static func loadRules() -> [Rule] {
        guard let data = defaults?.data(forKey: rulesKey),
              let rules = try? JSONDecoder().decode([Rule].self, from: data) else {
            return []
        }
        return rules
    }

    static func saveRules(_ rules: [Rule]) {
        if let data = try? JSONEncoder().encode(rules) {
            defaults?.set(data, forKey: rulesKey)
        }
    }

    /// The username is not secret; only the password is.
    static func loadUsername() -> String? {
        defaults?.string(forKey: usernameKey)
    }

    static func saveUsername(_ username: String) {
        defaults?.set(username, forKey: usernameKey)
    }

    // MARK: - App settings (menu-bar app preferences, not tunnel config)

    private static let appSettingsKey = AppGroups.appSettingsKey

    static func loadAppSettings() -> AppSettings {
        guard let data = defaults?.data(forKey: appSettingsKey),
              let settings = try? JSONDecoder().decode(AppSettings.self, from: data) else {
            return AppSettings()
        }
        return settings
    }

    /// One-time (§26.13): the Network page's networks join the list;
    /// the shipped 192.168.0.0/16 default is dropped (the local network
    /// is now detected). Old groups become entries as in §26.12.
    static func migrateSplitList() {
        var settings = loadAppSettings()
        if settings.presetsDropped != true {
            // §26.15: the old ready-made groups are not carried over.
            settings.directGroups = nil
            settings.presetsDropped = true
            saveAppSettings(settings)
        }
        guard settings.networksMigrated != true else { return }
        var sites = DirectSites.sites(settings)
        for network in loadProfile().allowNetworks where network != "192.168.0.0/16" {
            if !sites.contains(where: { $0.domains == [network] }) {
                sites.append(DirectSite(name: network, domains: [network]))
            }
        }
        settings.directSites = sites
        settings.directGroups = nil
        settings.directCustom = nil
        settings.networksMigrated = true
        saveAppSettings(settings)
    }

    static func saveAppSettings(_ settings: AppSettings) {
        if let data = try? JSONEncoder().encode(settings) {
            defaults?.set(data, forKey: appSettingsKey)
        }
    }

    // MARK: - Drop history (for the panel's history line and Diagnostics)

    private static let dropHistoryKey = AppGroups.dropHistoryKey

    /// How many drops are kept (DESIGN.md §21.21, §21.22). One number for the
    /// store, the in-memory list and the Diagnostics page, which shows
    /// every kept drop and states this limit; older drops are dropped.
    /// A display log, not an audit trail.
    static let dropHistoryLimit = 10

    static func loadDropHistory() -> [DropRecord] {
        guard let data = defaults?.data(forKey: dropHistoryKey),
              let history = try? JSONDecoder().decode([DropRecord].self, from: data) else {
            return []
        }
        return trimmedDropHistory(history)
    }

    static func saveDropHistory(_ history: [DropRecord]) {
        if let data = try? JSONEncoder().encode(trimmedDropHistory(history)) {
            defaults?.set(data, forKey: dropHistoryKey)
        }
    }

    static func trimmedDropHistory(_ history: [DropRecord]) -> [DropRecord] {
        Array(history.suffix(dropHistoryLimit))
    }
}

/// Menu-bar app preferences. These are App-local and never travel to
/// the Helper; the tunnel profile lives in Profile.
struct AppSettings: Codable, Equatable {
    /// Notification aggregation (UI-DESIGN.md §一.5): on = drop/restore
    /// notifications are posted; off = only action-required approval
    /// notifications are posted.
    var notificationAggregation: Bool = true
    /// Global hotkey enabled (default off, UI-DESIGN.md §五通用页).
    var globalHotkeyEnabled: Bool = false
    /// Stored hotkey: macOS key code + Carbon modifier flags, as set by
    /// the General page's recorder. Nil = no hotkey recorded.
    var hotkeyKeyCode: UInt16?
    var hotkeyModifiers: UInt?
    /// Characters of the recorded key (for display, e.g. "V"), captured
    /// alongside the key code at record time.
    var hotkeyCharacters: String?
    /// Drop protection (DESIGN.md §21.6): block the network while the
    /// VPN is down until it is back or the user disconnects. Optional
    /// so settings saved before it decode; nil means on (the default).
    var dropProtection: Bool?
    /// Connection method (DESIGN.md §二十三): nil or "cisco" = through
    /// Cisco Secure Client, the default; "own" = AlwaysConnect's own
    /// openconnect connection with the certificate relay. Since §26.12
    /// the user sees one switch, 按网站分流: on = "own", off = "cisco".
    var connectionMode: String?
    /// Own connection: the keychain certificate to present. nil = the
    /// only client certificate when there is exactly one, else none;
    /// "none" = never; otherwise that certificate's SHA-256.
    var clientCertificate: String?
    /// Own connection's domain split (DESIGN.md §26.5): the ready-made
    /// groups switched on (DirectSites ids) and the user's own names.
    /// Superseded by directSites (§26.12); read once to migrate.
    var directGroups: [String]?
    var directCustom: [String]?
    /// The user's list of sites that skip the VPN (§26.12), in their
    /// order. Nil until migrated from directGroups/directCustom.
    var directSites: [DirectSite]?
    /// "本地局域网直连" (§26.13): the Mac's own networks always allowed,
    /// detected, not a fixed 192.168. Nil = on.
    var autoLAN: Bool?
    /// Set once the Network page's networks were moved into the list.
    var networksMigrated: Bool?
    /// Set once entries made from the old ready-made groups were removed.
    var presetsDropped: Bool?
    /// The approval card at the top of the screen while a login waits
    /// on the phone (DESIGN.md §29). Nil = on.
    var approvalCard: Bool?

    var isDropProtectionOn: Bool { dropProtection ?? true }
    var isApprovalCardOn: Bool { approvalCard ?? true }
    var usesOwnConnection: Bool { connectionMode == "own" }
    /// 按网站分流 is on (the same switch as the own connection, §26.12).
    var splitOn: Bool { usesOwnConnection }
}

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

    /// The user's server list (DESIGN.md §21.13). Filled once from the
    /// local Cisco profile (VPN-A, VPN-B, ...), and always containing
    /// the selected server, so an older single-server profile carries
    /// over unchanged.
    static func loadServers() -> [ServerEntry] {
        var profile = loadProfile()
        var servers = profile.servers
        if servers.isEmpty {
            for (name, address) in CiscoProfiles.hostEntries().sorted(by: { $0.key < $1.key }) {
                servers.append(ServerEntry(name: name, address: address, ciscoName: name))
            }
        }
        if !profile.server.isEmpty, !servers.contains(where: { $0.target == profile.server }) {
            servers.insert(ServerEntry(name: profile.server, address: profile.server), at: 0)
        }
        // Nothing shipped as the server (§27.1): the first entry found
        // in the Mac's Cisco profile is the starting choice.
        if profile.server.isEmpty, let first = servers.first {
            profile.server = first.target
            saveProfile(profile)
        }
        if servers != profile.servers {
            profile.servers = servers
            saveProfile(profile)
        }
        return servers
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

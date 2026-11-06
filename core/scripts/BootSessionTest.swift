import Foundation

// scripts/boot-session-test.sh: Sources/Helper/BootSession.swift
// (DESIGN.md §23.12, §25.2). The network gate's record is trusted only
// within the boot that wrote it.
@main
struct BootSessionTest {
    static func main() {
        var failures = 0
        func check(_ ok: Bool, _ what: String) {
            print((ok ? "ok   " : "FAIL ") + what)
            if !ok { failures += 1 }
        }
        let id = BootSession.id
        check(id != nil && !(id ?? "").isEmpty, "boot session id readable")
        check(BootSession.id == id, "boot session id stable within a run")
        check(BootSession.isCurrent(id), "a record from this boot is current")
        check(!BootSession.isCurrent("00000000-0000-0000-0000-000000000000"), "another boot's record is stale")
        check(!BootSession.isCurrent(nil), "a record without a boot id is stale")
        exit(failures == 0 ? 0 : 1)
    }
}

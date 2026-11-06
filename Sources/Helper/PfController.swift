/// Our pf anchor (DESIGN.md §20.5): under `com.apple/` so the main ruleset
/// evaluates it. Every pfctl call is the network gate's, in Rust
/// (core/src/network_guard.rs, §32.12); diagnostics only read the name.
enum PfController {
    static let anchor = "com.apple/300.AlwaysConnect"
}

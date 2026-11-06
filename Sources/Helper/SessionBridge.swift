/// The session states the engine reports (core/src/state_machine.rs,
/// same numbers over the C ABI). The driver itself runs inside the Rust
/// engine (core/src/oc_engine.rs, DESIGN.md §32.13).
enum SessionDriverClient {
    enum State: Int {
        case disconnected = 0
        case connecting = 1
        case authenticating = 2
        case awaitingApproval = 3
        case connected = 4
        case reconnecting = 5
    }
}

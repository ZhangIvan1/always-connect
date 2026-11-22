import Foundation

/// Rust decides whether a completion is current and may start an engine.
/// The Swift shell supplies actual process-stop and timeout observations.
final class EngineStartBarrier {
    let handle = ac_start_barrier_new()!
    deinit { ac_start_barrier_free(handle) }
    func cancel() { ac_start_barrier_cancel(handle) }
    func begin() -> Ticket { Ticket(handle: ac_start_barrier_begin(handle)!) }

    final class Ticket {
        enum Action: UInt32 { case ignore = 0, start = 1, cancelled = 2, timedOut = 3 }
        let handle: OpaquePointer
        init(handle: OpaquePointer) { self.handle = handle }
        deinit { ac_start_ticket_free(handle) }
        func complete(stopped: Bool) -> Action {
            Action(rawValue: ac_start_ticket_complete(handle, stopped)) ?? .ignore
        }
    }
}

@_silgen_name("ac_start_barrier_new") private func ac_start_barrier_new() -> OpaquePointer?
@_silgen_name("ac_start_barrier_free") private func ac_start_barrier_free(_ h: OpaquePointer)
@_silgen_name("ac_start_barrier_cancel") private func ac_start_barrier_cancel(_ h: OpaquePointer)
@_silgen_name("ac_start_barrier_begin") private func ac_start_barrier_begin(_ h: OpaquePointer) -> OpaquePointer?
@_silgen_name("ac_start_ticket_complete") private func ac_start_ticket_complete(_ t: OpaquePointer, _ stopped: Bool) -> UInt32
@_silgen_name("ac_start_ticket_free") private func ac_start_ticket_free(_ t: OpaquePointer)

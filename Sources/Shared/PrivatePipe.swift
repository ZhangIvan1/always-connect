import Foundation

/// Anonymous descriptors prepared by Rust under the child-spawn fence.
/// Process receives FileHandles explicitly; close the parent's child-side end
/// after run(), since FileHandles do not have Foundation Pipe's auto-close.
final class PrivatePipe {
    let fileHandleForReading: FileHandle
    let fileHandleForWriting: FileHandle

    init?() {
        guard let pair = PrivateDescriptors.pair(kind: 0) else { return nil }
        fileHandleForReading = FileHandle(fileDescriptor: pair[0], closeOnDealloc: true)
        fileHandleForWriting = FileHandle(fileDescriptor: pair[1], closeOnDealloc: true)
    }
}

enum PrivateDescriptors {
    static func pair(kind: Int32) -> [Int32]? {
        var descriptors: [Int32] = [-1, -1]
        let made = descriptors.withUnsafeMutableBufferPointer { ac_private_fd_pair(kind, $0.baseAddress, $0.count) }
        return made ? descriptors : nil
    }
    static func duplicate(_ descriptor: Int32) -> Int32 { ac_private_fd_duplicate(descriptor) }
}

@_silgen_name("ac_private_fd_pair")
private func ac_private_fd_pair(_ kind: Int32, _ output: UnsafeMutablePointer<Int32>?, _ count: Int) -> Bool
@_silgen_name("ac_private_fd_duplicate")
private func ac_private_fd_duplicate(_ descriptor: Int32) -> Int32

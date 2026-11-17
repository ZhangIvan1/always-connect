#!/bin/bash
# Ordinary-user private pipe/socketpair and Process stdio checks. No VPN or
# system route/PF operation; only short local children and anonymous IPC.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
(cd "$ROOT/core" && cargo build --release --quiet)
python3 - "$ROOT" "$WORK/Test.swift" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1]);s=(root/'Sources/Helper/SystemChecks.swift').read_text()
a=s.index('    private static func run(_ path:');at=s.index('{',a);end=at+1;depth=1
while depth:
 depth+=(s[end]=='{')-(s[end]=='}');end+=1
method=s[a:end].replace('private static func','static func',1)
text='''import Foundation
import Darwin
enum Capture {
'''+method+'''
}
@main enum Test {
    static func main() throws {
        guard let input=PrivatePipe(), let output=PrivatePipe(), let errors=PrivatePipe() else { fatalError("private pipe unavailable") }
        for handle in [input.fileHandleForReading,input.fileHandleForWriting,output.fileHandleForReading,output.fileHandleForWriting] {
            precondition(fcntl(handle.fileDescriptor,F_GETFD)&FD_CLOEXEC != 0)
        }
        let child=Process();child.executableURL=URL(fileURLWithPath:"/bin/sh")
        child.arguments=["-c", "IFS= read -r value; printf '%s' \\"$value\\"; printf 'diagnostic' >&2"]
        child.standardInput=input.fileHandleForReading
        child.standardOutput=output.fileHandleForWriting
        child.standardError=errors.fileHandleForWriting
        try child.run()
        try input.fileHandleForReading.close();try output.fileHandleForWriting.close();try errors.fileHandleForWriting.close()
        try input.fileHandleForWriting.write(contentsOf: Data("fixture-input\\n".utf8));try input.fileHandleForWriting.close()
        let captured=output.fileHandleForReading.readDataToEndOfFile()
        let diagnostic=errors.fileHandleForReading.readDataToEndOfFile();child.waitUntilExit()
        precondition(child.terminationStatus==0 && captured==Data("fixture-input".utf8) && diagnostic==Data("diagnostic".utf8))
        guard let pair=PrivateDescriptors.pair(kind:1) else { fatalError("private duplex unavailable") }
        let copy=PrivateDescriptors.duplicate(pair[0]);precondition(copy>=0)
        for fd in pair+[copy] { precondition(fcntl(fd,F_GETFD)&FD_CLOEXEC != 0);Darwin.close(fd) }
        precondition(PrivateDescriptors.duplicate(-1)<0 && PrivateDescriptors.pair(kind:99)==nil)
        let result=Capture.run("/bin/sh",["-c","printf 'capture'; exit 7"])
        precondition(result.0==7 && result.1=="capture")
        let large=Capture.run("/bin/sh",["-c","head -c 131072 /dev/zero"])
        precondition(large.0==0 && large.1.utf8.count==131072)
        print("PASS private descriptors, explicit stdio, EOF, error status and actual capture helper")
    }
}
'''
Path(sys.argv[2]).write_text(text)
PY
swiftc -O -parse-as-library "$ROOT/Sources/Shared/PrivatePipe.swift" "$WORK/Test.swift" \
    "$ROOT/core/target/release/libalwaysconnect_core.a" -o "$WORK/test" 2>"$WORK/build.log" || { cat "$WORK/build.log"; exit 1; }
python3 - "$WORK/test" <<'PY'
import subprocess,sys
subprocess.run([sys.argv[1]],check=True,timeout=15)
PY

#!/bin/bash
# Long-run record for the own connection (DESIGN.md §28.4): read-only,
# no sudo. Every minute one line: whether a page loads through the
# tunnel and how fast, the default route, and the memory (RSS, MB) and
# CPU of the App, the background service and openconnect. Leave it
# running for hours (Ctrl-C to stop); the file is what to send back.
#
#   scripts/soak-check.sh [minutes-between-samples, default 1]
set -uo pipefail
EVERY=$(( ${1:-1} * 60 ))
OUT=${SOAK_LOG:-/tmp/ac-soak.log}
proc() { # pattern -> "rssMB/cpu%" or "-"
    local pid
    pid=$(pgrep -f "$1" | head -1)
    [ -n "$pid" ] || { echo "-"; return; }
    ps -o rss=,%cpu= -p "$pid" | awk '{ printf "%.0fMB/%s%%", $1 / 1024, $2 }'
}
echo "time                 web(code,s)        default  app         service     openconnect" | tee -a "$OUT"
while true; do
    web=$(curl -s -m 10 -o /dev/null -w '%{http_code},%{time_total}' https://www.wikipedia.org/ || echo "000,-")
    def=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
    printf '%s  %-18s %-8s %-11s %-11s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$web" "${def:--}" \
        "$(proc 'MacOS/AlwaysConnect')" "$(proc 'alwaysconnect.app.helper')" "$(proc 'bin/openconnect')" | tee -a "$OUT"
    sleep "$EVERY"
done

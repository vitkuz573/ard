#!/bin/sh
# Stop our own long-lived processes by name.
#
# Why this exists rather than `pkill -x`
#
# pkill hung repeatedly on this host while driving the end-to-end scripts, and a test script
# that hangs on its own cleanup is worse than one that fails: it turns a real failure into a
# timeout with no output. This walks the process table once, kills the pids it finds, and
# returns. It is also deliberately narrow -- an exact match on the command name, so it can
# never take down a process whose name merely contains the argument.
#
# Usage:
#
#   scripts/stop.sh adb ard-server ard-connect mockadbd probe
#
# It is a development aid, not part of the product: nothing in cmd/ or internal/ calls it.

set -u

# Signal TERM first, so a process gets the chance to close connections and unlink sockets.
# Then KILL whatever is left, because a wedged adb server holding a smart socket will
# otherwise keep a port bound and the next run's bind will fail for a reason that has
# nothing to do with what is being tested.
kill_named() {
  ps -eo pid=,comm= | awk -v want="$1" '$2 == want { print $1 }'
}

for name in "$@"; do
  for pid in $(kill_named "$name"); do
    kill "$pid" 2>/dev/null || true
  done
done

# One short settle. Not a wait loop: if something survives TERM it is going to get KILL,
# and polling until it agrees would be the same hang in a different costume.
sleep 1

for name in "$@"; do
  for pid in $(kill_named "$name"); do
    kill -9 "$pid" 2>/dev/null || true
  done
done

# Report rather than assume. A name that matched nothing is usually a typo in the caller,
# and finding that out here is cheaper than finding it out as a mysterious bind failure.
for name in "$@"; do
  left=$(ps -eo pid=,comm= | awk -v want="$name" '$2 == want { print $1 }' | tr '\n' ' ')
  if [ -n "$left" ]; then
    echo "stop.sh: $name still running: $left" >&2
  fi
done

exit 0
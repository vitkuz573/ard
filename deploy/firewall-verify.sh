#!/bin/bash
# Boot-time assertion that the ARD firewall is actually enforcing.
#
# A gateway that silently loses its ruleset is indistinguishable from an open one:
# every device and every operator port becomes publicly reachable, and nothing in
# the logs says so. nftables.service can fail to run (a ruleset syntax error, an
# ordering cycle, a broken drop-in) while the unit still reports enabled. This
# turns that into a loud, visible failure.
#
# Exits non-zero and logs to syslog when the policy is not deny-by-default.
set -uo pipefail

TABLE=ard
CHAIN=input

expected_policy=drop
actual_policy="$(nft list chain inet "$TABLE" "$CHAIN" 2>/dev/null | grep -oE 'policy [a-z]+' | head -1 | awk '{print $2}')"

if [[ -z "$actual_policy" ]]; then
  msg="ard-firewall-verify: table inet $TABLE is missing; the gateway has NO firewall"
  logger -p auth.warning -t ard-firewall-verify "$msg"
  echo "$msg" >&2
  exit 1
fi

if [[ "$actual_policy" != "$expected_policy" ]]; then
  msg="ard-firewall-verify: chain inet $TABLE $CHAIN policy is '$actual_policy', expected '$expected_policy'"
  logger -p auth.warning -t ard-firewall-verify "$msg"
  echo "$msg" >&2
  exit 1
fi

logger -p auth.info -t ard-firewall-verify "firewall enforcing: inet $TABLE $CHAIN policy=$actual_policy"
exit 0
#!/usr/bin/env bash
# Integration test for labctl. Needs root. Uses its OWN bridge, subnet, names
# and UID range, so it never touches a real lab created with the defaults.
# Always tears down what it created, even on failure.
#
#   sudo ./scripts/test-lab.sh

set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

export LAB_BRIDGE=br-labtest
export LAB_NET=10.78
export LAB_NODE_PREFIX=lt-node
export LAB_VETH_PREFIX=vlt
export LAB_UID_BASE=37000
export LAB_STATE_DIR=/var/lib/spiffe-lab-test
export LAB_NFT_TABLE=spiffe_lab_test

LABCTL="${SCRIPT_DIR}/labctl"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

[[ ${EUID} -eq 0 ]] || { echo "run as root: sudo $0" >&2; exit 1; }

pass=0 fail=0
ok()   { printf '  PASS  %s\n' "$*"; pass=$((pass + 1)); }
bad()  { printf '  FAIL  %s\n' "$*"; fail=$((fail + 1)); }
check() { local desc=$1; shift; if "$@" >/dev/null 2>&1; then ok "${desc}"; else bad "${desc}"; fi; }
check_not() { local desc=$1; shift; if "$@" >/dev/null 2>&1; then bad "${desc}"; else ok "${desc}"; fi; }

cleanup() { "${LABCTL}" down >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup   # start from a clean slate

n() { node_name "$1"; }

echo "== up 3"
"${LABCTL}" up 3
for i in 1 2 3; do
    check "netns $(n "$i") exists"            netns_exists "$(n "$i")"
    check "user $(n "$i") is a lab user"      is_lab_user "$(n "$i")"
    check "$(n "$i") runs as uid $(node_uid "$i")" \
        test "$("${LABCTL}" exec "$i" -- id -u)" = "$(node_uid "$i")"
    check "$(n "$i") has ip $(node_ip "$i")" \
        sh -c "ip -n $(n "$i") -4 addr show dev eth0 | grep -q 'inet $(node_ip "$i")/16'"
done

echo "== idempotency"
check "up 3 again succeeds" "${LABCTL}" up 3
check "still exactly 3 nodes" test "$(existing_ids | wc -l)" -eq 3

echo "== connectivity"
check "node1 -> node2 ICMP"   ip netns exec "$(n 1)" ping -c1 -W2 "$(node_ip 2)"
check "node3 -> host bridge"  ip netns exec "$(n 3)" ping -c1 -W2 "$(bridge_ip)"
# TCP between nodes as their unprivileged users. This is the path the mTLS demo
# in Milestone 3 uses, and the one Docker's FORWARD DROP would break.
"${LABCTL}" exec 2 -- python3 -c '
import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 8443)); s.listen(1); s.settimeout(10)
c,_=s.accept(); c.sendall(b"hello-from-node2"); c.close()' &
srv=$!
sleep 0.5
reply=$("${LABCTL}" exec 1 -- python3 -c "
import socket; s=socket.create_connection(('$(node_ip 2)', 8443), timeout=5); print(s.recv(64).decode())" 2>/dev/null || true)
wait "${srv}" 2>/dev/null || true
check "node1 -> node2 TCP as unprivileged users" test "${reply}" = "hello-from-node2"

echo "== isolation properties"
check_not "node has no default route"       sh -c "ip -n $(n 1) route | grep -q '^default'"
check_not "node cannot route to 1.1.1.1"    ip -n "$(n 1)" route get 1.1.1.1
check "nft table drops lab<->other forwarding" nft list table inet "${LAB_NFT_TABLE}"
check_not "node user cannot read another node's dir" \
    "${LABCTL}" exec 1 -- ls "$(node_home 2)"
check "no_new_privs is set for node processes" \
    sh -c "'${LABCTL}' exec 1 -- grep -q '^NoNewPrivs:[[:space:]]*1' /proc/self/status"

echo "== add / del (organic growth)"
"${LABCTL}" add 2
check "add 2 created node 4" netns_exists "$(n 4)"
check "add 2 created node 5" netns_exists "$(n 5)"
"${LABCTL}" del 2
check_not "del 2 removed netns"  netns_exists "$(n 2)"
check_not "del 2 removed user"   getent passwd "$(n 2)"
check "node 3 unaffected by del 2" ip netns exec "$(n 3)" ping -c1 -W2 "$(node_ip 1)"

echo "== safety: refuse to touch a non-lab user"
useradd --system --no-create-home --shell /usr/sbin/nologin "$(n 9)"
check_not "up refuses to adopt a foreign user named $(n 9)" "${LABCTL}" up 9
"${LABCTL}" down >/dev/null 2>&1 || true
check "down left the foreign user alone" getent passwd "$(n 9)"
userdel "$(n 9)"

echo "== down"
"${LABCTL}" up 2 >/dev/null
"${LABCTL}" down
check "no nodes left"                    test -z "$(existing_ids)"
check_not "bridge removed"               link_exists "${LAB_BRIDGE}"
check_not "nft table removed"            nft list table inet "${LAB_NFT_TABLE}"
check_not "iptables rule removed" sh -c "iptables -S | grep -q -- '${LAB_IPT_COMMENT}'"
check_not "state dir removed"            test -d "${LAB_STATE_DIR}"

echo
echo "passed: ${pass}  failed: ${fail}"
[[ ${fail} -eq 0 ]]

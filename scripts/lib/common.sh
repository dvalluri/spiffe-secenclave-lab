# shellcheck shell=bash
# Shared helpers for the namespace lab. Sourced by scripts/labctl and
# scripts/test-lab.sh. Not executable on its own.
#
# SECURITY NOTE: namespace nodes share one kernel with each other and with
# the SPIRE server. A network namespace isolates networking only. See
# docs/trust-levels.md. Nothing here is a security boundary against root or a
# kernel exploit on the host.

set -euo pipefail

# --- Configuration (override with environment variables) ---------------------
# The test script overrides all of these so it never touches the real lab.
: "${LAB_BRIDGE:=br-lab}"            # bridge device name (max 15 chars)
: "${LAB_NET:=10.77}"                # first two octets; the lab uses ${LAB_NET}.0.0/16
: "${LAB_NODE_PREFIX:=lab-node}"     # namespace name == Unix user name == group name
: "${LAB_VETH_PREFIX:=vlab}"         # host-side veth: ${LAB_VETH_PREFIX}NNNN (max 15 chars)
: "${LAB_UID_BASE:=47000}"           # node N gets UID/GID LAB_UID_BASE+N
: "${LAB_STATE_DIR:=/var/lib/spiffe-lab}"
: "${LAB_NFT_TABLE:=spiffe_lab}"     # our own nftables table (inet family)

# Every user we create carries this exact GECOS comment. We only ever modify
# or delete users that carry it, so a typo can never delete a real account.
readonly LAB_MARKER="spiffe-secenclave-lab node (${LAB_NODE_PREFIX})"
# iptables comment used to find and remove only our rules.
# shellcheck disable=SC2034 # used by labctl and test-lab.sh, which source this file
readonly LAB_IPT_COMMENT="spiffe-lab:${LAB_BRIDGE}"

readonly LAB_MAX_NODES=9999          # 4-digit IDs keep veth names <= 15 chars
readonly LAB_IP_OFFSET=10            # .0.1 = bridge/host; .0.2-.0.10 reserved for infra

# --- Logging -------------------------------------------------------------------
log()  { printf '[labctl] %s\n' "$*" >&2; }
warn() { printf '[labctl] WARNING: %s\n' "$*" >&2; }
die()  { printf '[labctl] ERROR: %s\n' "$*" >&2; exit 1; }

require_root() {
    [[ ${EUID} -eq 0 ]] || die "this command needs root (try: sudo $0 $*)"
}

# --- Config validation (fail early on bad overrides) ----------------------------
validate_config() {
    [[ ${#LAB_BRIDGE} -le 15 ]] || die "LAB_BRIDGE '${LAB_BRIDGE}' longer than 15 chars"
    [[ $(( ${#LAB_VETH_PREFIX} + 4 )) -le 15 ]] || die "LAB_VETH_PREFIX too long"
    [[ ${LAB_NET} =~ ^([0-9]{1,3})\.([0-9]{1,3})$ ]] || die "LAB_NET must look like '10.77'"
    [[ ${LAB_NODE_PREFIX} =~ ^[a-z][a-z0-9-]{0,20}$ ]] || die "bad LAB_NODE_PREFIX"
    [[ ${LAB_UID_BASE} =~ ^[0-9]+$ ]] || die "LAB_UID_BASE must be a number"
    # Stay below UID_MAX (60000) and well clear of systemd's dynamic-user
    # range (61184-65519), so lab UIDs never collide with DynamicUser services.
    (( LAB_UID_BASE >= 1000 && LAB_UID_BASE + LAB_MAX_NODES < 60000 )) \
        || die "LAB_UID_BASE must keep node UIDs within 1000..59999"
    [[ ${LAB_STATE_DIR} == /* && ${LAB_STATE_DIR} != / ]] || die "LAB_STATE_DIR must be an absolute, non-root path"
}

# --- Naming ------------------------------------------------------------------------
validate_id() {
    local id=$1
    [[ ${id} =~ ^[0-9]+$ ]] || die "node id '${id}' is not a number"
    (( 10#${id} >= 1 && 10#${id} <= LAB_MAX_NODES )) || die "node id must be 1..${LAB_MAX_NODES}"
}

node_name() { printf '%s-%04d' "${LAB_NODE_PREFIX}" "$((10#$1))"; }
veth_host() { printf '%s%04d'  "${LAB_VETH_PREFIX}" "$((10#$1))"; }
node_uid()  { echo $(( LAB_UID_BASE + 10#$1 )); }
node_home() { printf '%s/nodes/%s' "${LAB_STATE_DIR}" "$(node_name "$1")"; }
bridge_ip() { printf '%s.0.1' "${LAB_NET}"; }

# Node N -> ${LAB_NET}.X.Y with X.Y = N + LAB_IP_OFFSET (fits a /16 for N <= 9999).
node_ip() {
    local off=$(( 10#$1 + LAB_IP_OFFSET ))
    printf '%s.%d.%d' "${LAB_NET}" $(( off / 256 )) $(( off % 256 ))
}

# True if the user exists AND was created by this lab (GECOS marker matches).
is_lab_user() {
    local entry
    entry=$(getent passwd "$1") || return 1
    [[ $(cut -d: -f5 <<<"${entry}") == "${LAB_MARKER}" ]]
}

netns_exists() { ip netns list | awk '{print $1}' | grep -qx -- "$1"; }
link_exists()  { ip link show dev "$1" >/dev/null 2>&1; }

# IDs of all nodes that exist in any form (netns or lab user), sorted.
existing_ids() {
    {
        ip netns list | awk '{print $1}'
        getent passwd | awk -F: -v m="${LAB_MARKER}" '$5 == m {print $1}'
    } | sed -n "s/^${LAB_NODE_PREFIX}-\([0-9]\{4\}\)\$/\1/p" | sort -u
}

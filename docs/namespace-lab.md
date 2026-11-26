# Namespace lab (Milestone 2)

`scripts/labctl` creates and destroys any number of **namespace nodes** on the
Ryzen box. You can grow the lab one node at a time.

> **Read first:** namespace nodes share one kernel with each other and with
> the SPIRE server. They simulate machines on a network. They do **not**
> isolate a compromised node. See [trust-levels.md](trust-levels.md).

## Quick start

```bash
sudo ./scripts/labctl up 3              # bridge + firewall + nodes 1..3
./scripts/labctl status                 # no root needed
sudo ./scripts/labctl exec 2 -- id      # run a command as node 2
sudo ./scripts/labctl shell 1           # interactive shell as node 1
sudo ./scripts/labctl add 2             # grow: adds nodes 4 and 5
sudo ./scripts/labctl del 4             # remove one node
sudo ./scripts/labctl down              # remove everything

sudo ./scripts/test-lab.sh              # integration test (isolated names/subnet)
```

## What a node is

| Piece | Node N (example: N=3) | Notes |
|---|---|---|
| Network namespace | `lab-node-0003` | Created with `ip netns` |
| Interface | `eth0` inside, `vlab0003` on the host | veth pair; the host end is attached to `br-lab` |
| Address | `10.77.0.13/16` | `10.77.0.0/16 + 10 + N`. `.0.1` is the host; `.0.2`–`.0.10` are reserved for infrastructure |
| Unix user/group | `lab-node-0003`, UID = GID = 47003 | Deterministic, so SPIRE registration entries survive a rebuild |
| Private directory | `/var/lib/spiffe-lab/nodes/lab-node-0003` (0700) | For SVIDs and keys written by workloads in Milestone 3 |

Limits: up to 9,999 nodes (4-digit IDs keep interface names under Linux's
15-character limit). UIDs 47001–56999 stay below `UID_MAX` (60000) and clear
of systemd's dynamic-user range (61184–65519).

## How identities will work (Milestone 3)

There is **one SPIRE agent on the host**. Its Workload API socket is a
filesystem path, and network namespaces do not hide the filesystem, so
every node can reach it. When a process connects, the agent reads the
caller's UID from the kernel (`SO_PEERCRED`). The `unix` workload attestor
then turns that UID into selectors such as `unix:user:lab-node-0003`, and a
registration entry maps those selectors to
`spiffe://<trust-domain>/node/0003`.

So, to SPIRE, a namespace node is a **workload** on the host's agent, not a
separately attested SPIRE node. Anything that can run as UID 47003 *is*
node 3. That includes root on the host.

## Hardening that `labctl exec` applies

`exec` and `shell` run the command via `ip netns exec` + `setpriv` with:

- `--reuid/--regid` set to the node user, and `--clear-groups`.
- `--no-new-privs`, so setuid binaries (`sudo`, `ping`, ...) cannot raise
  privileges.
- `--bounding-set=-all` and `--inh-caps=-all`, so no capabilities can be
  regained.
- `--reset-env`, so the caller's environment does not leak in.

Unprivileged users inside a fresh namespace cannot use `ping`. That is
expected: `net.ipv4.ping_group_range` is per-namespace and disabled by
default. Use TCP for connectivity checks, as the test does.

## Firewall: two problems on this host and how `labctl` handles them

This Ryzen box runs Docker. That means:

1. **`net.ipv4.ip_forward = 1`.** The host routes between interfaces. Without
   a rule, a LAN machine with a static route to `10.77.0.0/16` could reach
   nodes through this box, and the reverse.
   **Fix:** `labctl` installs its own nftables table `inet spiffe_lab`. It
   drops any forwarded packet that enters or leaves `br-lab` through another
   interface. In nftables a drop in any table is final, so Docker or
   libvirt rules cannot accidentally reopen this path.
2. **`br_netfilter` + `bridge-nf-call-iptables = 1` + Docker's `FORWARD`
   policy `DROP`.** Traffic *between two nodes on the same bridge* goes
   through iptables `FORWARD` and gets silently dropped. (A common gotcha.)
   **Fix:** `labctl` inserts
   `-i br-lab -o br-lab -j ACCEPT` (tagged with an iptables comment) into
   `DOCKER-USER`, which is Docker's documented hook for user rules. Without
   Docker, it inserts the rule into `FORWARD`, and only if that chain's policy
   is `DROP`. `labctl down` removes exactly the rules it added.

Nodes also have **no default route**. They can reach only `10.77.0.0/16`,
which means other nodes and the host at `10.77.0.1`. Any host service
listening on `0.0.0.0` is therefore reachable from nodes. That is intended
for SPIRE later. If it matters for another service, bind that service to a
specific address.

None of this touches the secenclave link. That link gets its own rules in
Milestone 4.

## Safety properties of the scripts

- Every user `labctl` creates carries the GECOS comment
  `spiffe-secenclave-lab node (lab-node)`. `labctl` refuses to modify or
  delete any user without it, even if the name matches. The test checks this.
- It refuses to create a node if its UID, GID or group name is already taken.
- All commands are idempotent. Re-running `up` repairs a half-built node
  instead of failing.
- `del` and `down` kill the node's processes first. A namespace stays alive
  while any process is inside it, even after `ip netns del`.
- Home directories are removed only if the path matches the exact expected
  pattern.
- `test-lab.sh` uses its own bridge (`br-labtest`), subnet (`10.78/16`), names
  (`lt-node-*`), UIDs (37001+), state directory and nft table, so it never
  touches the real lab.

## Not done (yet)

- No PID or mount namespaces. A node can see every process on the host
  (`ps`). That could be added later, but it would not change the trust
  level: one kernel is one kernel.
- No per-node SPIRE agents. That would be a later option (join-token
  attestation per namespace) for a more realistic SPIRE topology.
- No `tc netem` latency or loss injection yet. That's an easy follow-up.
- The lab does not persist across reboots. Run `labctl up N` again; UIDs and
  IPs come out the same.

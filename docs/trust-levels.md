# Trust levels

Every component is placed in one trust level. A higher level must never depend
on a lower level for its security. Whenever the design has to break that rule,
this document says so.

| Level | Component | Holds | Compromise means |
|---|---|---|---|
| **T0** | Offline ceremony laptop and the paper backup | Root seed and issuing master seed (on paper only, after the ceremony) | Total: an attacker can recreate the CA keys |
| **T1** | secenclave board(s) | Root and issuing keys (PUF-wrapped / in ELS), board TLS key, signature log | Attacker can sign anything until the keys are replaced through a new ceremony |
| **T2** | SPIRE server host (Ryzen) | Registration entries, datastore, its secenclave-link client cert. **No CA keys** | Attacker can get **any SVID** in the trust domain signed *while in control*, but cannot extract keys. Recovery: rebuild the host. No re-ceremony is needed |
| **T3** | Hardware nodes (Pi 5) | Their own agent SVID and workload SVIDs | That node's identities only |
| **T4** | Namespace nodes on the Ryzen | Workload SVIDs fetched over the host agent's socket | See below. Effectively equal to T2 compromise if the kernel or root is involved |
| **untrusted** | Home LAN, Wi-Fi clients, router | Nothing | Assumed hostile from day one |

## Hardware nodes and namespace nodes

### Hardware node (Pi 5)

- Has its own kernel, its own memory, and its own SPIRE agent.
- An attacker who has root on the Pi gets that node's identities only.
- Node attestation in Phase 1 uses `join_token` (single use, never committed) or
  `x509pop`. The Pi 5 has no TPM, so there is no hardware-rooted node
  attestation for it.

### Namespace node

A namespace node is a Linux **network namespace** on the Ryzen box, attached to
a bridge. Each one runs its processes as a dedicated Unix user, such as
`lab-node-07`.

What it really is:

- **One kernel.** Every namespace shares the Ryzen kernel with all the other
  namespaces, with the SPIRE agent, *and with the SPIRE server*. A kernel
  exploit or root on the host compromises every namespace node and the server.
- **Network namespaces isolate only networking.** The filesystem, the PID view
  (unless a PID namespace is added), and the users are shared. The agent's
  Workload API socket is a filesystem path, so it is reachable from every
  namespace. That is how the namespace nodes get SVIDs from the single host
  agent.
- **Identity comes from the Unix UID**, through the SPIRE `unix` workload
  attestor. To SPIRE, a namespace node is a *workload* on the host agent, not
  a separate SPIRE node. Anything that can run as UID `lab-node-07` *is*
  node 07.
- **Good for:** many nodes, realistic IP topologies, mTLS between "nodes",
  failure injection (bringing links down, adding latency with `tc netem`).
- **Not good for:** demonstrating isolation, or containing a compromised node.

> **Namespaces are not a security boundary in this lab.** Treat a namespace
> node as a convenient simulation of a machine, not as a machine.

Possible later options: a per-namespace agent using `join_token` node attestation
(more realistic SPIRE topology, still one kernel), or microVMs such as
Firecracker for real kernel separation.

## Rules derived from these levels

1. CA private keys exist only at T0 (on paper, offline) and T1. Never at T2 or
   below.
2. The board (T1) accepts requests only from an allow-listed T2 client
   certificate, over the dedicated link.
3. T2 is the policy decision point for identities. The board cannot see what
   it signs on the SVID path (a digest only), so **T2 integrity is
   critical**, even though T2 holds no keys.
4. Nothing at T3, T4, or the LAN can reach the secenclave link. The Ryzen box must not
   route or bridge between the LAN and the secenclave interface (checked in
   Milestone 4 with nftables rules).
5. Identities issued to T4 nodes must never be used to authorize anything that
   assumes isolation from the host.

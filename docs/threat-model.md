# Threat model

Scope: Phase 1, one secenclave board. This is a learning lab on a home network, so
the goal is to state the protections and the gaps plainly, not to claim
production-grade security.

See also: [trust-levels.md](trust-levels.md) and
[research-findings.md](research-findings.md).

## Assets

| Asset | Where | Why it matters |
|---|---|---|
| Root CA key (seed) | Board (PUF-wrapped), paper backup | Anchors the whole trust domain |
| Issuing CA keys / issuing master seed | Board, paper backup (seed) | Sign every SVID |
| Board TLS identity key | Board (ELS / PUF) | Proves to the server that it talks to the real board |
| SPIRE server secenclave-link client key | Ryzen disk | Authorizes signature requests |
| Registration entries / datastore | Ryzen | Decide who gets which SPIFFE ID |
| Agent and workload SVIDs | Nodes | Short-lived (about 1h) credentials |
| Join tokens | Transient | Single-use node bootstrap credentials |
| Signature log | Board | Audit trail, used to detect misuse |

## Adversaries

| ID | Adversary | Capability | In scope? |
|---|---|---|---|
| A1 | LAN attacker | Any device on the home LAN or Wi-Fi: sniffing, spoofing, MITM | **Yes** |
| A2 | Compromised workload | Code execution as one workload's UID | **Yes** |
| A3 | Compromised hardware node (Pi) | Root on the Pi | **Yes** |
| A4 | Compromised namespace node | Code as a `lab-node-N` UID on the Ryzen | **Yes** (with the shared-kernel caveat) |
| A5 | Compromised SPIRE server host | Root on the Ryzen | **Partially**: key theft is prevented, misuse is not |
| A6 | Stolen or cloned flash image of the board | Reads the board's flash offline | **Yes** |
| A7 | Physical attacker with a debugger | SWD access to the board | **No in Phase 1**: debug is open (see G3) |
| A8 | Lab-grade hardware attacks | Fault injection, side channels, decapping | **No** |
| A9 | Supply chain (NXP ROM, SDK, SPIRE releases) | Malicious vendor code | **No**: trusted by assumption |

## Threats and mitigations

| Threat | Mitigation | Residual risk |
|---|---|---|
| A1 sniffs or tampers with SPIFFE traffic | All node traffic is mTLS with SVIDs. SPIRE agent ↔ server traffic is mTLS | Metadata (who talks to whom) is visible |
| A1 reaches the secenclave | The board is on a dedicated link, not on the LAN. The Ryzen does not forward between interfaces (nftables drop, Milestone 4) | Misconfiguration on the Ryzen; checked by a test script |
| A1 impersonates the board to the server | mTLS: the server pins the board's CA or certificate | none known |
| A1 or A3 impersonates the server to the board | The board allow-lists the server's client certificate | Theft of that cert's key from the Ryzen (that is A5) |
| A2 steals an SVID | 1h TTL limits how long it is useful | Valid until expiry. There is no revocation in SPIFFE; short TTL *is* the mitigation |
| A3 abuses a node identity | Limited to that node's registered SPIFFE IDs | Accepted |
| A4 gets another namespace node's identity | Separate Unix users; the unix attestor checks the UID | **Any root or kernel compromise on the Ryzen defeats this.** Documented, accepted |
| A5 steals CA keys | Keys are never on the Ryzen: not in RAM, not on disk. Every signature happens on the board | none known for key *extraction* |
| A5 mints arbitrary SVIDs | The board logs every signature, rate-limits, and authenticates the caller | **Not prevented.** The SVID path signs a digest the board cannot inspect. Recovery: rebuild the Ryzen. No re-ceremony, because the keys never leaked |
| A5 gets a rogue intermediate signed by the root | The root path sends the full TBS/CSR to the board, which enforces policy: trust domain, pathlen, TTL limits | Policy bugs. Root use is rare and logged, so anomalies are visible |
| A6 extracts keys from a flash dump | Keys exist in flash only as PUF key codes, bound to that chip's silicon fingerprint | none known |
| A7 runs code to unwrap PUF keys | **None in Phase 1** | Accepted for a dev board with lab keys. Fix later: secure boot, debug authentication, lifecycle lock |
| Board failure / DoS | Existing SVIDs remain valid until expiry. Phase 2 adds a mirrored board | Phase 1 issuance outage of up to the SVID TTL |
| Paper backup lost | none in Phase 1 | Loss means re-ceremony and redistributing the trust bundle |
| Paper backup stolen | Physical security of the paper. Optional split backup (for example Shamir) is discussed in Milestone 6 | Accepted |
| Secrets committed to the public repo | `.gitignore` patterns, review discipline. Optional pre-commit secret scanner later | Human error |

## Known gaps (stated, not hidden)

- **G1. The SPIRE server is a powerful signing oracle.** The secenclave protects
  *keys*, not *authorization*. This is true of most hardware-backed CAs.
- **G2. Namespaces share a kernel** with each other and with the server.
- **G3. Debug is open on the board in Phase 1.** PUF wrapping defeats flash
  cloning, but not an attacker who can attach a debugger.
- **G4. ELS key derivation portability is unproven.** The paper backup may only
  restore onto an MCXN-family ELS, or possibly only onto the same chip, until
  test H2 passes. See research-findings §2.3.
- **G5. No hardware-rooted node attestation yet.** That comes later with the
  Ryzen fTPM. Note the [faulTPM](https://arxiv.org/abs/2304.14717) result:
  AMD fTPM secrets can be extracted with voltage fault injection by an attacker
  with physical access. So fTPM attestation helps against remote attackers,
  not physical ones.
- **G6. Home router.** The AX23 cannot isolate VLANs, so the LAN is flat. That
  is why the secenclave gets its own physical link instead of a VLAN.
- **G7. Time.** Short-lived certificates depend on correct clocks. The board
  has no battery-backed trusted time source. It will take time from the
  server, which lets a compromised server (A5) skew it. To be addressed in
  Milestone 4.

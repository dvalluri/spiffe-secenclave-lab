# spiffe-secenclave-lab

A home-lab distributed system where **every machine and every workload has a
short-lived cryptographic identity**, and **the CA keys that issue those
identities live only inside a small network secure enclave ("secenclave")
built from an NXP microcontroller**.

This is a personal learning project. It is not production software, the
hardware is a development board, and parts of the threat model are explicitly
out of scope. See [docs/threat-model.md](docs/threat-model.md).

> **Status:** Milestone 1 (repo skeleton and threat model). No code yet.

<!-- TODO: photo of the FRDM-MCXN947 board on its dedicated secenclave link -->
<!-- ![FRDM-MCXN947 secenclave](docs/images/secenclave-board.jpg) -->
*[Photo placeholder: FRDM-MCXN947 on the dedicated secenclave Ethernet link]*

## Goals

1. **Workload identity everywhere.** SPIFFE/SPIRE issues X.509-SVIDs with a TTL of
   about 1 hour, rotated automatically, to every node and workload.
2. **No CA private key on a general-purpose computer.** The root and the issuing
   CA keys live on the secenclave board, wrapped by the chip's PUF. The SPIRE server
   asks the board for every CA signature, including every workload SVID.
3. **A documented root of trust.** The root comes from an offline key ceremony
   with a paper backup.
4. **Scale without buying hardware.** You can add any number of virtual nodes as
   Linux network namespaces, alongside real hardware nodes.
5. **Be honest about trust.** Namespace nodes and hardware nodes have different
   trust levels, and the docs say so plainly.
6. **Room to grow.** Phase 2 adds a second, mirrored secenclave board for active-active
   fault tolerance. The Phase 1 board client already takes a list of boards.

## Hardware

| Role | Device | Notes |
|---|---|---|
| SPIRE server, a SPIRE agent, namespace nodes | AMD Ryzen devbox (Linux) | Also the only host on the secenclave link |
| Physical node | Raspberry Pi 5 | Runs a SPIRE agent (Milestone 7) |
| Network secure enclave (secenclave) | NXP FRDM-MCXN947 | Ethernet only, on a dedicated link. A second board comes in Phase 2 |
| Home router | TP-Link Archer AX23 | No reliable LAN VLAN isolation, so the LAN is treated as untrusted |

## Architecture

```
                    OFFLINE (air-gapped laptop, key ceremony)
                    root seed + issuing seed  -->  paper backup
                                  |
                                  | one-time import during the ceremony (Milestone 6)
                                  v
 +--------------------------------------------------------------------------+
 |  FRDM-MCXN947  "secenclave"                                              |
 |   - CA keys stored in flash only as PUF-wrapped key codes                |
 |   - signing done in the ELS security subsystem (ECDSA P-256)             |
 |   - own PUF-wrapped TLS identity key; mutual TLS listener                |
 |   - allow-list of SPIRE server client certs; logs every signature        |
 +-----------------------------------+--------------------------------------+
                                     |  dedicated Ethernet (2nd NIC / USB NIC)
                                     |  mTLS; NOT bridged to the home LAN
 +-----------------------------------+--------------------------------------+
 |  Ryzen devbox                                                             |
 |   spire-server                                                            |
 |     +- UpstreamAuthority plugin --> board: "sign this intermediate"       |
 |     +- KeyManager plugin --------> board: "sign this digest"              |
 |        (both share one Go board client: list of boards + failover)        |
 |   spire-agent (host)                                                      |
 |   br-lab bridge                                                           |
 |     +- ns node-01 (uid lab-node-01) 10.77.0.11                            |
 |     +- ns node-02 (uid lab-node-02) 10.77.0.12                            |
 |     +- ... N namespaces (shared kernel: NOT a security boundary)          |
 +-----------------------------------+--------------------------------------+
                                     | home LAN (untrusted, no VLANs)
                          +----------+----------+
                          | Raspberry Pi 5      |
                          | spire-agent         |
                          +---------------------+
```

The addresses and names above are illustrative. Milestone 2 fixes the real ones.

### Key hierarchy

| Key | Generated | Stored | Used for | Plugin |
|---|---|---|---|---|
| Root CA | Offline ceremony, from a seed backed up on paper | secenclave board, PUF-wrapped | Signing SPIRE's intermediate CA certificates (rare) | UpstreamAuthority |
| Issuing (intermediate) CA keys | Derived on the board per CA rotation from a ceremony master seed (paper-backed) | secenclave board, never exported | Signing every X.509-SVID and JWT-SVID | KeyManager |
| Board TLS identity | On the board | secenclave board, PUF-wrapped / ELS slot | mTLS server identity toward the SPIRE server | none |
| SPIRE server's client cert for the secenclave link | Ryzen box | Ryzen disk (low value, can be revoked) | Authenticating to the board | none |

**Why two plugins?** In SPIRE, the *KeyManager* holds the key that actually
signs SVIDs, and the *UpstreamAuthority* signs SPIRE's own CA certificate.
To keep both keys off the server you need both plugins. The full reasoning is
in [docs/research-findings.md](docs/research-findings.md).

## Trust levels (summary)

| Level | What | Why it is trusted (or not) |
|---|---|---|
| T0 | Offline ceremony and paper backup | Never networked |
| T1 | secenclave board | Dedicated hardware, PUF-wrapped keys, single-purpose firmware |
| T2 | SPIRE server host (Ryzen) | Holds no CA keys, but it **decides who gets which identity** |
| T3 | Hardware nodes (Pi 5) | Separate kernel and machine |
| T4 | Namespace nodes | **Share one kernel with each other and with the SPIRE server.** Useful for scale and topology, not for isolation |
| none | Home LAN | No VLAN isolation. Assume an attacker can reach it |

Details: [docs/trust-levels.md](docs/trust-levels.md).

## Milestones (Phase 1)

Each milestone stops for review before the next one starts.

- [x] **1. Repo skeleton.** README, license, `.gitignore`, threat model, trust levels
- [ ] **2. Namespace lab.** Scripts to create and destroy N namespace nodes on a bridge
- [ ] **3. Software-only SPIRE baseline.** Test-only software keys; two namespace nodes talk over mTLS using SVIDs
- [ ] **4. Board firmware.** mTLS listener, PUF-wrapped key storage, sign-digest command, signature log
- [ ] **5. SPIRE plugins (Go).** All CA signing goes to the board; board list and failover
- [ ] **6. Key ceremony.** Offline root and issuing seed generation, paper backup, import, wipe
- [ ] **7. Pi 5 joins** as a physical node

### Later (not Phase 1)

- TPM node attestation using the Ryzen fTPM, documenting the
  [faulTPM](https://arxiv.org/abs/2304.14717) caveat (AMD fTPM state can be
  extracted with voltage fault injection, given physical access)
- Anti-tamper hardening, and moving the board into a locked lifecycle state
- Post-quantum signing (ML-DSA)
- A second secenclave board with mirrored keys, active-active

## Repository layout

```
docs/
  threat-model.md        assets, adversaries, what is and is not defended
  trust-levels.md        hardware nodes vs. namespace nodes, and why it matters
  research-findings.md   verified facts behind the design (SPIRE, MCXN947, TLS)
  images/                board photos (no serial-number stickers!)
LICENSE                  Apache-2.0
```

## Secrets policy

This repo is public. Private keys, seeds, join tokens, PINs, PUF activation
codes or key codes, and device serial numbers are **never** committed.
[.gitignore](.gitignore) blocks common patterns, but it is only a safety net.
Review `git diff --cached` before every commit. Crop serial-number stickers
out of board photos.

## License

[Apache License 2.0](LICENSE). This matches the SPIFFE/SPIRE ecosystem, and the
plugin code will be built against SPIRE's Apache-2.0 plugin SDK.

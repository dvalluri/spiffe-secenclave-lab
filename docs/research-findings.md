# Research findings (verified before coding)

Checked on 2026-11-25. Each item is tagged:

- **[verified]**: read in a primary source (SDK source code, a proto file, or vendor docs).
- **[inferred]**: follows from verified facts, but not stated directly.
- **[unverified]**: still has to be tested on hardware or confirmed in the reference manual.

Sources: SPIRE v1.16.0 and the spire-plugin-sdk protos (`main`, latest tag v1.16.0),
and a local MCUXpresso SDK 26.06 checkout (`mcuxsdk/`). The paths below are relative
to that checkout.

---

## 1. Which SPIRE plugin type: KeyManager, UpstreamAuthority, or both?

### The interfaces (spire-plugin-sdk, `proto/spire/plugin/server/...`)

**KeyManager** (`keymanager/v1/keymanager.proto`) [verified]

```proto
service KeyManager {
  rpc GenerateKey(GenerateKeyRequest)     returns (GenerateKeyResponse);   // key_id, key_type
  rpc GetPublicKey(GetPublicKeyRequest)   returns (GetPublicKeyResponse);
  rpc GetPublicKeys(GetPublicKeysRequest) returns (GetPublicKeysResponse);
  rpc SignData(SignDataRequest)           returns (SignDataResponse);      // key_id, data, hash_algorithm | pss_options
}
// KeyType: EC_P256, EC_P384, RSA_2048, RSA_4096
// PublicKey{id, type, pkix_data, fingerprint}. (id, fingerprint) identifies a key "instance".
// GenerateKey on an existing id overwrites it and MUST yield a new fingerprint.
```

**UpstreamAuthority** (`upstreamauthority/v1/upstreamauthority.proto`) [verified]

```proto
service UpstreamAuthority {
  rpc MintX509CAAndSubscribe(MintX509CARequest)       returns (stream MintX509CAResponse);  // csr, preferred_ttl
  rpc PublishJWTKeyAndSubscribe(PublishJWTKeyRequest) returns (stream PublishJWTKeyResponse); // optional
  rpc PublishWITKeyAndSubscribe(PublishWITKeyRequest) returns (stream PublishWITKeyResponse); // optional, new
  rpc SubscribeToLocalBundle(...)                     returns (stream ...);                   // optional
}
// MintX509CAResponse{x509_ca_chain (first = new CA cert), upstream_x509_roots}
```

### What each one controls

- **KeyManager** holds the SPIRE server's *own* signing keys: the X.509 CA key
  that signs every X.509-SVID, and the JWT signing keys. SPIRE calls
  `GenerateKey` on every CA rotation. It uses A/B key slots, so it can prepare
  the next key while the current one is still in use. Then it calls `SignData`
  for each SVID. [verified: proto comments; inferred: A/B slot naming comes from the
  SPIRE server CA manager, not the proto]
- **UpstreamAuthority** receives SPIRE's CA **CSR** and returns a signed CA
  certificate plus the upstream roots. It runs about once per CA rotation.

### Conclusion: both are needed for this project's requirements

| Requirement | KeyManager only | UpstreamAuthority only | Both |
|---|---|---|---|
| Root key never on server | no (SPIRE self-signs, so the "root" is a rotating KeyManager key) | yes | yes |
| Issuing key never in server RAM or disk | yes | **no** (SPIRE's own CA key sits in a server-side KeyManager) | yes |
| Ceremony-backed root | no | yes | yes |

- An UpstreamAuthority alone would leave the key that signs every SVID in
  server memory (or in the `disk` KeyManager's `keys.json`). That violates the
  spec.
- A KeyManager alone would make SPIRE's self-signed, rotating CA the trust
  anchor. There would be no ceremony root.
- So: **UpstreamAuthority = root on the board; KeyManager = issuing keys on the
  board.** Both are thin Go plugins that share one `boardclient` package (list
  of boards, failover). They are two plugin binaries, or one binary run as two
  plugin instances. Which of those the SDK supports is to be confirmed in
  Milestone 5.

### Tradeoffs and consequences to design around

1. **Rotation versus "intermediate from the ceremony".** SPIRE expects
   `GenerateKey` to make a **new** key on every CA rotation (default `ca_ttl` is
   24h). If one static intermediate from the ceremony is returned for every
   `GenerateKey` call, that breaks the fingerprint contract and removes
   rotation. Two ways to resolve this:
   - (a) **The board derives a fresh issuing key per rotation** from a
     ceremony-generated *issuing master seed*, by KDF over
     `(key_id, generation)`. Two boards that hold the same master seed derive
     the same keys, which is what the Phase 2 mirror needs. The ceremony still
     backs everything up on paper. **Decided (2026-11-25), accepted with
     reservations.** The owner preferred one fixed ceremony intermediate, but
     that conflicts with SPIRE's rotation model. Every derived intermediate can
     be rebuilt from the paper-backed master seed, so the ceremony remains the
     only source of issuing key material. Whether ELS can feed a KDF output
     into ECC key generation is [unverified] (see 2.3, H4). If H4 fails, this
     decision is reopened.
   - (b) The board generates random issuing keys. This is simpler, but the
     keys cannot be mirrored, and they cannot be restored from paper. That is
     acceptable, because the root re-signs new ones.
2. **The board signs a digest it cannot inspect.** `SignData` carries `data`,
   which for ECDSA is the pre-computed hash. (SPIRE wraps the KeyManager as a
   Go `crypto.Signer`, so `data` is the digest.) [inferred from the
   `crypto.Signer` design; confirm in Milestone 5.] The board therefore
   **cannot enforce policy** on SVID contents. A compromised SPIRE server can
   get any SVID in the trust domain signed while it stays compromised. What the
   board *can* do is authenticate the caller, rate-limit, and log. See the
   threat model.
3. **The root signing path can enforce policy.** UpstreamAuthority receives the
   full CSR. The plan is to send the full TBSCertificate (or the CSR plus
   parameters) to the board, so the board can check the trust domain, path
   length, and TTL limits before signing with the root.
4. **Availability.** In Phase 1 the board is a single point of failure. If it is
   down, no new SVIDs are issued. Existing SVIDs keep working until they
   expire, which is about 30 to 60 minutes with a 1h TTL. This is the main
   motivation for the Phase 2 mirror.
5. **Load.** A few hundred `SignData` calls per hour at lab scale. An ECDSA
   P-256 signature in ELS takes milliseconds. Keep one persistent mTLS session
   per board, instead of a TLS handshake per signature.
6. **Key type.** Configure SPIRE with `ca_key_type = "ec-p256"` and
   `jwt_key_type = "ec-p256"`. ELS supports **only P-256** for ECDSA (see 2.2).
7. **WIT keys (new in recent SDKs).** `PublishWITKeyAndSubscribe` exists. Whether
   SPIRE v1.16 also asks the KeyManager for WIT signing keys is [unverified].
   Check this in Milestone 3.

---

## 2. MCXN947 security features

### 2.1 PUF key wrapping [verified: `drivers/puf_v3/fsl_puf_v3.h`, driver v2.0.4]

- An SRAM-based PUF with Enroll / Start / Wrap / Unwrap / GetKey /
  WrapGeneratedRandom / Zeroize / SetLock.
- `PUF_Wrap(userKey) -> keyCode`. The key code can be stored in ordinary flash.
  It is bound to this chip's PUF fingerprint.
- Unwrap destinations: `kPUF_KeyDestRegister` (to CPU-readable memory) or
  `kPUF_KeyDestKeyBus` (a hardware key bus to the crypto engine, never visible
  to the CPU).
- The **activation code** comes from Enroll, once per device. It is needed at
  every boot, and is normally stored in protected flash (the ROM can manage
  this). It is device-unique, so it is in `.gitignore`.
- `PUF_SetLock` / `PUF_SetCtxMask` restrict the PUF by security level
  (Secure / Non-secure, privileged / user). This lets the PUF be confined to
  the TrustZone secure world.

### 2.2 Crypto accelerator: ELS (EdgeLock Secure Subsystem, "S50") + PKC [verified: `components/els_pkc/includes/mcuxClEls_*.h`]

- `mcuxClEls_EccSign_Async` does ECDSA **NIST P-256 only** and accepts a
  pre-hashed input (`MCUXCLELS_ECC_HASHED`). That matches the KeyManager's
  sign-digest model.
- `mcuxClEls_EccKeyGen_Async` generates a P-256 key in an ELS key slot. It can
  be *random*, or *deterministic* from key material already in the slot. The
  private key stays in the slot.
- `mcuxClEls_KeyImport_Async` formats: `RFC3394` (wrapped blob), **`PUF`
  (the key arrives over the PUF key bus)**, `UDF`, `PBK`.
- `mcuxClEls_KeyExport_Async` exports slot contents wrapped with RFC3394, so
  board-generated keys can persist across reboots as wrapped blobs in flash.
- The PKC co-processor handles P-384, RSA, and other curves through
  `mcuxClEcc` / `mcuxClRsa`. Its scalars pass through CPU-visible RAM, so it is
  a weaker option than ELS.
- The PSA opaque driver uses location `0xC00401` for keys held in ELS slots
  ("never leave the ELS50 in plain format": the
  `psa_crypto_opaque_key_examples` readme). mbedTLS 3.x can therefore use an
  ELS key as the **board's TLS identity key** without exposing it.

### 2.3 Important finding: ELS cannot sign with an arbitrary imported ECC private key

The NXP PSA driver imports ECC keys like this
(`components/psa_crypto_driver/els_pkc/oracle/src/mcuxClPsaDriver_Oracle_Utils.c`,
`..._ExecuteElsKeyIn`):

1. `KeyIn` a blob into a slot. The slot must have the property
   `ukgsrc` ("usable as key material input for ECC key generation").
2. Run `EccKeyGen` in **deterministic** mode on that slot. ELS derives the
   private key and returns the public key.

So the imported material is a **seed**, and ELS derives the actual P-256
private scalar from it internally. [verified from code] Consequences:

- The ceremony should generate a 256-bit **seed**, not an ECDSA private key.
  The paper backup records the seed.
- **The root public key cannot be computed offline from the seed.** Only an ELS
  can turn the seed into the key pair. So the board self-signs the root
  certificate after import, and the ceremony records its fingerprint. [inferred]
- **Portability risk.** If the derivation mixes in a device-unique secret,
  then a paper backup restored onto a *different* board yields a *different*
  key. That would break both disaster recovery and the Phase 2 mirror.
  [unverified. **This is the most important hardware test.** One board is
  enough to show the derivation is deterministic across reboots. Proving it is
  device-independent needs board #2, or an NXP statement.]
- Proposed import path, with the seed never in CPU-readable memory after the
  ceremony: ceremony → `PUF_Wrap(seed)` → key code in flash. At each boot,
  `PUF_Unwrap(..., kPUF_KeyDestKeyBus)` → `mcuxClEls_KeyImport(KFMT_PUF)` →
  `EccKeyGen(deterministic)`. Whether a slot loaded with `KFMT_PUF` can carry
  `ukgsrc` is [unverified].
- During the ceremony, the plaintext seed passes once through board RAM (over
  UART or USB) to be PUF-wrapped. That is unavoidable for an
  externally generated key, and Milestone 6 documents it.

**Fallback (option B):** keep the private scalar PUF-wrapped, unwrap it into
CPU RAM, and sign with PKC/`mcuxClEcc`. The paper backup is then a standard
key, portable to any software. The cost is that the scalar sits briefly in
board SRAM. It still never touches the server.

**Decision pending (owner's call):** option A (ELS-native seed: the key can
never be exported, but portability is unproven) or option B (PKC with a
standard key: portable, but weaker on the board). My recommendation is A, with
B as the fallback if the portability test fails.

### 2.4 Secure boot [verified: MCX Nx4x Security Reference Manual excerpts]

- The ROM authenticates images with ECDSA P-256/P-384 or CMAC. The root-of-trust
  key hash (RKTH) is provisioned in CMPA.
- PRINCE on-the-fly flash encryption uses a PUF-derived device-unique key.
- Tooling: NXP SPSDK (`nxpimage`, `blhost`) / the Secure Provisioning Tool.

### 2.5 Debug lockout [verified: SPSDK MCXN9xx debug-auth docs and the Security RM]

- Debug access is controlled by CMPA/CFPA settings and lifecycle state, with
  **debug authentication** (a challenge-response DAT signed by a
  debug-credential key).
- When the device enters failure-analysis (FA) mode, **the PUF key store is
  emptied and PUF unwrapping is blocked** before debug is opened. That is good:
  an RMA or FA path destroys the wrapped keys.
- **Security note:** while debug is open, anyone with SWD access can run code on
  the chip, and **that code can ask the PUF to unwrap keys**. PUF wrapping alone
  stops flash dumps and cloning, not physical attackers with a debugger. Real
  protection needs secure boot plus debug lockout. Lifecycle transitions are
  **irreversible**, and a mistake can brick the board. Phase 1 therefore stays
  in the open "develop" state, documents this, and uses lab keys only. Locking
  is part of the later hardening work.

---

## 3. Ethernet + mutual TLS within the board's memory [verified: SDK examples / linker script]

- The FRDM-MCXN947 board has a 10/100 Ethernet PHY. The SDK ships
  `lwip_httpssrv_mbedTLS` (bare-metal and FreeRTOS), `lwip_https_client`, and
  others for this board.
- The FreeRTOS HTTPS server example uses **mbedTLS 3.x**
  (`CONFIG_MCUX_COMPONENT_middleware.mbedtls3x=y`) with the ELS/PKC PSA driver.
  Its `example.yml` excludes the armgcc *debug* build for this board. The
  likely reason is flash or RAM size; the release build is supported.
  [inferred reason]
- Memory: the default linker script gives `m_data` = 0x4E000 (312 KB) plus 96 KB
  SRAMX. NXP lists 512 KB SRAM and 2 MB flash in total. [linker: verified;
  totals: from the datasheet]
- mTLS cost: a TLS 1.2 or 1.3 server with ECDHE-ECDSA P-256, client-cert
  verification, and 4 to 8 KB record buffers typically needs on the order of
  40 to 80 KB of heap per session. [inferred from general mbedTLS sizing;
  measure in Milestone 4] One session (or two, for Phase 2 testing) fits
  comfortably.
- **Conclusion: feasible.** Use lwIP + mbedTLS 3.x + FreeRTOS, a single cipher
  suite (ECDHE-ECDSA-AES128-GCM-SHA256 or TLS 1.3 AES-128-GCM), and the board's
  TLS key as an ELS opaque PSA key.

---

## Open items that need hardware

| # | Question | How to test | Blocks |
|---|---|---|---|
| H1 | Is ELS deterministic keygen repeatable across reboots? | Import the same seed twice, compare public keys | M4 |
| H2 | Is it device-independent? | Same seed on board #2 | Phase 2 / recovery |
| H3 | Can a `KFMT_PUF` import be used as `ukgsrc`? | Try it | M4 |
| H4 | Can ELS CKDF output become `ukgsrc` (per-rotation derivation)? | Try it | M5 |
| H5 | Real mbedTLS heap peak with mTLS | Instrument the allocator | M4 |
| H6 | Does SPIRE v1.16 request WIT keys from the KeyManager? | Software baseline | M3 |

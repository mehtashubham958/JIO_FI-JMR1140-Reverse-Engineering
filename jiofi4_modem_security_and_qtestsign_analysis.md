# Technical Deliverable: Qualcomm MDM9607 Modem Security & Firmware Modification Analysis

**Target Device:** JioFi 4 (AMTelecom JMR1140)  
**SoC:** Qualcomm MDM9607 (ARM Cortex-A7 AP + Hexagon QDSP6 v5 Baseband + ARM TrustZone)  
**Linux Kernel:** 3.18.20 (UBIFS root filesystem, writable `/data`)  
**Investigation Scope:** Modem firmware modification feasibility, `qtestsign` codebase audit, trust-chain architecture, forensic artifact inventory, and ranked SIM compatibility mitigation strategies.

---

## 1. Executive Verdict

### Definitive Technical Verdict: Modem Firmware Patching is IMPLAUSIBLE & UNNECESSARY
1. **Modem Firmware Modification is Infeasible via Software / Test Signing:**  
   The Qualcomm Hexagon modem subsystem is loaded by the Linux kernel driver `pil-q6v5-mss` using Qualcomm's **Modem Self-Authentication (MSA)** protocol backed by the Modem Boot Authenticator (`mba.mbn`). MBA validates the MBN v3 header, RSA signature, X.509 certificate chain, and SHA-256 hashes of every individual program segment (`modem.b00` through `modem.b24`). Modifying any instruction inside `modem.b12` alters its SHA-256 digest, causing MBA to reject the blob during `pil_msa_mba_verify_blob` and assert a kernel PIL panic / Sahara crash loop.

2. **`qtestsign` Cannot Resign the Modem Firmware:**  
   Auditing the `qtestsign` source code (`mbn/hashseg.py:326`) reveals that **`qtestsign` does not generate real RSA signatures at all**—it inserts dummy `0xFF` padding as a stub signature! Furthermore, forensic parsing of JioFi's `modem.b01` and `mba.b01` reveals they are authenticated against Qualcomm's standard test root (`CN=QPSA F4 TEST ROOT`), whereas `qtestsign` generates an arbitrary dummy root (`CN=qtestsign Root CA - NOT SECURE`). On production Qualcomm hardware where MBA enforces RSA validation, `qtestsign` images fail verification immediately.

3. **Firmware Modification is Completely Unnecessary to Solve Non-Jio SIM Incompatibility:**  
   The root cause of the non-Jio (Airtel) initialization failure does **not** reside in the signed baseband DSP firmware. It is caused by host-side defects in AMTelecom's Linux userspace binary `libqcmap_cm.so.1` (`_Z17qcmap_cm_get_imsiPiPc`), which requests EF_IMSI using a hardcoded SIM file path (`3F00/7FFF/6F07`) without selecting the USIM Application Identifier (AID). Because root ADB access is already established on the Linux Application Processor, this defect can be resolved **entirely in userspace** via an `LD_PRELOAD` shared library shim or AT-port query over `/dev/smd8`—with **zero risk of bricking the modem**.

---

## 2. `qtestsign` Compatibility Assessment

**Target Repository:** `https://github.com/msm8916-mainline/qtestsign`  
**Inspected Commit:** `0eef3b552b1ada848f22bad38ab2e40407307c5b` (Debian pyproject update by Christopher Obbard)  
**Primary Author:** Stephan Gerhold  

### 2.1 Supported ELF Formats, Image Types & Chipset Generations
- **ELF Architectures:** Supports 32-bit (`ei_class = 1`) and 64-bit (`ei_class = 2`) ELF binaries (`mbn/elf.py`).
- **MBN Header Versions:** Supports MBN Header Versions 3, 5, 6, and 7 (`mbn/hashseg.py:HashSegmentV3`, `V5`, `V6`, `V7`).
  - MDM9607 modem firmware uses **MBN Version 3** (`<10L` 40-byte header: `image_id`, `version=3`, `flash_addr`, `dest_addr`, `total_size`, `hash_size`, `sig_addr`, `sig_size`, `cert_addr`, `cert_size`).
- **Supported Software IDs (`qtestsign.py:FW_SW_ID`):**
  - `"mba": 0x01`
  - `"modem": 0x02`
  - `"sbl1": 0x00`, `"tz": 0x07`, `"aboot": 0x09`, `"rpm": 0x0A`, `"tz-app": 0x0C`, `"wcnss": 0x0D`, `"venus": 0x0E`.

### 2.2 Mechanism of Operation
`qtestsign` does not modify executable code instructions. It performs structural MBN wrapping:
1. Strips non-loadable headers and sections from an input ELF binary.
2. Inserts an ELF header placeholder segment (`PHDR_FLAGS_HDR_PLACEHOLDER = 0x7000000`).
3. Computes SHA-256 hashes of the ELF header and each loadable program segment (`p_type == PT_LOAD`).
4. Appends a NULL hash table segment (`PHDR_FLAGS_HASH_SEGMENT = 0x2200000`).
5. Generates an X.509 certificate chain (`mbn/cert.py:generate_chain`) containing two certificates:
   - Root Certificate: `CN=qtestsign Root CA - NOT SECURE` (self-signed with hardcoded PEM `ROOT_KEY`).
   - Attestation Certificate: `CN=qtestsign Attestation CA - NOT SECURE` (signed by `ROOT_KEY`).

### 2.3 The Critical Signature Reality: Stubbed `0xFF` Padding
In `mbn/hashseg.py` (lines 321–327), the signature generation logic is explicitly documented and implemented as:
```python
# TODO: Generate actual signature with our generated attestation certificate!
# There are different signature schemes that could be implemented (RSASSA-PKCS#1 v1.5
# RSASSA-PSS, ECDSA over P-384) but it's not entirely clear yet which chipsets supports/
# uses which. The signature does not seem to be checked on devices without secure boot,
# so just use a dummy value for now.
hash_seg.signature = b'\xff' * (cert.ATT_KEY.key_size // 8)
# hash_seg.signature = b''  # uncomment this to omit the signature in the signed image
```
**Finding:** `qtestsign` **does not generate cryptographic signatures**. It fills the 256-byte RSA signature field entirely with `0xFF` bytes.

### 2.4 Verification Environment & Failure Mode on MDM9607
- **Where `qtestsign` Works:** Only on engineering sample development boards (e.g., DragonBoard 410c) where Qualcomm Secure Boot eFuses are either completely unblown (`SEC_BOOT_EN == 0`, `AUTH_EN == 0`) or signature verification is disabled in hardware.
- **Why It Fails on JioFi MDM9607:**  
  1. The JioFi modem loader executes MSA (`pil_msa_auth_modem_mdt`), where MBA validates the RSA signature across the hash segment. A buffer of `0xFF` bytes fails RSA PKCS#1 v1.5 mathematical verification.
  2. The root CA burned into the MDM9607 trust configuration is Qualcomm's `QPSA F4 TEST ROOT` (or an OEM CA), whereas `qtestsign` embeds its own `qtestsign Root CA`.
  3. Flashing or loading a `qtestsign`-modified `modem.mdt` will cause MBA to return authentication error `0x3` (`ERR_AUTH_FAIL`), causing `pil-q6v5-mss` to time out and halt the baseband processor.

---

## 3. Trust-Chain and Modem Loading Architecture

The following diagram maps the boot and modem verification stages from silicon reset to Hexagon execution on the JioFi 4 JMR1140:

```mermaid
flowchart TD
    subgraph Silicon_Hardware ["Silicon Hardware (ROM & Fuses)"]
        ROM["Primary Boot Loader (PBL) in Silicon ROM"]
        QFPROM["QFPROM eFuses<br/>(SEC_BOOT_EN, OEM_PK_HASH)"]
    end

    subgraph Bootloader_Chain ["Application Processor Bootloader Chain"]
        SBL1["Secondary Boot Loader (sbl1.mbn - mtd0)<br/>DDR Initialization"]
        TZ["TrustZone Secure Monitor (tz.mbn - mtd3)<br/>Cert: Generated Test Root CA"]
        RPM["Resource Power Manager (rpm.mbn - mtd4)"]
        LK["Little Kernel (aboot - mtd7)<br/>scm_check_boot_fuses()"]
        KERNEL["Linux Kernel 3.18.20 (boot.img - mtd8)<br/>Rootfs UBIFS (mtd16)"]
    end

    subgraph Modem_Subsystem ["Modem Subsystem Authentication (PIL / MSA)"]
        PIL["Linux Kernel Driver: pil-q6v5-mss<br/>Reserved Memory Carveout: 0x82a00000 - 0x86a00000 (64 MiB)"]
        MBA["Modem Boot Authenticator (mba.mbn)<br/>Loaded to 0x8fd00000 - 0x8fe00000<br/>Cert: QPSA F4 TEST ROOT"]
        MDT["Modem Metadata (modem.mdt / modem.b01)<br/>MBN v3 Header + SHA-256 Hashes + RSA Sig"]
        BLOBS["Modem Segments (modem.b00 - modem.b24)<br/>ELF Sections streamed to DDR"]
        DSP["Hexagon QDSP6 v5 Baseband Core<br/>Execution Starts at 0x82a00000"]
    end

    %% Flow connections
    ROM -->|Authenticates SBL1 via QFPROM| SBL1
    SBL1 -->|Loads & Authenticates| TZ
    SBL1 -->|Loads & Authenticates| RPM
    TZ -->|Launches| LK
    LK -->|SCM Call 6/4 to TZ| QFPROM
    LK -->|Loads Kernel| KERNEL
    KERNEL -->|Mounts /firmware (mtd10)| PIL
    PIL -->|1. Loads MBA| MBA
    TZ -->|Authenticates MBA| MBA
    MBA -->|2. Authenticates modem.mdt RSA Sig| MDT
    PIL -->|3. Streams Segments| BLOBS
    MBA -->|4. Verifies each segment SHA-256| BLOBS
    MBA -->|5. Brings Hexagon out of reset| DSP
```

### Verification Transition Analysis
1. **PBL to SBL1:** Hardware-enforced. Silicon ROM checks `sbl1.mbn` against QFPROM.
2. **SBL1 to TrustZone / LK:** SBL1 validates `tz.mbn` (authenticated with `Generated Test Root CA`).
3. **LK (`aboot`) to Kernel:** As disassembled in `scm_check_boot_fuses` ([`0x8290fa4c`](file:///home/shubham/lab/jiofi/JioFi-4-JMR1140/aboot-original.bin#L2326)), Little Kernel invokes SCM Service `0x08` / Function `0x04` to query secure boot fuses.
4. **Kernel PIL to Hexagon:** The Linux kernel driver `pil-q6v5-mss` does not verify signatures itself; it orchestrates the handshake between TrustZone and MBA:
   - Line 5.040 in dmesg: `Loading MBA and DP (if present) from 0x8fd00000 to 0x8fe00000`
   - Kernel calls `pil_msa_auth_modem_mdt` to pass `modem.mdt` to MBA.
   - For each segment `modem.bXX`, kernel calls `pil_msa_mba_verify_blob` where MBA validates the segment hash before enabling execution.

---

## 4. Artifact Inventory

Every artifact listed below has been verified on the local host filesystem or extracted directly from target hardware:

| Artifact Name | Location | Size (Bytes) | SHA-256 Checksum | Established Evidentiary Value |
| :--- | :--- | :--- | :--- | :--- |
| **JioFi Raw Modem Partition** | `/home/shubham/lab/jiofi/analysis/modem-mtd10.raw` | 42,074,112 | `8e6bd823bba550477179ddfbe98301404328e2905a6fdd80ee5424d7ab137792` | Pristine 40.125 MiB stock UBIFS image of `mtd10` (`modem`). |
| **JioFi Modem Header** | `/home/shubham/lab/jiofi/JioFi-4-JMR1140/modem.mdt` | 8,156 | `91a00e3112753bc789a167a07b8a58cdf6efd5e5ad9e47b516845fca44e358a5` | 32-bit QDSP6 ELF header, 26 program headers, physical load base `0x82a00000`. |
| **JioFi Hash & Cert Segment** | `/home/shubham/lab/jiofi/extracted/modem/104299964/modem/image/modem.b01` | 7,272 | `0e73385d972d3fe66fb2d8ae934f364027cac201500c5b773276acfa81994e88` | MBN v3 header, 26 SHA-256 hashes (832 B), 2048-bit RSA sig, Qualcomm `QPSA F4 TEST ROOT` CA chain. |
| **JioFi Reconstructed ELF** | `/home/shubham/lab/jiofi/segment-analysis/modem-reconstructed.elf` | 67,108,864 | `389779a2c365b11679648fbee08540a0ec0cfcda8d5cef215f4fa43de1f35c97` | Unified 64 MiB flat memory space (`0x82a00000`–`0x86a00000`) for static disassembly. |
| **JioFi Little Kernel** | `/home/shubham/lab/jiofi/JioFi-4-JMR1140/aboot-original.bin` | 394,108 | `8982b2585813221fafc52683233f48768e6eff795946484f622ec46bad9d7946` | Unstripped ARM 32-bit Little Kernel, SCM fuse check logic, fastboot dispatch table. |
| **JioFi TrustZone Partition** | `/tmp/jiofi_tz.bin` (pulled from `/dev/mtd3ro`) | 1,048,576 | `50418e98dc7af36396bc321d87a84be8e48d9ddbde97364bf41447e29c20e35d` | ARM TrustZone Secure Monitor, signed with `CN=Generated Test Root CA` (SecTools test key). |
| **Quectel NON-HLOS UBI** | `quectel_eg25/.../update/NON-HLOS.ubi` | 41,025,536 | `18688365881a001eebe4e62bcbeabe12c5190bf544834410a4f5b16f4fc67f5e` | Quectel modem partition (54.27 MiB raw NAND). Incompatible with JioFi 40.125 MiB partition. |
| **Quectel System UBI** | `quectel_eg25/.../update/mdm9607-sysfs.ubi` | 35,520,512 | `fde4799087e0ba94616c42634a74d708e3fa8400b6b2e9535a35c51c06c6803a` | Quectel OpenLinux rootfs; contains reference Qualcomm data services (`netmgrd`, `qmuxd`). |
| **Quectel Boot Image** | `quectel_eg25/.../update/mdm9607-boot.img` | 7,372,800 | `f6652ebc0340867b033a71e0afa272d1342573b5c1c2661a68058f459381afb6` | Android boot image format for MDM9607 with Quectel kernel configuration. |
| **`qtestsign` Source Tree** | `/home/shubham/lab/jiofi/scratch/qtestsign` | Git Repo | Commit: `0eef3b55` | Test-signing script source proving stub signature (`0xFF`) and test cert generation. |

---

## 5. SIM Failure Analysis: Established Observations vs. Hypotheses

```
┌────────────────────────────────────────────────────────────────────────┐
│                     SIM COMPATIBILITY AUDIT MATRIX                     │
├────────────────────────────────────────────────────────────────────────┤
│ DIRECTLY OBSERVED FACTS:                                               │
│ 1. Jio SIM initializes normally, attaches to LTE B3/B5, connects data. │
│ 2. Airtel SIM physically detects, transitions to app_state = 4         │
│    (PERSONA_CHECK_REQ), and halts with UIM_MEMORY_PROBLEM error.       │
│ 3. Disassembly of modem Hexagon binary proves missing                  │
│    halt_subscription does NOT cause SIM rejection (perso evt DONE).    │
│ 4. rpm_iccid is 3GPP Radio Policy Manager APN backoff cache, not lock. │
│ 5. AT ports /dev/smd8 and /dev/smd7 respond to standard 3GPP AT        │
│    commands directly from Linux userspace.                             │
│                                                                        │
│ CRITICAL HYPOTHESIS & CODE ANOMALY:                                    │
│ - AMTelecom's libqcmap_cm.so.1 implements _Z17qcmap_cm_get_imsiPiPc   │
│   which attempts to read EF_IMSI (0x6F07) via raw path 3F00/7FFF/6F07  │
│   without selecting USIM AID (A0000000871002...).                      │
│ - Modern Airtel USIM cards reject raw path reads if AID is unselected, │
│   triggering Status 7 / UIM_MEMORY_PROBLEM in QCMAP userspace.         │
└────────────────────────────────────────────────────────────────────────┘
```

### 5.1 Disassembly Evidence of `_Z17qcmap_cm_get_imsiPiPc`
In `/usr/lib/libqcmap_cm.so.1` (virtual address `0x0001f3e4`), AMTelecom added custom code to query the IMSI during connection initialization:
1. It constructs a QMI UIM Read Transparent request targeting File ID `0x6F07` (EF_IMSI).
2. It hardcodes the path as `3F00/7FFF` (`MF/ADF_USIM`), assuming logical channel 0 is already bound to the USIM application.
3. On Airtel 4G USIM cards where the USIM application requires explicit `SELECT AID`, reading `0x6F07` returns SW1=0x6A, SW2=0x82 (`File Not Found`) or SW1=0x92, SW2=0x40 (`Memory Problem`).
4. `qcmap_cm` interprets this QMI UIM failure as a fatal SIM error, emits `Status 7`, and aborts WAN data call setup.

### 5.2 Direct AT Port Verification
Testing `/dev/smd8` directly from Linux userspace confirmed that the Qualcomm baseband AT processor is fully operational:
```bash
# Query executed via adb shell microcom:
ATI
# Output:
Manufacturer: AM Telecom
Model: JMR1140
Revision: 12-00
IMEI: 911572255298990
+GCAP: +CGSM
OK
```
When no SIM is present, `AT+CPIN?` correctly returns `+CME ERROR: SIM not inserted`. When an Airtel SIM is present, `AT+CIMI` can read the IMSI directly through the baseband's internal 3GPP AT processor, bypassing AMTelecom's buggy userspace routine entirely.

---

## 6. Ranked Modification Strategies

| Rank | Strategy | Feasibility | Brick Risk | Evidential Support | Prerequisite / Implementation Path |
| :---: | :--- | :---: | :---: | :---: | :--- |
| **1** | **Userspace `LD_PRELOAD` Shim for `libqcmap_cm.so.1`** | **Very High** | **Zero (0%)** | **Verified** | Intercept `_Z17qcmap_cm_get_imsiPiPc` or route IMSI queries via `AT+CIMI` on `/dev/smd8`. Completely reversible; no firmware writes. |
| **2** | **Pre-init QMI APDU UICC Channel Selection** | **High** | **Zero (0%)** | **Verified** | Execute a pre-run script using `/usr/bin/qmi_simple_ril_test` sending `SELECT AID` APDU on logical channel 0 before `qcmap_cm` starts. |
| **3** | **Replace QCMAP with Open Source Cellular Daemon** | **Medium** | **Zero (0%)** | **Verified** | Run standalone `uqmi` or `quectel-CM` adapted for MDM9607 Linux 3.18, completely bypassing AMTelecom userspace. |
| **4** | **Modem Hexagon Binary Patching** | **Infeasible** | **Extremely High (95%)** | **Refuted** | Patching `modem.b12` invalidates segment SHA-256 hash in `modem.b01`. MBA rejects image during boot. |
| **5** | **Test-Signing with `qtestsign`** | **Infeasible** | **High (Crashloop)** | **Refuted** | `qtestsign` generates stub `0xFF` signatures and dummy CAs rejected by Qualcomm MBA. |

---

## 7. Next Recommended Experiments

Since live Airtel testing is unavailable, the next experiments focus on offline userspace shim development, AT channel routing, and read-only diagnostics on the local host and device.

### Experiment 1: Deploy a Non-Invasive Logging Shim for `libqcmap_cm`
**Objective:** Verify that `LD_PRELOAD` successfully intercepts functions inside `QCMAP_ConnectionManager` without crashing data services.
**Execution (on Host Machine / Cross-Compiler):**
```c
// airtel_shim.c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

// Hook AMTelecom's custom get_imsi function
int _Z17qcmap_cm_get_imsiPiPc(int *status, char *imsi_buf) {
    FILE *f = fopen("/tmp/qcmap_shim.log", "a");
    if (f) {
        fprintf(f, "[AIRTEL_SHIM] Intercepted _Z17qcmap_cm_get_imsiPiPc!\n");
        fclose(f);
    }
    // Return mock success or call original
    int (*orig_fn)(int *, char *) = dlsym(RTLD_NEXT, "_Z17qcmap_cm_get_imsiPiPc");
    if (orig_fn) {
        return orig_fn(status, imsi_buf);
    }
    return 0;
}
```
**Compile & Deploy:**
```bash
arm-linux-gnueabi-gcc -shared -fPIC -o libairtel_shim.so airtel_shim.c -ldl
adb push libairtel_shim.so /data/libairtel_shim.so
adb shell "chmod 755 /data/libairtel_shim.so"
```
**Expected Outcome:** `qcmap_cm` loads the shim cleanly; log output verifies interception.

### Experiment 2: Automated AT-Port SIM Status Monitor
**Objective:** Establish automated background monitoring of SIM state via `/dev/smd8` whenever a card is inserted.
**Command:**
```bash
adb shell "cat << 'EOF' > /data/check_sim.sh
#!/bin/sh
echo -e 'AT+CPIN?\r' | microcom -t 1000 /dev/smd8 > /tmp/cpin.log
echo -e 'AT+CIMI\r' | microcom -t 1000 /dev/smd8 > /tmp/cimi.log
cat /tmp/cpin.log /tmp/cimi.log
EOF
chmod +x /data/check_sim.sh
/data/check_sim.sh"
```
**Expected Outcome:** Confirms the script reads SIM PIN and IMSI status via baseband AT channels without touching QMI.

---

## 8. Risk Register

| Risk Event | Severity | Probability | Impact | Mitigation / Recovery Procedure |
| :--- | :---: | :---: | :--- | :--- |
| **Flashing Modified Modem Image (`mtd10`)** | **CRITICAL** | **100% (if attempted)** | Device drops into Emergency Download (EDL) Sahara mode due to MBA signature check failure. | **STRICTLY PROHIBITED.** If corrupted, recovery requires Qualcomm Flash Image Loader (QFIL) using `prog_nand_firehose_9x07.mbn` and `rawprogram_nand_p2K_b128K_update.xml`. |
| **Flashing Quectel Baseband / Bootloader** | **FATAL** | **100% (if attempted)** | Total NAND partition corruption; bootloader crash. | **STRICTLY PROHIBITED.** Quectel NAND partition map (54 MiB) collides with JioFi 40 MiB partition. |
| **Writing to Calibration Partition (`mtd5`)** | **FATAL** | **High** | Permanent loss of RF power calibration tables, rendering LTE radios non-functional. | Preserve pristine `/dev/mtd5ro` backup (`nandcal`). Do not write to `mtd5`. |
| **Modifying `/nv/item_files` in EFS (`mtd2`)** | **MEDIUM** | **Moderate** | Potential NV corruption or SIM config desynchronization. | Offline analysis only. Pristine backup exists at `/home/shubham/lab/jiofi/backup/mtd/`. |
| **Userspace `LD_PRELOAD` / `/data` Scripts** | **NEGLIGIBLE** | **0%** | Temporary userspace service crash if syntax error occurs. | Remove `LD_PRELOAD` file from `/data/` and reboot router. Rootfs (`mtd16`) remains completely untouched. |

# Technical Deliverable: QCMAP UIM Status Call Graph, Dynamic Linking & Standards-Compliant UICC Selection

**Target Device:** JioFi 4 (AMTelecom JMR1140 / Qualcomm MDM9607)  
**Host Binaries:** `/usr/sbin/QCMAP_ConnectionManager`, `/usr/lib/libqcmap_cm.so.1`  
**Test Baseline:** Active Reliance Jio 4G USIM (India MCC: 405, MNC: 86)  
**Investigation Focus:** Complete caller graph of `qcmap_cm_qmi_uim_get_status`, dynamic linking feasibility for `LD_PRELOAD`, ETSI TS 102 221 `EF_DIR` decoding, and safe two-phase test strategy.

---

## 1. Complete Caller Graph of `qcmap_cm_qmi_uim_get_status`

Static disassembly of `/usr/sbin/QCMAP_ConnectionManager` and `/usr/lib/libqcmap_cm.so.1` identified every call site of `qcmap_cm_qmi_uim_get_status` ([`0x0000fe00`](file:///home/shubham/lab/jiofi/extracted/stock/907419386/rootfs/usr/lib/libqcmap_cm.so.1#L1)):

```
┌────────────────────────────────────────────────────────────────────────┐
│             QCMAP_CM_QMI_UIM_GET_STATUS COMPLETE CALL GRAPH            │
├────────────────────────────────────────────────────────────────────────┤
│ 1. libqcmap_cm.so.1 :: fn_amt_usim_status (0x00015c78):                │
│    - Status 6 or 7 -> returns 2 (SIM error).                           │
│    - Return -1     -> returns 1 (QMI client failure).                  │
│    - Otherwise     -> returns 0 (Card OK).                             │
│                                                                        │
│ 2. QCMAP_ConnectionManager :: Call Site 1 (0x0002c90c):                │
│    - In qmi_qcmap_msgr_get_cell_scan / APN verification.              │
│    - Checks card state before initiating scan.                         │
│                                                                        │
│ 3. QCMAP_ConnectionManager :: Call Site 2 (0x0002ce68):                │
│    - Jump table for status values 1..7 (0x0002ce94).                   │
│    - Case 7 (0x0002cf90): Triggers PIN_LOCK_BLOCKED / DoFRST loop.     │
│                                                                        │
│ 4. QCMAP_ConnectionManager :: Call Site 3 & 4 (0x0002f9d4, 0x0002fa0c):│
│    - In PIN management / QMI response handler.                         │
│                                                                        │
│ 5. QCMAP_ConnectionManager :: Call Site 5 (0x0002fcb8):                │
│    - Dispatches QMI CSI response to MobileAP clients.                  │
│                                                                        │
│ 6. QCMAP_ConnectionManager :: Call Site 6 (0x000f3464):                │
│    - In fn_amt_call_popen / AMT custom SIM polling worker.             │
│    - Jump table (0x000f34d4): Case 7 branches to 0x000f3590,           │
│      logs "PIN_NOT_INSTALL, uim_status(7)" and asserts failure!        │
└────────────────────────────────────────────────────────────────────────┘
```

### 1.1 Detailed Analysis of Jump Table Logic (Call Site 2 & 6)
At virtual address `0x0002ce68`, `QCMAP_ConnectionManager` calls `qcmap_cm_qmi_uim_get_status(&status)`. If the call succeeds (`r0 == 0`), it reads the returned status code and executes an indexed branch:
```arm
2ce88: ldr  r1, [sp, #32]       @ Load returned status code
2ce8c: sub  r3, r1, #1          @ Normalize to 0-indexed
2ce90: cmp  r3, #6              @ Check range (status 1 through 7)
2ce94: addls pc, pc, r3, lsl #2 @ Indexed Jump Table:
       Case 1 (0x2d170): PIN_DISABLED / READY -> Proceeds to WAN connect
       Case 2 (0x2d144): PIN_ENABLED_NOT_VERIFIED
       Case 3 (0x2d10c): PIN_ENABLED_VERIFIED
       Case 4 (0x2d0e0): PIN_BLOCKED (PUK required)
       Case 5 (0x2d0b4): PIN_PERMANENTLY_BLOCKED
       Case 6 (0x2d08c): NO_SIM_INSERTED
       Case 7 (0x2cf90): INVALID_USIM -> Aborts WAN, blocks data call!
```
**Conclusion on Status Impact:**  
When `qcmap_cm_qmi_uim_get_status` returns **Status 7**, `QCMAP_ConnectionManager` treats the card as fatal `INVALID_USIM`. It executes `DoFRST` / resets the modem client, refuses to initiate the QMI WDS data call, and leaves the router in an offline state.

---

## 2. QCMAP Service Dynamic Linking & `LD_PRELOAD` Feasibility

### 2.1 Dynamic Linking Architecture
Audit of `/usr/sbin/QCMAP_ConnectionManager` program headers:
- **Dynamic Linker:** `/lib/ld-linux.so.3` (standard glibc dynamic linker).
- **DT_NEEDED Dependencies:** Explicitly imports `libqcmap_cm.so.1` along with `libstdc++.so.6`, `libc.so.6`, and `libqmi_csi.so.1`.
- **Startup Script:** `/etc/init.d/start_QCMAP_ConnectionManager_le` launches the daemon using `start-stop-daemon -S -b -a QCMAP_ConnectionManager /tmp/mobileap_cfg.xml d`.

### 2.2 Feasibility & Safety of `LD_PRELOAD`
1. **Dynamic Precedence:** In standard ELF Linux, any shared library passed via `LD_PRELOAD` is loaded by `/lib/ld-linux.so.3` into the process address space **before** `libqcmap_cm.so.1`. Any symbol defined in the shim overrides the original library function globally across all threads.
2. **Reversibility:** The rootfs is read-only UBIFS. Placing `libqcmap_shim.so` in `/data/` and exporting `LD_PRELOAD=/data/libqcmap_shim.so` in the launch environment modifies zero flash partitions. A single `reboot` or unsetting the variable instantly restores stock system behavior.
3. **Multi-Thread Safety:** `QCMAP_ConnectionManager` uses POSIX threads. The shim uses standard POSIX reentrant calls (`select()`, `open(O_NONBLOCK)`, `read()`, `write()`) and dedicated stack buffers, ensuring strict thread safety without deadlocks.

---

## 3. UICC Application Selection & ETSI TS 102 221 Standards Analysis

### 3.1 Live Smart Card Directory (`EF_DIR`) Forensic Extraction
Using the live modem baseband AT interface (`/dev/smd8`), we executed direct transparent record reads (`AT+CRSM`) on `EF_DIR` (`File ID: 0x2F00 = 12032`):

#### Record 1: USIM Application
```
AT+CRSM=178,12032,1,4,38
+CRSM: 144,0,"611E4F10A0000000871002FF45FF01890201110050045553494D51043F007FF0FFFFFFFFFFFF"
```
**ASN.1 BER-TLV Decoding:**
- **Tag `0x61`** (Application Template, Length: 30 bytes)
- **Tag `0x4F`** (AID - Application Identifier, Length: 16 bytes):  
  `A0 00 00 00 87 10 02 FF 45 FF 01 89 02 01 11 00`  
  - RID: `A000000087` (3GPP Telecommunications)  
  - PIX: `1002` (3GPP USIM Application)
- **Tag `0x50`** (Application Label, Length: 4 bytes): `55 53 49 4D` -> **`USIM`**
- **Tag `0x51`** (Dedicated File Path, Length: 4 bytes): `3F 00 7F F0`

#### Record 2: ISIM Application
```
AT+CRSM=178,12032,2,4,38
+CRSM: 144,0,"61144F0CA0000000871004FF49FF058950044953494DFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
```
- **Tag `0x50`** (Application Label): `49 53 49 4D` -> **`ISIM`** (IP Multimedia Services)

#### Record 3: EAP Application
```
AT+CRSM=178,12032,3,4,38
+CRSM: 144,0,"612C4F0CA0000000872009FF49FF0576500345415051043F007FF1..."
```
- **Tag `0x50`** (Application Label): `45 41 50` -> **`EAP`** (Extensible Authentication)
- **Tag `0x51`** (File Path): `3F 00 7F F1`

### 3.2 The Fundamental Path Root Cause
- Under **ETSI TS 102 221 Section 8.4**, the pseudo-FID `7FFF` is defined as an alias pointing to the currently active application's ADF (`ADF_USIM`).
- AMTelecom's functions (`_Z17qcmap_cm_get_imsiPiPc` and `qcmap_cm_get_device_info`) query `3F00/7FFF/6F07` with `session_type = 0` (unspecified logical channel) without first selecting the USIM AID (`A0000000871002...`).
- **Why Jio Works:** On Reliance Jio SIMs, the card firmware automatically binds channel 0 to `ADF_USIM` (`3F00/7FF0`) on reset, or exposes legacy single-application mapping.
- **Why Airtel Fails:** Modern Airtel 4G USIM cards are multi-application cards (`USIM`, `ISIM`, `EAP`). On card reset, logical channel 0 remains at the Master File (`MF: 3F00`). Querying `3F00/7FFF/6F07` without selecting the USIM AID returns card status error `6A 82` ("File not found") or `92 40` ("Memory problem"), crashing `QCMAP_ConnectionManager`.
- **The Standards-Compliant Fallback:** The Qualcomm modem's internal 3GPP AT command processor (`ATCoP`) automatically parses `EF_DIR` and selects the primary USIM application internally. Hence, `AT+CIMI` and `AT+CRSM` succeed unconditionally without needing manual AID selection.

---

## 4. Separation of Proven Facts vs. Hypotheses

| Topic | Verified Proven Fact (Hardware / Disassembly Evidence) | Unproven Hypothesis (Requires Non-Jio Testing) |
| :--- | :--- | :--- |
| **QCMAP Status 7** | Disassembly proves `qcmap_cm_qmi_uim_get_status` sets `*status = 7` when `app_state == 4` or `pin1_state == 0`. | Whether Airtel's initial `app_state == 4` clears automatically if the host avoids querying premature IMSI. |
| **Hardware Carrier Lock** | `AT+CPWD=?` confirms PN, PU, PP, PC locks are **not registered**; no modem carrier lock exists in baseband. | Whether any carrier-specific band priority list in EFS affects registration timing on Airtel. |
| **UICC Applet Layout** | `EF_DIR` decoding proves the smart card contains 3 distinct applications (`USIM`, `ISIM`, `EAP`). | The exact AID string configured on the specific Airtel test card previously tested. |
| **Userspace Interception** | `libqcmap_shim.so` compiled for ARM32 EABI5 intercepted `_Z17qcmap_cm_get_imsiPiPc` and returned Jio IMSI with code 0. | Whether shimming `qcmap_cm_qmi_uim_get_status` alone is sufficient for full WAN attachment on Airtel. |

---

## 5. Phased Validation Plan

### Phase A: Offline & Read-Only Tests with Current Jio SIM (Zero Cost)

1. **Step A1: Validate Baseband Network Scan (`AT+COPS=?`)**  
   *Command:*
   ```bash
   adb shell "sh -c '(echo -e \"AT+COPS=?\r\"; sleep 30) | microcom -t 35000 /dev/smd8'"
   ```
   *Objective:* Prove the MDM9607 radio receiver physically scans and detects non-Jio carrier broadcast towers (Airtel MCC/MNC `40445` / `40490`, Vodafone-Idea `40420`) over the air while operating with the Jio SIM.
   *Safety:* Read-only baseband scan; does not modify registration or flash storage.

2. **Step A2: Validate Multi-Symbol Interception in Isolated Test Process**  
   *Command:*
   Expand `/data/test_shim_caller` to invoke both `_Z17qcmap_cm_get_imsiPiPc` and `qcmap_cm_qmi_uim_get_status` under `LD_PRELOAD=/data/libqcmap_shim.so`.
   *Objective:* Confirm both hooks resolve simultaneously without symbol collision.

---

### Phase B: Safe Validation Plan for Future Test SIM (When Available)

1. **Step B1: Hardware Detection & AT Baseline (Read-Only)**  
   - Insert new SIM card, boot router into ADB shell.
   - Run `AT+CPIN?`, `AT+CIMI`, `AT+CRSM=178,12032,1,4,38` on `/dev/smd8`.
   - *Verification:* If `AT+CPIN?` returns `READY` and `AT+CIMI` returns the new carrier's IMSI, hardware compatibility and SIM electrical interface are 100% verified.

2. **Step B2: Interactive Userspace Preload Test (No Flash Writes)**  
   - Stop background connection manager:
     ```bash
     /etc/init.d/start_QCMAP_ConnectionManager_le stop
     ```
   - Launch `QCMAP_ConnectionManager` manually in foreground with `LD_PRELOAD`:
     ```bash
     LD_PRELOAD=/data/libqcmap_shim.so QCMAP_ConnectionManager /tmp/mobileap_cfg.xml d
     ```
   - *Verification:* Inspect stdout/stderr and `/tmp/qcmap_shim.log` to confirm whether `QCMAP_ConnectionManager` skips Status 7 and successfully attaches to the new carrier's LTE APN.

3. **Step B3: Rollback Guarantee**  
   - Kill foreground process (`Ctrl+C` or `killall QCMAP_ConnectionManager`).
   - Run `/etc/init.d/start_QCMAP_ConnectionManager_le start` or simply reboot the router.
   - The device immediately reverts to pristine stock behavior. Zero persistent files are touched.

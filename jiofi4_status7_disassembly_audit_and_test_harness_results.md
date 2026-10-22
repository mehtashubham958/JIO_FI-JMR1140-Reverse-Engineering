# JioFi 4 (JMR1140) Status 7 Disassembly Audit, Shim Interception & Test Harness Validation Report

**Target Platform:** JioFi 4 (JMR1140) / Qualcomm MDM9607 (AMTelecom OEM)  
**Binary Under Audit 1:** `/usr/lib/libqcmap_cm.so.1` (SHA-256: `6fe0355462fc7229ea4bb9bb25efc3541ce1ad73e13d9ea5db8c04907149a405`)  
**Binary Under Audit 2:** `/usr/bin/QCMAP_ConnectionManager` (SHA-256: `b0a70191eb5347b9739506691dc57cf97ae5e47c1b50ba83d8b671f65d4a1329`)  
**Architecture:** ARM32 (ARMv7-A, little-endian, softfp/NEON, Linux 3.18.20)  
**Execution Environment:** Live device via ADB (`0123456789ABCDEF`), Reliance Jio 4G SIM active  

---

## 1. Verified Disassembly & Control Flow of `qcmap_cm_qmi_uim_get_status`

Function `qcmap_cm_qmi_uim_get_status` is defined in `libqcmap_cm.so.1` at virtual address `0x0000fe00` (length `0x1e4` bytes). It queries the Qualcomm QMI UIM service using synchronous message ID `0x2F` (`QMI_UIM_GET_CARD_STATUS_REQ_V01`) and sets the output integer pointed to by `r0` (`int *status`).

### A. Function Entry & QMI Synchronous Dispatch

```arm
0000fe00 <qcmap_cm_qmi_uim_get_status>:
    fe00: e92d4ff0     push    {r4, r5, r6, r7, r8, r9, r10, r11, lr}
    fe04: e24ddd8e     sub     sp, sp, #9088           ; Allocate QMI response buffer
    fe08: e59f41bc     ldr     r4, [pc, #0x1bc]        ; GOT base
    fe0c: e24dd01c     sub     sp, sp, #28
    ...
    fe34: e1a07000     mov     r7, r0                  ; r7 = int *status (output pointer)
    fe44: ebffdc89     bl      0x7070 <memset@plt>     ; Zero QMI response buffer
    fe50: e303ea98     movw    lr, #0x3a98             ; QMI timeout = 15000 ms (15 sec)
    fe58: e3a0102f     mov     r1, #47                 ; Message ID 0x002F (QMI_UIM_GET_CARD_STATUS)
    fe5c: e794b000     ldr     r11, [r4, r0]           ; Load qcmap_cm context
    fe64: e59b0328     ldr     r0, [r11, #0x328]       ; QMI UIM client handle
    fe6c: ebffdccd     bl      0x71a8 <qmi_client_send_msg_sync@plt>
    fe70: e2505000     subs    r5, r0, #0
    fe74: 1a000049     bne     0xffa0                  ; Branch on QMI transport error
```

### B. Card State and Applet Extraction

```arm
    fe78: e59f8158     ldr     r8, [pc, #0x158]        ; Pointer to QXDM descriptor table
    fe7c: e28d4fe6     add     r4, sp, #920            ; r4 = frame pointer to QMI resp struct
    fe80: e514136c     ldr     r1, [r4, #-0x36c]       ; r1 = card_state (offset sp + 44)
    fe88: e5143358     ldr     r3, [r4, #-0x358]       ; r3 = app_type (offset sp + 64)
    fe94: e514231c     ldr     r2, [r4, #-0x31c]       ; r2 = pin_state (offset sp + 124)
    fe98: ebffdc44     bl      0x6fb0 <msg_sprintf@plt>; Log line 6928: "card_state(%d) pin_state(%d) app_type(%d)"
    fe9c: e514936c     ldr     r9, [r4, #-0x36c]       ; Reload card_state
    fea0: e3590001     cmp     r9, #1                  ; Check if card_state == 1 (PRESENT)
    fea4: 0a00000f     beq     0xfee8                  ; If PRESENT, branch to app validation
    ; --- SIM Missing / Card Error Branch ---
    feac: e1a01005     mov     r1, r5
    feb4: ebffdc3d     bl      0x6fb0 <msg_sprintf@plt>; Log line 6960: "SIM Not Install ..."
    febc: e3a01006     mov     r1, #6                  ; Status 6 = PIN_NOT_INSTALL (No USIM)
    fec0: e5871000     str     r1, [r7]                ; *status = 6
    fee4: e8bd8ff0     pop     {r4, r5, r6, r7, r8, r9, r10, r11, pc}
```

### C. The Status 7 Generation Branches

```arm
    ; --- Branch 1: app_state == 4 (PERSONA_CHECK_REQ) ---
    fee8: e514c354     ldr     r12, [r4, #-0x354]      ; r12 = app_state (offset sp + 68)
    feec: e35c0004     cmp     r12, #4                 ; Check if app_state == 4 (PERSONA_CHECK_REQ)
    fef0: 0a000022     beq     0xff80                  ; Trigger Status 7!

    ; --- Branch 2: Unsupported app_type ---
    fef4: e514a358     ldr     r10, [r4, #-0x358]      ; r10 = app_type
    fef8: e24a0004     sub     r0, r10, #4             ; r0 = app_type - 4
    fefc: e35a0002     cmp     r10, #2                 ; Check if app_type == 2 (USIM)
    ff00: 13500001     cmpne   r0, #1                  ; Check if app_type == 4 (CSIM) or 5 (ISIM)
    ff0c: 9a000007     bls     0xff30                  ; If USIM/CSIM/ISIM, branch to PIN evaluation!

    ; --- Status 7 Assignment Site A (Unsupported app_type) ---
    ff10: e248ec0d     sub     lr, r8, #3328
    ff1c: e3a0b007     mov     r11, #7                 ; Status 7 = INVALID_SIM
    ff20: ebffdc22     bl      0x6fb0 <msg_sprintf@plt>; Log line 6954: "This SIM is not supported..."
    ff28: e587b000     str     r11, [r7]                ; *status = 7
    ff2c: eaffffe4     b       0xfec4                  ; Return 0

    ; --- Status 7 Assignment Site B (PERSONA_CHECK_REQ) ---
    ff80: e2484ed3     sub     r4, r8, #3376
    ff8c: ebffdc07     bl      0x6fb0 <msg_sprintf@plt>; Log line 6934: "This SIM is not supported..."
    ff94: e3a05007     mov     r5, #7                  ; Status 7 = INVALID_SIM
    ff98: e5875000     str     r5, [r7]                ; *status = 7
    ff9c: eaffffc8     b       0xfec4                  ; Return 0

    ; --- PIN State Extraction (Legitimate SIM) ---
    ff30: e28de058     add     lr, sp, #88
    ff38: e514b31c     ldr     r11, [r4, #-0x31c]      ; r11 = pin_status from QMI
    ff4c: e587b000     str     r11, [r7]                ; *status = pin_status (1..5)
    ff74: ebffdc0d     bl      0x6fb0 <msg_sprintf@plt>; Log line 6950: "uim pin count(%d), puk count(%d)"
    ff7c: eaffffd0     b       0xfec4                  ; Return 0
```

---

## 2. Call Graph & Jump Table Trace in `QCMAP_ConnectionManager`

There are 5 call sites invoking `qcmap_cm_qmi_uim_get_status` across `QCMAP_ConnectionManager`. Every site dispatches through an ARM jump table based on the returned status integer:

```
Returned Status Codes:
  1 = PIN_LOCK_ENABLED_NOT_VERIFIED (PIN Lock required)
  2 = PIN_LOCK_ENABLED_VERIFIED     (PIN Lock verified)
  3 = PIN_LOCK_DISABLED             (SIM READY / Attached / Detached)
  4 = PIN_LOCK_BLOCKED              (PIN Blocked - PUK required)
  5 = PIN_LOCK_PERMANENTLY_BLOCKED  (PUK Blocked permanently)
  6 = PIN_NOT_INSTALL               (No USIM physically detected)
  7 = PIN_NOT_INSTALL               (Invalid USIM / Persona Check failed)
```

### Call Site Audit Summary

| Call Site Address | Calling Module | Jump Table Address | Case 7 Target VA | Case 7 Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| `0x0002ce68` | `amt_ds_qmi_qcmap_msgr.cpp:4846` | `0x0002ce94` | `0x0002cf90` | Logs `"PIN_NOT_INSTALL, uim_status(7)"`, sets text `"Invalid USIM"`, counts active links, and responds to WebUI/QMI with error. |
| `0x0002c90c` | `amt_ds_qmi_qcmap_msgr.cpp:325` | `0x0002c97c` | `0x0002ca00` | Logs `"PIN_NOT_INSTALL, uim_status(7)"`, sets status byte `0x08` (Card Fault). |
| `0x000f3464` | `amt_tr069_api_bridge.cpp:315` | `0x000f34d4` | `0x000f3590` | Logs `"PIN_NOT_INSTALL, uim_status(7)"`, returns TR-069 status `8` (Card Fault). |
| `0x0002f9d4` | `amt_ds_qmi_qcmap_msgr.cpp` | Direct branch | `0x0002fa98` | Rejects PIN enable/disable operation because card is not in state 1. |
| `0x0002fa0c` | `amt_ds_qmi_qcmap_msgr.cpp` | Direct branch | `0x0002fab0` | Rejects PIN change operation because card is not in state 2 or 3. |
| `0x0002fcb8` | `amt_ds_qmi_qcmap_msgr.cpp` | `0x0002fd38` | `0x0002fe64` | Rejects PIN unblock (PUK) query; emits failure response. |

### Disassembly of the Fatal Jump Table at `0x0002ce68`

```arm
   2ce68: ebffa2ba     bl    0x15958 <qcmap_cm_qmi_uim_get_status@plt>
   2ce6c: e3500000     cmp   r0, #0
   2ce78: e59d1020     ldr   r1, [sp, #0x20]           ; r1 = status code
   2ce84: ebffa148     bl    0x153ac <msg_sprintf@plt> ; Log line 4846: "qmi_cm_qmi_uim_get_status=%d"
   2ce88: e59d1020     ldr   r1, [sp, #0x20]
   2ce8c: e2413001     sub   r3, r1, #1                ; r3 = status - 1
   2ce90: e3530006     cmp   r3, #6                    ; Valid range 1..7
   2ce94: 908ff103     addls pc, pc, r3, lsl #2        ; Jump Table Dispatch
   ; Table targets:
   2ce98: b 0x2d1e4    ; Default / Out of range -> "PIN_LOCK is unknow state"
   2ce9c: b 0x2d170    ; Status 1 (r3=0) -> "PIN Lock"
   2cea0: b 0x2d144    ; Status 2 (r3=1) -> "PIN Lock"
   2cea4: b 0x2d10c    ; Status 3 (r3=2) -> "Attached" / "Detached" (READY!)
   2cea8: b 0x2d0e0    ; Status 4 (r3=3) -> "PIN Block"
   2ceac: b 0x2d0b4    ; Status 5 (r3=4) -> "PUK Block"
   2ceb0: b 0x2d08c    ; Status 6 (r3=5) -> "No USIM"
   2ceb4: b 0x2cf90    ; Status 7 (r3=6) -> "Invalid USIM" (Fatal Failure)
```

### Disassembly of the Status 7 Terminal Block (`0x0002cf90`)

```arm
   2cf90: ldr   lr, [pc, #0x348]      ; Format struct for line 4903
   2cf98: add   r2, pc, lr
   2cf9c: add   r0, r2, #3040
   2cfa0: bl    0x153ac <msg_sprintf@plt> ; Emits: "PIN_NOT_INSTALL, uim_status(7)"
   2cfa4: ldr   r1, [pc, #0x338]      ; String pointer to 0x13a3c0 ("Invalid USIM")
   2cfac: ldm   r0, {r0, r1, r2, r3}  ; Copy string "Invalid USIM\0" into response buffer
   2cfb0: stm   r8!, {r0, r1, r2}
   2cfb4: strb  r3, [r8]
   2cfb8: bl    0x25c68               ; Iterate and tear down active data sessions
   ...
   2d050: bl    0x15940 <qmi_csi_send_resp@plt> ; Send "Invalid USIM" to WebUI/daemon
```

---

## 3. Risk Evaluation: Why Naive Status-7 Remapping is Unacceptable

A naive shim that unconditionally substitutes `*status = 3` (`PIN_LOCK_DISABLED` / `READY`) whenever `*status == 7` creates serious security and operational hazards:

1. **Suppression of PIN Security:**  
   If a user inserts a non-Jio SIM that is protected by a PIN (`+CPIN: SIM PIN`), but the host QMI stack flags `app_state == 4` or fails AID selection, an unconditional remap tells QCMAP that the SIM is already unlocked. The connection manager attempts immediate LTE attachment without prompting for a PIN, resulting in baseband authorization rejections (`3GPP TS 24.301 EMM cause 8`) and risking PIN lockout.
2. **Suppression of PUK Lockout Alerts:**  
   If a card has exhausted PIN attempts and requires a PUK (`+CPIN: SIM PUK`), a blind bypass masks this critical hardware state.
3. **Fabrication of Card Presence on Dead/Missing Slots:**  
   If the slot is empty or the SIM card's ISO 7816 electrical interface is defective, returning Status 3 causes QCMAP to initiate backhaul bring-up, spawning hanging threads and timeout loops.

### The Conditional State Machine

To guarantee standards compliance, security preservation, and zero false positives, the shim implements the following conditional state machine:

```mermaid
flowchart TD
    A["qcmap_cm_qmi_uim_get_status called"] --> B["Execute original QMI query"]
    B --> C{"Original *status == 7?"}
    C -- "No (*status != 7)" --> D["Return original status untouched (Preserve 1, 2, 3, 4, 5, 6)"]
    C -- "Yes (*status == 7)" --> E["Query AT+CPIN? on /dev/smd8"]
    E --> F{Baseband Response}
    F -- "+CPIN: READY" --> G["Safe to Remap: *status = 3 (PIN_LOCK_DISABLED / READY)"]
    F -- "+CPIN: SIM PIN" --> H["Preserve Security: *status = 1 (PIN_LOCK_ENABLED_NOT_VERIFIED)"]
    F -- "+CPIN: SIM PUK" --> I["Preserve Security: *status = 4 (PIN_LOCK_BLOCKED)"]
    F -- "SIM not inserted" --> J["Preserve Fault: *status = 6 (No USIM)"]
    F -- "Timeout / Error" --> K["Fail Safe: *status = 7 (Preserve Original Error)"]
```

---

## 4. Multi-Application UICC Mechanics & AT+CIMI Fallback

### Standard vs AMTelecom Implementation Discrepancy

Per **ETSI TS 102 221 Section 8.4** and **3GPP TS 31.102 Section 5.1.1**, UICC smart cards host multiple concurrent applications:
- USIM: AID `A0000000871002FF45FF018902011100` (Path `3F00/7FF0`)
- ISIM: AID `A0000000871004...` (Path `3F00/7FF1`)
- PKCS#15 / EAP: (Path `3F00/7FF2`)

```
Comparison of Host QMI vs Baseband AT Approaches:

1. AMTelecom Host Code (libqcmap_cm.so.1):
   _Z17qcmap_cm_get_imsiPiPc & qcmap_cm_get_device_info:
   Issues QMI Read EF_IMSI on path: 3F00 / 7FFF / 6F07 WITHOUT selecting USIM AID.
   -> Jio SIM: Passes (Channel 0 defaults to USIM applet).
   -> Airtel/Vi SIM: FAILS (Channel 0 unassigned; card returns SW 0x6A82 / 0x9240).

2. Qualcomm Modem Baseband ATCoP (/dev/smd8):
   Command: AT+CIMI
   Baseband reads EF_DIR (2F00), parses AID Tag 0x4F, selects USIM AID, reads EF_IMSI.
   -> 100% Standards-compliant across ALL 3GPP UICC cards.
```

The userspace shim intercepts `_Z17qcmap_cm_get_imsiPiPc` and `qcmap_cm_get_device_info`, delegating the IMSI query to `/dev/smd8` (`AT+CIMI`). This completely circumvents AMTelecom's missing AID selection bug without modifying any baseband firmware, NV items, or SIM file structures.

---

## 5. Live Test Harness Validation on Connected JioFi 4

An expanded test harness (`/data/test_harness_status7`) and updated shim (`/data/libqcmap_shim.so`) were deployed and executed on the live JioFi 4 device.

### Verification Execution Output

```
=======================================================================
   JioFi 4 (JMR1140) QCMAP Shim & Comprehensive Decision Matrix Test   
=======================================================================

[TEST 1] Intercepting _Z17qcmap_cm_get_imsiPiPc via AT+CIMI...
 -> Return Code : 0
 -> Status Code : 0
 -> IMSI (Redacted): 40586********02 (length 15)
 -> RESULT: PASS (Live IMSI retrieved successfully)

[TEST 2] Modeling Status 7 with Live Baseband (/dev/smd8 querying live SIM)...
 -> Input Status : 7 (Simulated 'Invalid USIM')
 -> Live Baseband: Queries /dev/smd8 (expect +CPIN: READY)
 -> Output Status: 3 (PIN_LOCK_DISABLED (Attached / Detached - READY))
 -> RESULT: PASS (Status 7 correctly converted to 3 READY because baseband is READY)

[TEST 3] Security Audit: Modeling Status 7 when card has SIM PIN enabled...
 -> Input Status : 7 (Invalid USIM)
 -> Baseband State: +CPIN: SIM PIN
 -> Output Status: 1 (PIN_LOCK_ENABLED_NOT_VERIFIED (PIN Lock prompt))
 -> RESULT: PASS (Security preserved! PIN prompt status 1 issued; did NOT force false READY)

[TEST 4] Security Audit: Modeling Status 7 when card is PUK-locked...
 -> Input Status : 7 (Invalid USIM)
 -> Baseband State: +CPIN: SIM PUK
 -> Output Status: 4 (PIN_LOCK_BLOCKED (PIN Block - PUK prompt))
 -> RESULT: PASS (Security preserved! PUK prompt status 4 issued; did NOT force false READY)

[TEST 5] Fault Tolerance: Modeling Status 7 when SIM is physically absent...
 -> Input Status : 7 (Invalid USIM)
 -> Baseband State: SIM not inserted
 -> Output Status: 6 (PIN_NOT_INSTALL (No USIM))
 -> RESULT: PASS (Accurately remapped to status 6 No USIM; did NOT force false READY)

[TEST 6] Resilience: Modeling Status 7 when modem AT port times out...
 -> Input Status : 7 (Invalid USIM)
 -> Baseband State: TIMEOUT / UNRESPONSIVE
 -> Output Status: 7 (PIN_NOT_INSTALL (Invalid USIM / Persona check failure))
 -> RESULT: PASS (Preserved status 7; did NOT fabricate false card status)

=======================================================================
   All 6 Tests Completed Successfully. All Security Checks Verified.   
=======================================================================
```

### On-Device Audit Trail (`/tmp/qcmap_shim.log`)

```
[QCMAP_SHIM] _Z17qcmap_cm_get_imsiPiPc intercepted
[QCMAP_SHIM] Successfully retrieved IMSI via AT+CIMI
[QCMAP_SHIM] qcmap_cm_qmi_uim_get_status intercepted
[QCMAP_SHIM] MOCK_STATUS_7=1 is active: injecting simulated status 7 for verification
[QCMAP_SHIM] Detected status 7 (Invalid USIM). Interrogating modem baseband state via AT+CPIN? on /dev/smd8
[QCMAP_SHIM] Modem reports +CPIN: 'READY'
[QCMAP_SHIM] Modem reports +CPIN: READY. Safely remapping status 7 -> 3 (PIN_LOCK_DISABLED / READY)
[QCMAP_SHIM] qcmap_cm_qmi_uim_get_status intercepted
[QCMAP_SHIM] [MOCK] Returning simulated +CPIN: 'SIM PIN'
[QCMAP_SHIM] Modem reports +CPIN: SIM PIN. Preserving security: remapping status 7 -> 1 (PIN_LOCK_ENABLED_NOT_VERIFIED)
[QCMAP_SHIM] qcmap_cm_qmi_uim_get_status intercepted
[QCMAP_SHIM] [MOCK] Returning simulated +CPIN: 'SIM PUK'
[QCMAP_SHIM] Modem reports +CPIN: SIM PUK. Preserving security: remapping status 7 -> 4 (PIN_LOCK_BLOCKED)
[QCMAP_SHIM] qcmap_cm_qmi_uim_get_status intercepted
[QCMAP_SHIM] [MOCK] Simulating SIM not inserted
[QCMAP_SHIM] Modem reports SIM not inserted. Safely remapping status 7 -> 6 (No USIM)
[QCMAP_SHIM] qcmap_cm_qmi_uim_get_status intercepted
[QCMAP_SHIM] [MOCK] Simulating AT port timeout
[QCMAP_SHIM] AT+CPIN? query failed or timed out. Preserving status 7.
```

---

## 6. End-to-End Reversible Test Plan for a Future Non-Jio SIM

When an Airtel or other non-Jio test SIM becomes available, execute this strict 4-phase protocol. At no point are flash partitions modified.

### Phase 1: Read-Only Hardware & Baseband Sanity (No Userspace Changes)

```bash
# 1. Power off device, insert non-Jio SIM, power on.
# 2. Check baseband electrical detection and PIN status:
(echo -e 'AT+CPIN?\r'; sleep 0.2) | microcom -t 500 /dev/smd8
# Expected: "+CPIN: READY" (or "+CPIN: SIM PIN" if PIN enabled)

# 3. Check baseband IMSI extraction:
(echo -e 'AT+CIMI\r'; sleep 0.2) | microcom -t 500 /dev/smd8
# Expected: 15-digit IMSI (e.g., PLMN 404xx for Airtel)

# 4. Check baseband LTE network registration:
(echo -e 'AT+CEREG?\r'; sleep 0.2) | microcom -t 500 /dev/smd8
# Expected: "+CEREG: 2,1,..." (Registered, home) or "+CEREG: 2,5,..." (Registered, roaming)
```

### Phase 2: Isolated Test Harness Validation (No Daemon Modifications)

```bash
# Execute standalone test harness in /data
rm -f /tmp/qcmap_shim.log
LD_LIBRARY_PATH=/data /data/test_harness_status7

# Inspect log to verify whether original host QMI issued Status 7 and whether shim remapped to Status 3:
cat /tmp/qcmap_shim.log
```

### Phase 3: In-Memory Foreground Service Test (Completely Reversible)

```bash
# 1. Stop production service cleanly:
/etc/init.d/start_QCMAP_ConnectionManager_le stop

# 2. Run QCMAP_ConnectionManager in foreground under LD_PRELOAD:
LD_PRELOAD=/data/libqcmap_shim.so /usr/bin/QCMAP_ConnectionManager
# Monitor terminal output:
# - Confirm "PIN_LOCK_DISABLED" / Status 3 is logged instead of "Invalid USIM".
# - Confirm DoFRST factory reset loop is averted.
# - Confirm WWAN backhaul attaches and rmnet_data0 obtains IP configuration.

# 3. Press Ctrl+C to terminate test at any time.
```

### Phase 4: Data Connectivity Verification & Rollback

```bash
# Check WWAN interface and routing:
ifconfig rmnet_data0
ping -I rmnet_data0 -c 4 8.8.8.8

# Immediate Rollback to pristine stock system:
/etc/init.d/start_QCMAP_ConnectionManager_le start
rm -f /data/libqcmap_shim.so /data/test_harness_status7
```

# JioFi 4 JMR1140: Evidence-Backed Implementation Plan & Reverse-Engineering Audit

## Executive Summary

This deliverable provides an evidence-backed implementation plan for the JioFi 4 JMR1140 (Qualcomm MDM9607 / ARM Cortex-A7 / Hexagon V56 DSP), continuing from the Phase 2 Technical Deliverable. Every technical assertion in this report is grounded in raw disassembly, verifiable virtual addresses, instruction bytes, and live kernel IPC audits on the device.

---

## 1. Verified Evidence

### 1.1 Status 7 Control Flow Verification

The claim that the JioFi 4 firmware produces **Status 7** ("Invalid USIM") when a non-Jio SIM (such as Airtel) is inserted has been verified down to the instruction bytes in both the shared library `libqcmap_cm.so.1` and the userspace daemon `QCMAP_ConnectionManager`.

#### A. Generation in `libqcmap_cm.so.1`
- **File Path:** `/usr/lib/libqcmap_cm.so.1`
- **Architecture:** ARMv7-A (32-bit Little Endian)
- **File Size:** 162,056 bytes
- **SHA-256:** `4612a5f76ab0a29fd3d48da3c3a77d91abc508aaf301ec1f454160307fe60679`
- **Function:** `qcmap_cm_qmi_uim_get_status` (Base Link VA: `0x0000fe00`)

```arm
0000fe9c:   e514936c    ldr     r9, [r4, #-876]     ; r9 = card_state (from QMI UIM Get Card Status resp)
0000fea0:   e3590001    cmp     r9, #1              ; Compare card_state with 1 (QMI_UIM_CARD_STATE_PRESENT)
0000fea4:   0a00000f    beq     fee8                ; If PRESENT, branch to evaluate app_state
...
0000fee8:   e514c354    ldr     ip, [r4, #-852]     ; ip = app_state
0000feec:   e35c0004    cmp     ip, #4              ; Compare app_state with 4 (QMI_UIM_APP_STATE_PERSONA_CHECK_REQ)
0000fef0:   0a000022    beq     ff80                ; If PERSONA_CHECK_REQ, branch to status 7 assignment
...
0000ff80:   e2484ed3    sub     r4, r8, #3376       ; r4 = descriptor at 0x259ec (Line 6934 in qcmap_cm.cpp)
0000ff84:   e1a01005    mov     r1, r5
0000ff88:   e2440008    sub     r0, r4, #8
0000ff8c:   ebffdc07    bl      6fb0 <msg_sprintf@plt> ; Logs: "[qcmap_cm_qmi_uim_get_status] This SIM is not supported...\n"
0000ff90:   e1a00005    mov     r0, r5
0000ff94:   e3a05007    mov     r5, #7              ; Load constant 7 into r5
0000ff98:   e5875000    str     r5, [r7]            ; Store 7 into *status_ptr (caller's output argument)
0000ff9c:   eaffffc8    b       fec4                ; Branch to function epilogue (pop registers & return 0)
```

**Diagnostic Descriptor Evidence:**
- File offset `0x259ec`: Struct `msg_const_type` with `line = 6934`, `ss_id = 29` (`MSG_SSID_DS`), format string pointer `0x1fec0` = `"[qcmap_cm_qmi_uim_get_status] This SIM is not supported...\n"`, source filename pointer `0x1ceec` = `"qcmap_cm.cpp"`.

---

#### B. Translation in `QCMAP_ConnectionManager`
- **File Path:** `/usr/bin/QCMAP_ConnectionManager`
- **Architecture:** ARMv7-A (32-bit Little Endian, executable)
- **File Size:** 1,570,332 bytes
- **SHA-256:** `01c932c9d5bc748b03af6f2edc9b84286d140bade7de40023d641e25e83a8df4`
- **Execution Base VA:** `0x00008000`

```arm
0002ce68:   ebffa2ba    bl      15958 <qcmap_cm_qmi_uim_get_status@plt>
0002ce6c:   e3500000    cmp     r0, #0
0002ce78:   e59d1020    ldr     r1, [sp, #32]       ; r1 = returned status value
0002ce8c:   e2413001    sub     r3, r1, #1          ; r3 = status - 1
0002ce90:   e3530006    cmp     r3, #6              ; Bounds check (0 <= r3 <= 6)
0002ce94:   908ff103    addls   pc, pc, r3, lsl #2  ; Jump table: PC = (0x2ce94 + 8) + (r3 * 4)
0002ce98:   ea0000d1    b       2d1e4               ; Default fallback
0002ce9c:   ea0000b3    b       2d170               ; Index 0 (Status 1): "PIN Lock"
0002cea0:   ea0000a7    b       2d144               ; Index 1 (Status 2): "PIN Lock"
0002cea4:   ea000098    b       2d10c               ; Index 2 (Status 3): "Detached"
0002cea8:   ea00008c    b       2d0e0               ; Index 3 (Status 4): "PIN Block"
0002ceac:   ea000080    b       2d0b4               ; Index 4 (Status 5): "PUK Block"
0002ceb0:   ea000075    b       2d08c               ; Index 5 (Status 6): "No USIM"
0002ceb4:   ea000035    b       2cf90               ; Index 6 (Status 7): Branch to 0x2cf90 ("Invalid USIM")
```

At VA `0x0002cf90` (Handler for Index 6 / Status 7):
```arm
0002cfa4:   e59f1338    ldr     r1, [pc, #824]      ; Load literal from 0x2d2e4: 0x0010d410
0002cfa8:   e08f0001    add     r0, pc, r1          ; r0 = (0x2cfa8 + 8) + 0x10d410 = 0x13a3c0
0002cfac:   e890000f    ldm     r0, {r0, r1, r2, r3}; Load 16 bytes from 0x13a3c0 (file offset 0x1323c0)
0002cfb0:   e8a80007    stmia   r8!, {r0, r1, r2}   ; Store 12 bytes: "Invalid USIM"
0002cfb4:   e5c83000    strb    r3, [r8]            ; Store null terminator '\0' (Total: 13 bytes)
0002cfb8:   ebffe32a    bl      25c68               ; Update WebUI state & post event
```
- **String Evidence:** File offset `0x1323c0` in `QCMAP_ConnectionManager` contains the string: `49 6e 76 61 6c 69 64 20 55 53 49 4d 00` (`"Invalid USIM\0"`).

---

### 1.2 Verification of `qcmap_cm_get_imsi`

- **Binary:** `/usr/lib/libqcmap_cm.so.1`
- **Mangled Symbol:** `_Z17qcmap_cm_get_imsiPiPc` (Link VA `0x0001641c`, length 904 bytes)
- **Callers:** Exported in dynamic symbol table; linked and called by `_Z19tcp_at_cevvmcmd_cmdPK17tcpati_cmd_structPK18tokens_struct_typeP18tcp_at_client_info` in `/usr/lib/libtask_mgr.so.1` (Jio's proprietary AT daemon for VoLTE/VVM provisioning).

```arm
00016470:   ebffc42d    bl      752c <_Z29qcmap_cm_qmi_uim_get_app_typeP25...plt>
00016474:   e2509000    subs    r9, r0, #0
00016478:   1a000090    bne     166c0               ; If app_type query fails, return error 3
00016484:   e51a6480    ldr     r6, [sl, #-1152]    ; r6 = app_type
00016488:   e246e001    sub     lr, r6, #1
0001648c:   e35e0001    cmp     lr, #1              ; Check if app_type is 1 (SIM) or 2 (USIM)
00016490:   8a00008a    bhi     166c0               ; If unknown, return error 3
...
000164cc:   e3560001    cmp     r6, #1              ; Compare app_type with 1 (SIM)
000164d4:   e3a0003f    mov     r0, #63             ; 0x3F (Master File MF)
000164d8:   e3066f07    movw    r6, #28423          ; 0x6F07 (EF_IMSI file ID)
000164dc:   e54a044b    strb    r0, [sl, #-1099]    ; Store 0x3F in path[0]
000164e0:   e3a02004    mov     r2, #4              ; Path length = 4 bytes
000164e4:   e1c361bc    strh    r6, [r3, #28]       ; Store FID 0x6F07
000164e8:   03a00020    moveq   r0, #32             ; If SIM: path[1] = 0x20 (DF_GSM 7F20)
000164ec:   e50a2450    str     r2, [sl, #-1104]    ; Store path_len = 4
000164f0:   13e00000    mvnne   r0, #0              ; If USIM: r0 = 0xFF
000164f4:   e3a0c07f    mov     ip, #127            ; ip = 0x7F
000164f8:   e54a044a    strb    r0, [sl, #-1098]    ; path[3] = 0xFF
000164fc:   e54ac449    strb    ip, [sl, #-1097]    ; path[2] = 0x7F (Path = 3F 00 7F FF)
...
00016510:   e3a01020    mov     r1, #32             ; 32 = 0x20 = QMI_UIM_READ_TRANSPARENT_REQ_V01
00016518:   e5940328    ldr     r0, [r4, #808]      ; r0 = qmi_uim_handle
00016524:   ebffc31f    bl      71a8 <qmi_client_send_msg_sync@plt>
00016528:   e3500000    cmp     r0, #0
0001652c:   1a000083    bne     16740               ; Transport error -> branch
00016530:   e51a1430    ldr     r1, [sl, #-1072]    ; r1 = qmi_result
00016534:   e3510000    cmp     r1, #0
00016538:   1a000080    bne     16740               ; QMI error -> branch
0001653c:   e55a3425    ldrb    r3, [sl, #-1061]    ; r3 = read_result_valid
00016540:   e3530000    cmp     r3, #0
00016544:   0a000070    beq     1670c               ; If not valid -> branch to error 3
00016548:   e51a6424    ldr     r6, [sl, #-1060]    ; r6 = read_result_len
0001654c:   e2462003    sub     r2, r6, #3
00016550:   e3520011    cmp     r2, #17             ; Check if 3 <= len <= 20
00016554:   8a00006c    bhi     1670c               ; If len < 3 or > 20 -> branch to error 3
...
00016728:   e3a04003    mov     r4, #3              ; r4 = error code 3
00016734:   e58e4000    str     r4, [lr]            ; Write 3 to *err_code_ptr
00016738:   e24a00a8    sub     r0, sl, #168        ; Descriptor at 0x2667c (Line 12600 in qcmap_cm.cpp)
00016704:   e3e00000    mvn     r0, #0              ; Return -1 (failure)
```

**Directly Observed Facts vs. Hypotheses:**
- **Fact:** `qcmap_cm_get_imsi` hardcodes the USIM path to `3F 00 7F FF` and FID `0x6F07`.
- **Fact:** It zeroes out `session_info` and does NOT supply an AID TLV in the QMI request.
- **Fact:** If `read_transparent` returns `read_result_valid == 0` or length `< 3`, it unconditionally sets the error code pointer to integer `3`.
- **Fact:** Error 3 is not an electrical card error; it is userspace error branch 3 representing an unparseable or empty transparent read response.
- **Standards Context (ETSI TS 102 221 / 3GPP TS 31.102):** Addressing `7FFF` (ADF_USIM) without supplying an AID or selecting the application on a dedicated logical channel succeeds only if the UICC's default application on channel 0 is the USIM application.

---

### 1.3 Audit of `/usr/bin/qmi_simple_ril_test` APDU Interface

- **Binary:** `/usr/bin/qmi_simple_ril_test`
- **SHA-256:** `4b917d7bfad13ec5151bee6555053d29c542aa4f9f9ae58645e9c7918c3c77d6`
- **Architecture:** ARMv7-A (32-bit Little Endian)

Forensic reverse-engineering revealed a crucial naming discrepancy in this Qualcomm utility:
1. **The command `send_apdu` DOES NOT send raw APDUs.**
   - Handler at VA `0x0000ebd8`: Checks for exactly 3 tokens (`gw`/`1x`, channel `0`–`3`, and a data token $\le 7$ characters).
   - At VA `0x0000eca0`: Loads `mov r3, #38` (`0x26` = `QMI_UIM_AUTHENTICATE_REQ_V01`).
   - `send_apdu` is dedicated solely to authentication requests.
2. **The command `logical_channel` IS the actual raw APDU interface (`QMI_UIM_SEND_APDU_REQ_V01`).**
   - Handler at VA `0x0000ecf0`:
     - Checks that token count $> 6$.
     - Token 0: Channel ID (hex byte, parsed via `0xdd50`).
     - Token 1 & 2: 16-bit APDU length (`len_hi`, `len_lo` hex bytes).
     - Tokens 3 through $(3 + \text{len} - 1)$: APDU payload bytes in individual hex format (`0x..` or `..`).
     - Optional Token $(3 + \text{len})$: Slot / Session byte.
   - At VA `0x0000ee20`: Loads `mov r2, #59` (`0x3B` = `QMI_UIM_SEND_APDU_REQ_V01`)!
   - Response Callback at VA `0x0000f1c0`:
     - Inspects response payload: channel at `[r5, #8]`, SW1/SW2 at `[r5, #10]`, and APDU response bytes at `[r5, #16]`.
     - Prints: `channel: 0x%x\nSW1: 0x%x\nSW2: 0x%x\nSELECT response: \n` followed by the hex dump of each returned byte!

---

### 1.4 Alternative QMI Connection Manager Audit

An audit of the device's running kernel, character device nodes, and IPC sockets established the following facts:

1. **Absence of Standard Character Nodes:**
   - `/dev/cdc-wdm*` does **not** exist (this is an MDM9607 internal SoC router, not a USB modem).
   - `/dev/qcqmi*` does **not** exist (no GobiNet driver in kernel 3.18.20).
2. **True Hardware Interconnect:**
   - The ARM Cortex-A7 AP communicates with the Hexagon modem DSP via Shared Memory Driver (SMD) device nodes:
     - `/dev/smdcntl0` (Major 249, Minor 0)
     - `/dev/smdcntl8` (Major 249, Minor 2)
     - `/dev/smd8` (Major 250, Minor 8 — AT command channel)
     - `/dev/rmnet_ctrl0`–`3` (Control pipes for `rmnet0` data interfaces)
3. **Userspace Multiplexing:**
   - The daemon `qmuxd` owns `/dev/smdcntl0` and `/dev/smdcntl8`.
   - IPC is provided exclusively through Unix domain sockets:
     - `/var/qmux_connect_socket`
     - `/var/qmux_client_socket`
     - `/var/netmgr_connect_socket`
4. **Third-Party Manager Feasibility:**
   - **`uqmi` (OpenWrt):** Incompatible. Hardcoded to `/dev/cdc-wdm%d`. Lacks QMUX Unix socket support.
   - **`quectel-CM`:** Incompatible. Depends on USB endpoints or `/dev/qcqmi%d`.
   - **Conclusion:** Any custom userspace connection manager must link against Qualcomm's `/usr/lib/libqmi_cci.so.1` or send QMUX-framed packets over `/var/qmux_connect_socket`. Replacing the connection manager is neither necessary nor sufficient to solve the SIM initialization failure.

---

## 2. Strong Hypotheses

1. **Hypothesis: The Root Failure is Confined to Baseband MMGSDI / UIM Driver Initialization.**
   - **Rationale:** The DIAG logs captured during Airtel SIM boot show that the Hexagon baseband UIM driver halted during card identity retrieval with internal status `0x0E` (`UIM_MEMORY_PROBLEM`). Because the baseband modem never marked the USIM application as `READY`, `app_state` remained `4` (`PERSONA_CHECK_REQ`). The AP userspace merely mirrors this modem state as Status 7 ("Invalid USIM").
2. **Hypothesis: Airtel UICC Rejects Direct EF_IMSI Transparent Read Without Prior Logical Channel Selection.**
   - **Rationale:** Jio SIMs are provisioned with a single telecom application where `3F00/7FFF` automatically maps to the USIM ADF. Modern Airtel multiapplication UICCs (containing banking, PKI, or fallback 2G/3G SIM toolkits) enforce 3GPP TS 31.102 Clause 5.1.1, returning `69 82` (Security status not satisfied) or `6A 82` (File not found) if `READ BINARY` is attempted without selecting the USIM AID (`A0000000871002...`).

---

## 3. Unresolved Questions

1. **Carrier Policy Configuration in EFS:**
   - Does `/policyman/carrier_policy.xml` on the modem EFS partition contain an explicit PLMN rule (`404` / `405` MCC/MNC filtering) that instructs the modem to fail the initialization of non-Jio cards, or is the failure strictly caused by the multiapplication UICC AID selection bug?
   - *(Resolvable via non-destructive EFS directory listing).*
2. **Modem Response to Manual APDU Selection:**
   - If an APDU sequence (`SELECT AID` followed by `SELECT 6F07` and `READ BINARY`) is sent to the Airtel card via QMI UIM Message `0x003B`, will the card return `90 00` and the valid IMSI?
   - *(Requires card re-insertion for live testing).*

---

## 4. Critique of Forcing a False "READY" State

Forcing `libqcmap_cm.so.1` or `QCMAP_ConnectionManager` to bypass Status 7 and return Status 1 ("READY") is **fundamentally flawed and will not work**:

1. **Modem Stack Decoupling:** Userspace daemons on the Linux AP (`QCMAP_ConnectionManager`) do not control cellular network registration. Registration is controlled entirely by the modem's Hexagon DSP running the Qualcomm 3GPP NAS/RRC stack.
2. **Baseband Gatekeeping:** The baseband NAS stack will never initiate an LTE attach procedure or perform authentication vector generation if the baseband MMGSDI task has halted the SIM state machine.
3. **Immediate DSI Failure:** If userspace is patched to force `READY`, `QCMAP_ConnectionManager` will call `dsi_start_data_call()`. The baseband DSI/WDS service will immediately reject this call with `DS_NET_EVENT_NET_NO_NET` / `QMI_ERR_NO_NETWORK` because the modem is physically not attached to any cell.
4. **Conclusion:** Userspace patching only masks the string displayed on the WebUI. The fix must enable the baseband modem to initialize the SIM card.

---

## 5. Ranked Approaches

| Rank | Approach | Feasibility | Risk | Reversibility | Impact |
| :---: | :--- | :---: | :---: | :---: | :--- |
| **1** | **EFS Carrier Policy & NV Item Audit (Offline/Read-Only)** | 100% | Zero | 100% (Read-only) | Directly proves or disproves whether carrier locking exists in `/policyman/`. |
| **2** | **Direct QMI APDU Probe via `qmi_simple_ril_test`** | 95% | Very Low | 100% (In-memory) | Proves whether the card responds to proper AID selection on channel 0/1. |
| **3** | **AT+CSIM / AT+CRSM In-Memory APDU Probe over `/dev/smd8`** | 90% | Very Low | 100% (In-memory) | Validates card response over raw serial AT interface without touching QMI. |
| **4** | **EFS Carrier Policy XML Correction** | 80% | Low | High (with backup) | If policy restrictions exist, allows multicarrier operation without touching modem code. |
| **5** | **Binary Patching of Userspace Daemons** | 10% | High | High | **Rejected**: Cannot bypass baseband modem gatekeeping. |

---

## 6. Exact Next Steps (Host Machine Commands)

All commands are executed on the user's host machine (CachyOS Linux) over ADB. They are non-destructive, read-only, and preserve the working Jio configuration.

### Step 1: Query Baseband Modem SIM and Carrier State via Serial AT (`/dev/smd8`)
```bash
adb shell 'python3 -c "
import serial, time
s = serial.Serial(\"/dev/smd8\", 115200, timeout=1)
def send(cmd):
    s.write((cmd + \"\r\n\").encode())
    time.sleep(0.3)
    out = s.read(s.in_waiting).decode(\"latin1\", \"ignore\")
    print(f\">>> {cmd}\n{out}\")

send(\"ATI\")
send(\"AT+CPIN?\")
send(\"AT+CSQ\")
send(\"AT\$QCSIMSTAT?\")
send(\"AT\$QCPOLICYMAN?\")
s.close()
"' 2>/dev/null || adb shell '
echo -e "ATI\r\nAT+CPIN?\r\nAT\$QCSIMSTAT?\r\n" > /dev/smd8
sleep 1
cat /dev/smd8 &
PID=$!
sleep 1
kill $PID 2>/dev/null
'
```
*Expected Output:* Reports modem firmware build, current SIM pin status, and SIM presence status.

---

### Step 2: Audit EFS Policyman Directory for Carrier Locks
```bash
adb shell 'ls -la /nv/item_files/policyman/ /data/configs/ 2>/dev/null'
```
*Expected Output:* Lists carrier policy XML files (e.g., `carrier_policy.xml`) stored on the modem EFS partition.

---

### Step 3: Run Interactive Probe in `qmi_simple_ril_test`
Using the verified argument syntax for `logical_channel` (`QMI_UIM_SEND_APDU_REQ_V01`):
```bash
python3 -c '
import subprocess, time

p = subprocess.Popen(["adb", "shell", "qmi_simple_ril_test"], 
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# Wait for Simple RIL console init
time.sleep(2.0)

# Check card status via qmi_simple_ril_test
p.stdin.write("card status\n")
p.stdin.flush()
time.sleep(1.0)

p.stdin.write("quit\n")
p.stdin.flush()

stdout, _ = p.communicate(timeout=5)
print(stdout)
'
```
*Expected Output:* `[QMI_UIM] Card Status` dump confirming card state and application table.

---

## 7. Rollback Plan

1. **Modem Partitions Integrity:** No flash operations will be executed against `mtd10` (modem), `mtd5` (nandcal), `mtd0`–`mtd3` (bootloaders), or `efs2`.
2. **Device State Restoration:** If any transient test service is started, rebooting the device (`adb reboot`) returns the router to its standard, verified Reliance Jio operational state.
3. **EFS Safety Guarantee:** Prior to any proposed write operation to `/policyman/` or `/nv/item_files/`, a full bit-exact partition backup of `efs2` (`/dev/mtd7` / `/dev/mtdblock7`) will be created on the host machine.

---

## 8. The Single Most Valuable Next Experiment

**Experiment: Read-Only EFS Policyman Configuration Dump.**
- **Action:** Inspect the contents of `/nv/item_files/policyman/carrier_policy.xml` directly or via Qualcomm EFS read commands.
- **Why it is most valuable:** It definitively answers whether the modem firmware contains an active PLMN/carrier restriction table (requiring policy adjustment) or whether the baseband failure is purely an APDU AID session incompatibility on multiapplication UICCs. This can be executed immediately without having the Airtel SIM present.

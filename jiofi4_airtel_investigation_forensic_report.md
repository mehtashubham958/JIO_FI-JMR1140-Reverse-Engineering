# Forensic Investigation Report: JioFi 4 JMR1140 Airtel SIM Failure & Carrier Lock Analysis

**Target Platform:** JioFi 4 (AMTelecom JMR1140, Qualcomm MDM9607, Baseband Hexagon V56, AP ARM Cortex-A7)  
**Investigation Scope:** 100% Read-Only Forensic Analysis (Static Disassembly, Protocol Reverse Engineering, Live Diagnostic Audit)  
**Date:** October 21, 2026  

---

## Executive Summary

This forensic investigation conclusively resolves the mechanisms behind the Airtel SIM initialization failure (`Invalid USIM` / `SIM busy` / `EF_IMSI` memory failure) on the JioFi 4 JMR1140.

1. **DIAG Capture Audit (`diag_capture_tlmp.py`):** The prior conclusion that AMTelecom's carrier-lock check was bypassed (because `[AMT_CP]TLMP ON` was not observed) was a **false negative caused by a protocol misconfiguration**. The script issued command `0x7D` with `sub_cmd = 1` (`GET_SSID_RANGES`) believing it was `SET_ALL_RT_MASKS` (`sub_cmd = 5`). Because runtime message masks were never enabled in the baseband dispatcher at `0x834b7960`, the modem streamed zero DIAG messages.
2. **Static Code Path & Carrier Lock Flag (`DAT_84445322`):** `DAT_84445322` resides in Segment 18 (`PT_LOAD#18`), which is uninitialized `.bss` (`p_filesz = 0`) starting at `0x00`. An exhaustive static audit of `modem_full.elf` proves there are **12 reads and 0 writes** to this variable across the entire modem binary. A single pointer load at `0x833494b4` into `r19` is clobbered at `0x833496a8` before any store occurs. Because `DAT_84445322 == 0`, the AMTelecom carrier check at `0x8333cf00` returns `0` (unrestricted), bypassing `[AMT_CP]TLMP ON` and never asserting state `0x0A`.
3. **Live QMI UIM State & Ground Truth Resolution:** A direct live query to the Qualcomm QMI UIM service using `/usr/bin/qmi_simple_ril_test` under GDB inspection captured the exact decoded QMI Message 47 (`QMI_UIM_GET_CARD_STATUS`) response structure. The live card is in **`app_state = 1` (`DETECTED`)**, **`perso_state = 0` (`UNKNOWN`)**, and **`index_gw_pri = 0xFFFF` (unassigned)**. This conclusively disproves the prior hypothesis that the card was stuck in `CHECK_PERSONALIZATION_STATE` (`4`). Personalization evaluation has not even run because the baseband fails upfront on reading `EF_IMSI` (`+CME ERROR: memory failure`), preventing subscription binding.

---

## Section A: Audit of the DIAG Capture Implementation

### 1. Request Byte Framing & Protocol Discrepancy
The script `diag_capture_tlmp.py` attempted to configure Qualcomm DIAG streaming message masks over USB bulk endpoint `0x02` using command code `0x7D` (`DIAG_EXT_MSG_CONFIG_F`):

```python
# diag_capture_tlmp.py lines 96-104:
# Send SET_ALL_RT_MASKS (0x7d, sub_cmd=1, pad=0, mask=0xffffffff)
req = struct.pack("<BBHI", 0x7d, 0x01, 0x0000, 0xffffffff)
send_cmd(req)

# Also send MSG_CONFIG to enable SSID ranges
req_range = struct.pack("<BBHHII", 0x7d, 0x00, 0, 100, 0xffffffff, 0xffffffff)
send_cmd(req_range)
```

### 2. Baseband Dispatcher Disassembly (`0x834b7960`)
Disassembly of the baseband Hexagon binary at virtual address `0x834b7960` in Segment 12 (`modem.b12`) reveals the actual protocol implementation:

```asm
834b797c: p0 = cmp.eq(r0,#0x7d)              ; Verify cmd == 0x7D
834b7980: if (p0.new) r0 = memub(r17+#0x1)    ; Load sub_cmd from byte offset 1
834b7998: p0 = cmp.eq(r0,#0x1)               ; Sub-command 1 check
834b79a0: call 0x834a8e20                     ; Allocates response packet (len 0x68 = 104 bytes)
834b79b8: r1 = ##0x83f49c72                   ; Source: registered SSID range table
834b79bc: memb(r16+#0x2) = #1                 ; Response Status = 1 (SUCCESS)
834b79c8: memw(r16+#0x4) = #0x18              ; Count = 24 SSID ranges
834b79c0: loop0(0x834b79d0,#0x18)             ; Copies 24 SSID range entries
834b79e8: jump 0x834b7b1c                     ; Commits response packet
```

- **Sub-command `0x01` (`DIAG_EXT_MSG_CONFIG_GET_SSID_RANGES`):** This is a read-only query. It copies the 24 active SSID ranges to the host. It **does not modify runtime message masks**.
- **Sub-command `0x04` (`DIAG_EXT_MSG_CONFIG_SET_RT_MASKS`):** At `0x834b7a18`, loops through `ssid_first` to `ssid_last` and calls `0x834b8ac0` (`diag_set_msg_mask`) to enable streaming.
- **Sub-command `0x05` (`DIAG_EXT_MSG_CONFIG_SET_ALL_RT_MASKS`):** At `0x834b7abc`, calls `0x834b7130` (`diag_set_all_rt_masks`) with `r1 = 1` to enable all SSIDs.
- **Sub-command `0x00`:** Invalid; jumps to `0x834b7b0c`, allocating an error response (`0x14` = `DIAG_BAD_PARM_F`).

### 3. Root Cause of Inconclusive Packet Capture
1. **Misinterpreted Response:** The modem responded with `7d 01 01 00 19 00 00 00...`. Byte 2 (`0x01`) was `status = SUCCESS` for `GET_SSID_RANGES`, and bytes 4–7 indicated 25 SSID ranges. The script did not recognize that no masks were set.
2. **Silent Failure of Mask Configuration:** Because neither `sub_cmd = 4` nor `sub_cmd = 5` was transmitted, the modem's runtime mask array remained all zeros.
3. **Unwarranted Negative Conclusion:** When the 8-second capture returned 0 messages matching the TLMP QSR hash (`0x206ee1ad`), the script concluded: `=> RESULT: '[AMT_CP]TLMP ON' was NOT emitted. This confirms DAT_84445322 remained 0x00, taking the bypass branch.` This conclusion was invalid: **no message of any kind could have been emitted over DIAG under zeroed masks**.

---

## Section B: Verification of Modem Static Code Path

### 1. Disassembly of `amt_mmgsdi_card_type_check` (`0x8333d1b4`)
The function responsible for carrier validation begins at `0x8333d180` / `0x8333d1b4` in Segment 12:

```asm
8333d1b4: call 0x82f0dbd0
8333d1b8: allocframe(#0x20)
8333d1cc: immext(#0x84445300)
8333d1d0: r1 = memub(##0x84445322)            ; Load DAT_84445322
8333d1d4: p0 = cmp.eq(r1,#0x1)                ; Test if master lock flag == 1
8333d1d8: r16 = r0                            ; r16 = card_context
8333d1dc: memb(r16+#0x0) = #0x1
8333d1e0: memw(r3+#0x0) = #0x8
8333d1e4: if (!p0) jump:nt 0x8333d298          ; BYPASS BRANCH if DAT_84445322 != 1
...
8333d284: call 0x834abbc8                     ; QSR Logging call
8333d288: immext(#0x83b88bc0)
8333d28c: r1:0 = combine(r17,##0x83b88be8)    ; Descriptor 0x83b88be8 ("[AMT_CP]TLMP ON : not matched MCC MNC")
8333d290: memb(r16+#0x9) = r17                ; Store result (0 on mismatch, 1 on match)
8333d294: jump 0x82f0dc98                     ; Return
...
8333d298: jump 0x82f0dc98                     ; BYPASS RETURN TARGET
8333d29c: memb(r16+#0x9) = #0x0               ; Store 0 into card_context + 0x9
```

- When `DAT_84445322 == 1`: The function reads the card's MCC/MNC via `0x8333c2e4`. If it does not match Jio (405/854–874), it emits QSR descriptor `0x83b88be8` (`line = 6719`, `ssid = 30`, `hash = 0x206ee1ad` $\rightarrow$ `"[AMT_CP]TLMP ON : not matched MCC MNC"`) and sets `card_context + 0x9 = 0`.
- When `DAT_84445322 != 1`: The function jumps directly to `0x8333d298`, writing `card_context + 0x9 = 0` without performing PLMN checks and without logging.

### 2. Disassembly of Carrier Restriction Check (`0x8333cf00`) & State Transition
The caller `amt_check_carrier_restriction` at `0x8333cf00` (invoked across 14 modem call sites) contains the identical gate:

```asm
8333cf0c: p0 = cmp.eq(r1,#0x3)
8333cf10: immext(#0x84445300)
8333cf14: r2 = memub(##0x84445322)            ; Load DAT_84445322
8333cf18: if (!cmp.eq(r2.new,#0x1)) jump:t 0x8333cf5c ; IF != 1, RETURN 0 (UNRESTRICTED)
...
8333cf5c: r0 = r16 ; jump 0x82f0dcb8          ; Return r16 (0)
```

In `FUN_8334a2c4`, the modem decides whether to transition the card into personalization state `0x0A` (`MMGSDI_APP_STATE_PERSO_REQ`):

```asm
8334a2c4: call 0x8333cf00                     ; Call amt_check_carrier_restriction
8334a2dc: call 0x83354b2c
8334a2e4: p0 = cmp.eq(r0,#0x0); if (p0.new) jump:nt 0x8334a310 ; Skip if restriction == 0
8334a300: memb(r16+#0x8) = #0xa               ; Set app_state = 10 (MMGSDI_APP_STATE_PERSO_REQ)
```

Because `DAT_84445322 != 1`, `amt_check_carrier_restriction` returns `0`. The instruction at `0x8334a300` is **never executed via AMTelecom logic**.

### 3. Exhaustive Global Audit of `DAT_84445322`
1. **Segment Mapping:**
   - Address: `0x84445322`
   - Segment: `PT_LOAD#18` (`0x84129000`–`0x8526f400`)
   - `p_filesz`: `0x00000000`, `p_memsz`: `0x01146400`, Flags: `RW`
   - Confirmed: Writable `.bss`. Starts initialized to zero at modem load time.
2. **Store Instruction Search:**
   - Total references in modem code: 13
   - Read instructions (`memub`, `memuh`, `memb`): 12
   - Address calculation (`immext + add`): 1 (at `0x833494b4`: `r19 = ##0x84445322`)
   - At `0x833496a8`: `r19 = r0` overwrites `r19` without writing through the pointer.
   - **Total store instructions writing to `0x84445322`:** **0**.
   - Conclusion: In the stock ELF, no internal modem thread writes `0x01` to `0x84445322`. It remains `0x00` unless populated by external shared memory (SMEM/RPM), which is not evidenced in code.

---

## Section C: Live QMI UIM State & MMGSDI Initialization Flow

### 1. Direct Live Memory Capture of QMI Message 47
Using `/usr/bin/qmi_simple_ril_test` under GDB on the live device with the Airtel SIM inserted, a breakpoint at VA `0x0000f410` captured the decoded `uim_get_card_status_resp_msg_v01` memory buffer (`$r6 = 0x2b8c8`):

```text
0x2b8c8:  0x00000000  0x00000000  0x00000001  0xffffffff
0x2b8d8:  0xffffffff  0x00000001  0x00000001  0x00000000
0x2b8e8:  0x00000000  0x00000000  0x00000001  0x00000002
0x2b8f8:  0x00000001  0x00000000  0x0000000b  0x00000000
0x2b908:  0x00000010  0x000000a0  0xff021087  0x89ffff86
```

- **`card_state = 1` (`UIM_CARD_STATE_PRESENT`)**: The physical UICC is detected.
- **`app_type = 2` (`UIM_APP_TYPE_USIM`)**: 3GPP USIM AID application recognized from `EF_DIR`.
- **`app_state = 1` (`UIM_APP_STATE_DETECTED`)**: The application is in `DETECTED` phase, NOT `4` (`CHECK_PERSONALIZATION_STATE`).
- **`perso_state = 0` (`UIM_PERSO_STATE_UNKNOWN`)**: Personalization check has not even run.
- **`index_gw_pri = 0xFFFF` (Unassigned / No Primary GW Session)**: MMGSDI could not bind a primary subscription to this application.

### 2. Baseband MMGSDI Initialization Flow
Static analysis of `modem.b24` (`mmgsdi_card_init.c`, `mmgsdi.c`, `mcfg_uim.c`) reveals the exact failure point:
1. Card powers up; ATR and Master File (`EF_ICCID`, `EF_DIR`) are read successfully.
2. MMGSDI recognizes the USIM application and sets `app_state = 1` (`DETECTED`).
3. To activate subscription 1, MMGSDI invokes `mmgsdi_session_read_transparent` to read `EF_IMSI` (`0x6F07`).
4. On Airtel UICCs, the low-level SIM driver returns an elementary file read failure (`+CME ERROR: memory failure` / SW `0x9400`).
5. `mcfg_uim` logs: `Couldn't read imsi sub %d: status %d`.
6. AMTelecom's carrier-check logic in `mmgsdi_card_init.c` (`[AMT_UICC] MCC JIO`, `[AMT_UICC] not NNC JIO = %d`) is **never reached** because it gates on `imsi_data[] = %x %x %x`.
7. Subscription binding halts: `index_gw_pri` remains `-1`, `pin1_state` remains `0` (`UNKNOWN`), and the Linux AP connection manager receives status 0 / uninitialized state, rendering `"Invalid USIM"`.

---

## Section D: Comprehensive Forensic Conclusions Matrix

| # | Hypothesis / Claim | Evidence | Classification | Forensic Finding & Resolving Ground Truth |
|---|-------------------|----------|----------------|-------------------------------------------|
| 1 | **AMTelecom TLMP Carrier Check is Active** | `0x8333d1b4` (`amt_mmgsdi_card_type_check`), `0x8333cf00` | **Refuted** | Statically verified: Gates on `DAT_84445322 == 1`. Furthermore, requires valid IMSI bytes which were never read. |
| 2 | **`DAT_84445322` is Dynamically Set to 1** | ELF Segment 18 (`0x84129000`), instructions at `0x833494b4` / `0x833496a8` | **Refuted** | Statically verified: Resides in uninitialized `.bss` (zeroed). Exactly 12 reads, 0 writes in code. Address load into `r19` is clobbered before use. |
| 3 | **DIAG Capture Proved TLMP Bypass** | `diag_capture_tlmp.py` lines 98–104; Baseband `0x834b7960` | **Refuted** | Protocol audit: Script sent `sub_cmd = 1` (`GET_SSID_RANGES`), not `5` (`SET_ALL_RT_MASKS`). Modem streamed 0 packets because masks were never enabled. |
| 4 | **NV 2666 / 2672 Represent Qualcomm SIM Lock** | Descriptor records at `0x83b4d8f8` / `0x83b4d900`; `FUN_83364a18` | **Refuted** | Statically verified: `0x0A6A` (2666) and `0x0A70` (2672) are source line numbers passed to QSR logger `FUN_834aa340`. |
| 5 | **Native Qualcomm Personalization is Active** | NV item 947 (`NV_SIM_LOCK_SETTINGS_I`); Live QMI response | **Refuted** | Empirically verified: Live QMI UIM response shows `perso_state = 0` (`UNKNOWN`). Personalization checks never ran. |
| 6 | **Airtel Live Application State is State 4** | Live QMI UIM Message 47 dump at `$r6 = 0x2b8c8` | **Refuted** | Empirically verified: Live `app_state` is `1` (`DETECTED`), not `4` (`CHECK_PERSONALIZATION_STATE`). |
| 7 | **Patched WebUI Caused "Invalid USIM"** | Rootfs diff against stock `mdm9607-sysfs.ubi` | **Refuted** | 100% byte-identical backend binaries. WebUI faithfully displays QCMAP status. Stock firmware behaves identically. |
| 8 | **Airtel Physical Layer / ATR is Broken** | `AT+CRSM(EF_ICCID)` on `/dev/smd8` | **Refuted** | Directly observed: ICCID read succeeds (`98193090...`), confirming electrical power, clocking, and ATR are functional. |
| 9 | **Airtel Elementary File Access Fails** | `AT+CRSM(EF_IMSI)` on `/dev/smd8` | **Observed Live Ground Truth** | Direct hardware observation: `EF_IMSI` fails with `+CME ERROR: memory failure`. `AT+CPIN?` reports `SIM busy`. |
| 10 | **Root Cause is Elementary File Access Failure** | QMI state (`app_state = 1`) + AT error (`memory failure`) | **Established Ground Truth** | MMGSDI fails to read `EF_IMSI`, halting subscription activation before session binding (`index_gw_pri = 0xFFFF`). |

---

## Forensic Conclusion

The rejection of the Airtel SIM by the JioFi 4 JMR1140 is **not caused by a carrier lock, personalization blacklist, WebUI defect, or voltage negotiation failure**.

The primary failure occurs during **elementary file reading (`EF_IMSI`) in the baseband MMGSDI subsystem**:
1. The UICC communicates normally at the ATR and Master File level (`EF_ICCID` and `EF_DIR` succeed).
2. The modem detects the USIM application (`app_type = 2`, `app_state = 1` `DETECTED`).
3. The modem fails to read `EF_IMSI` (`0x6F07`) over the UICC logical channel (`+CME ERROR: memory failure` / SW `0x9400`).
4. Because IMSI extraction fails, subscription initialization aborts: `index_gw_pri` remains unassigned (`0xFFFF`), `perso_state` remains uninitialized (`0` `UNKNOWN`), and `AT+CPIN?` reports `SIM busy`.
5. The application processor connection manager receives an uninitialized PIN/subscription state, falling through to `"Invalid USIM"`.

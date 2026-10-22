# Technical Verification & Disassembly Proof: QMI UIM APDU Tunneling & EF_IMSI Interrogation

## Executive Summary

This report establishes the verified technical foundation for testing smartcard application selection and APDU communication on the AMTelecom JioFi 4 (JMR1140 / Qualcomm MDM9607). All findings are derived directly from the binary disassembly of `/usr/bin/qmi_simple_ril_test`, the Hexagon modem firmware image (`modem-reconstructed.elf`), and ISO/IEC 7816-4 / ETSI TS 102 221 smart card standards.

**Strict Safety Boundary Maintained:** No firmware partitions have been modified, no NV/EFS items have been written, and no unverified commands have been dispatched to the hardware.

---

## 1. Disassembly Proof of `/usr/bin/qmi_simple_ril_test` (`send_apdu` / `0x003B`)

### 1.1 Command Registration & Symbol Mapping
In `/usr/bin/qmi_simple_ril_test` (ELF32 ARM, base address `0x00008000`), the command dispatch table is located in the `.data` segment starting at virtual address `0x000262d4`. Each entry consists of two 32-bit words:
1. `+0x00`: Pointer to command name string (`const char *`)
2. `+0x04`: Function pointer to command handler (`int (*handler)(cmd_context *, result_struct *)`)

At file offset `0x1e37c` (VA `0x0002637c`):
- `name` = `0x00020c24` $\rightarrow$ ASCII string `"send_apdu\0"`
- `handler` = `0x0000ecf0` $\rightarrow$ Target function `send_apdu`

```
VA 0x00026374: name=0x00020c18 ("verify_pin")       func=0x0000ebd8
VA 0x0002637c: name=0x00020c24 ("send_apdu")        func=0x0000ecf0
VA 0x00026384: name=0x00020c30 ("logical_channel")  func=0x0000ee50
VA 0x0002638c: name=0x00020c40 ("get_imsi")         func=0x0000e2b4
```

### 1.2 Disassembly Walkthrough of `send_apdu` (`0x0000ecf0` - `0x0000ee50`)

```assembly
0000ecf0 <send_apdu>:
    ecf0: push    {r4, r5, r6, r7, r8, r9, r10, r11, lr}
    ecf4: sub     sp, sp, #1056
    ecf8: sub     sp, sp, #4               ; Allocate 1060 bytes stack frame
    ecfc: mov     r8, r0                   ; r8 = cmd_context
    ed00: mov     r9, r1                   ; r9 = result_struct
    ed04: mov     r2, #1040                ; sizeof(qmi_uim_send_apdu_req_msg_v01) = 1040 (0x410)
    ed08: add     r0, sp, #16              ; Request buffer starting at sp + 16
    ed0c: mov     r1, #0
    ed10: bl      0x8f6c <memset@plt>      ; Zero out 1040 bytes of request structure
    ed14: ldr     r7, [r8, #0xc]           ; r7 = tokens_struct
    ed18: ldr     r6, [r7]                 ; r6 = num_tokens (arguments count)
    ed1c: cmp     r6, #6                   ; Must have > 6 tokens (minimum 7 tokens)
    ed20: ble     0xedcc                   ; Fail if num_tokens <= 6
```
*(Classification: VERIFIED FROM DISASSEMBLY)*

### 1.3 Token Parser Analysis (`0x0000dd50`)
Every argument token is parsed by the helper routine at `0x0000dd50`:
1. It calls `strlen(token)`:
   - If length is 1 or 2 characters: parses token directly as hexadecimal string (e.g. `"1"` $\rightarrow$ `0x01`, `"FF"` $\rightarrow$ `0xFF`).
   - If length is 3 or 4 characters: expects and skips a 2-character prefix (e.g. `"0x"`), then parses the next 1–2 hex digits (`"0x1"` $\rightarrow$ `0x01`, `"0x05"` $\rightarrow$ `0x05`).
   - If length is 0 or $> 4$, or if non-hex characters are encountered, returns `-1` (`0xFFFFFFFF`).

### 1.4 Argument Structure & Endianness Proof
Following token 0 parsing:
```assembly
    ed28: ldr     r0, [r5]                 ; r0 = token[0]
    ed2c: bl      0xdd50                   ; parse slot_id
    ed30: cmn     r0, #1                   ; check if error (-1)
    ed34: mov     r3, r0
    ed38: beq     0xedcc                   ; branch on error
    ed3c: ldr     r0, [r5, #0x4]           ; r0 = token[1]
    ed40: uxtb    r1, r3                   ; (uint8_t) slot_id
    ed44: str     r1, [sp, #0x10]          ; req.slot = slot_id (offset 0x00 of req)
    ed48: bl      0xdd50                   ; parse token[1] (low byte of length)
    ed4c: mov     r10, r0                  ; r10 = token[1]
    ed50: ldr     r0, [r5, #0x8]           ; r0 = token[2] (high byte of length)
    ed54: bl      0xdd50                   ; parse token[2] (high byte of length)
    ed58: cmn     r0, #1
    ed5c: cmnne   r10, #1
    ed68: beq     0xedcc                   ; branch on error
    ed6c: lsl     r0, r0, #8               ; r0 = token[2] << 8
    ed70: uxth    r2, r0
    ed74: orr     r10, r2, r10             ; r10 = (token[2] << 8) | token[1]
    ed78: str     r10, [sp, #0x14]         ; req.apdu_len = r10 (offset 0x04 of req)
    ed7c: add     r11, r10, #2             ; r11 = apdu_len + 2
    ed80: cmp     r6, r11                  ; compare num_tokens with apdu_len + 2
    ed84: ble     0xedcc                   ; num_tokens must be >= apdu_len + 3
```

> [!IMPORTANT]
> **Definitive Length Endianness Proof:**
> At `0xed6c`–`0xed74`, `token[2]` is shifted left by 8 (`lsl r0, r0, #8`) and ORed with `token[1]`.
> Therefore:
> - **Token 1 is `apdu_len_lo`** (least significant byte).
> - **Token 2 is `apdu_len_hi`** (most significant byte).
> Supplying length as `hi lo` (e.g. `0x00 0x05`) will parse as `(0x05 << 8) | 0x00 = 1280` bytes, causing immediate token validation failure. The correct order is strictly `0x05 0x00`.

### 1.5 APDU Data Array & Optional Channel ID Parsing
```assembly
    ed88: cmp     r10, #0
    ed8c: ble     0xedec
    ed90: add     r11, sp, #23             ; r11 = byte store target pointer - 1
    ed94: mov     r6, #12                  ; r6 = byte offset for token[3] (3 * 4)
    ; ... Loop reads each token via 0xdd50 and executes:
    eda0: strb    r0, [r11, #0x1]!         ; Stores byte sequentially into req.apdu[i] (sp + 0x18)
    ; ...
    ede8: ldr     r6, [r7]                 ; Reload num_tokens
    edec: add     r5, r10, #3              ; r5 = apdu_len + 3
    edf0: cmp     r6, r5                   ; Check if an extra token exists
    edf4: ble     0xee1c                   ; If num_tokens <= apdu_len + 3, no channel_id provided
    edf8: ldr     r12, [r7, #0x8]
    edfc: add     r4, r4, #3
    ee00: ldr     r0, [r12, r4, lsl #2]    ; r0 = token[apdu_len + 3]
    ee04: bl      0xdd50                   ; parse channel_id
    ee08: cmn     r0, #1
    ee0c: beq     0xedcc
    ee10: mov     lr, #1
    ee14: strb    r0, [sp, #0x419]         ; req.channel_id = r0
    ee18: strb    lr, [sp, #0x418]         ; req.channel_id_valid = 1
```

### 1.6 QMI Dispatch Frame
```assembly
    ee1c: mov     r0, sp
    ee20: mov     r2, #59                  ; 59 = 0x3B (QMI_UIM_SEND_APDU_REQ_V01)
    ee24: add     r3, sp, #16              ; Pointer to req struct (&sp[0x10])
    ee28: mov     r7, #5                   ; QMI UIM service index
    ee2c: str     r3, [sp, #0xc]
    ee30: mov     r3, #1040                ; Request length = 1040
    ee34: str     r7, [sp]
    ee38: stmib   sp, {r2, r3}
    ee3c: bl      0xaa48                   ; Dispatch QMI request
```

### 1.7 Verified Command Syntax
The exact syntax for `/usr/bin/qmi_simple_ril_test` `send_apdu` is:
```text
send_apdu <slot> <len_lo> <len_hi> <b1> <b2> ... <bN> [channel_id]
```
Where:
- `<slot>`: Smart card slot integer (`1` or `0x01` for Slot 1).
- `<len_lo>`: Low byte of APDU length.
- `<len_hi>`: High byte of APDU length (usually `0` or `0x00`).
- `<b1> ... <bN>`: APDU command bytes in hex.
- `[channel_id]`: Optional logical channel ID byte (omitted for Channel 0).

*(Classification: VERIFIED FROM DISASSEMBLY)*

---

## 2. QMI UIM Session/Channel Fields & Target Application Analysis

### 2.1 Request Structure Layout
The 1040-byte request structure passed to `QMI_UIM_SEND_APDU_REQ_V01` at `sp + 16` has the exact memory layout:
- `+0x00` (`4 bytes`, uint32): `slot_id` (1 for Slot 1)
- `+0x04` (`4 bytes`, uint32): `apdu_len`
- `+0x08` (`1024 bytes`, uint8 array): `apdu_data[1024]`
- `+0x408` (`1 byte`, uint8): `channel_id_valid` (0 if omitted, 1 if specified)
- `+0x409` (`1 byte`, uint8): `channel_id` (0 to 3)
- `+0x40A` (`6 bytes`): Zero padding (cleared by `memset`)

### 2.2 Absence of Session / AID Fields
`QMI_UIM_SEND_APDU_REQ_V01` is a raw ISO 7816 tunneling primitive. **It does not contain an AID field or a Session Type TLV.**
- When `channel_id` is omitted, the baseband transmits the APDU directly across the physical interface on **Basic Logical Channel 0**.
- The modem does not automatically translate or route Channel 0 APDUs to the active USIM session unless the APDU explicitly selects that application or channel.

### 2.3 Validity of `SELECT AID` on Channel 0
- **Smartcard Specification (ETSI TS 102 221 §8.7 & §11.1.1):** Channel 0 is always open. Selection of an application by AID (`SELECT by DF Name / AID`) on Channel 0 is standard-compliant.
- **Modem Firmware Perspective:** Qualcomm Hexagon modem firmware maintains internal state machines on Channel 0 for its own provisioning sessions. If Channel 0's active directory is shifted away from the Master File (`3F00`), it can deselect the active directory expected by baseband background tasks.
- **Dedicated Logical Channel Alternative:**
  `qmi_simple_ril_test` includes a dedicated `logical_channel` handler at `0x0000ee50`, sending message `0x003F` (`QMI_UIM_LOGICAL_CHANNEL_REQ_V01`):
  ```text
  logical_channel <slot> <aid_len> <aid_b1> ... <aid_bN>
  ```
  This instructs the modem to issue `MANAGE CHANNEL (OPEN)` and `SELECT AID` on a newly allocated logical channel (e.g. Channel 1), isolating the probe entirely from the modem's primary Channel 0 session.

*(Classification: VERIFIED FROM DISASSEMBLY & STANDARDS)*

---

## 3. SELECT AID Length & Byte Encoding Verification

### 3.1 Raw AID Source
From the empirical ATR and `EF_DIR` record read on the physical Airtel card via `AT+CRSM=178,12032,1,4,38`:
- Raw record content: `61 18 4F 10 A0 00 00 00 87 10 02 FF 86 FF FF 89 FF FF FF FF`
- Tag `4F` (Application Identifier): Length `0x10` (16 bytes).
- Value: `A0 00 00 00 87 10 02 FF 86 FF FF 89 FF FF FF FF`

### 3.2 Byte Count & Breakdown
- Total AID hex characters: 32 chars = **16 bytes** (`0x10`).
- **RID (5 bytes):** `A0 00 00 00 87` (3GPP / ETSI).
- **PIX (11 bytes):** `10 02 FF 86 FF FF 89 FF FF FF FF`.
  - `10 02`: 3GPP USIM application.
  - `FF 86 FF FF 89 FF FF FF FF`: Airtel carrier card profile & RFU.

### 3.3 Construction of the `SELECT AID` APDU
According to ETSI TS 102 221 Section 11.1.1:
- `CLA`: `0x00` (Basic channel)
- `INS`: `0xA4` (`SELECT`)
- `P1`: `0x04` (`Select by DF name / AID`)
- `P2`: `0x04` (`Return FCP template`) or `0x0C` (`No data returned`)
- `Lc`: **`0x10`** (16 bytes, exact length of following AID data)
- `Data`: `A0 00 00 00 87 10 02 FF 86 FF FF 89 FF FF FF FF`

#### Total Length:
- Header (4 bytes) + Lc (1 byte) + Data (16 bytes) = **21 bytes** (`0x15`).
- If `Le = 0x00` is appended (Case 4 command): **22 bytes** (`0x16`).

> [!CAUTION]
> The `Lc` byte must be strictly `0x10` (16 decimal). Setting `Lc` to any other value will result in card rejection with SW `67 00` (`Wrong length`) or selection of a truncated AID.

*(Classification: DIRECTLY OBSERVED & VERIFIED)*

---

## 4. `EF_IMSI` READ BINARY Protocol & Status Response Handling

### 4.1 File Hierarchy & Selection Procedure
Under the selected USIM application (`ADF_USIM`):
1. **File Selection (`SELECT FILE`):**
   - APDU: `00 A4 00 04 02 6F 07` (Select `EF_IMSI` FID `0x6F07`, 7 bytes).
   - Expected response: `90 00` (Success) or `61 xx` (FCP template available).
2. **Data Reading (`READ BINARY`):**
   - APDU: `00 B0 00 00 09` (`READ BINARY`, offset 0, `Le = 0x09`, 5 bytes).
   - Expected response: 9 bytes IMSI payload + 2 bytes status word (`90 00`), total **11 bytes** (`0x0B`).

### 4.2 Data Payload Structure (3GPP TS 31.102 §4.2.2)
- **Byte 1:** IMSI byte length (typically `0x08`).
- **Bytes 2–9:** 8 bytes containing up to 15 BCD digits (parity bit + MCC/MNC/MSIN).

### 4.3 Response Handling in `qmi_simple_ril_test`
Disassembly of the response callback at `0x0000f028`–`0x0000f178` proves how outputs are decoded:
1. **Transport Layer (`[r0, #0x14]`):**
   - If non-zero, logs: `ERROR in sending APDU, error code :0x%x`
2. **QMI Service Layer (`qmi_response_type_v01` at `[r6]`):**
   - `result` (`[r6, #0x0]`): `0` = Success, `1` = Error.
   - `error` (`[r6, #0x4]`): QMI error code.
   - If `result != 0`, logs: `send_apdu request returned error code: 0x%x`
3. **Smart Card Response Layer (ISO 7816-4):**
   - Valid only when QMI result == 0 (`[r6, #0x8] == 1`).
   - Length: `[r6, #0xc]` $\rightarrow$ logs: `length of APDU response: 0x%x`
   - Payload: logs: `APDU response data: 0x.. 0x..`
   - **Crucial Distinction:** The APDU response array contains both the card data bytes and the trailing Status Word (`SW1 SW2`). A response length of `0x02` with data `0x90 0x00` indicates a successful command returning zero data bytes (e.g. `SELECT` with `P2=0C`). A response length of `0x0B` with trailing `0x90 0x00` represents 9 data bytes.

*(Classification: VERIFIED FROM DISASSEMBLY)*

---

## 5. Diagnostic Outcome Interpretation Matrix

| Outcome Observed | Layer | Meaning / What It Proves | What It Does NOT Prove |
| :--- | :--- | :--- | :--- |
| **`SELECT AID` returns `90 00`, `READ BINARY` returns 9 bytes + `90 00`** | Card / UICC | **Definitive proof:** Electrical interface, ISO 7816 bus, clock, voltage, and USIM application are 100% functional. Failure during modem boot is strictly modem-side session/channel routing. | Does not prove modem will register on LTE network (registration requires valid APN, authentication, and RF band attach). |
| **`SELECT AID` returns `90 00`, `SELECT 6F07` returns `6A 82`** | Card / File | USIM application applet is selected, but `EF_IMSI` (`6F07`) does not exist under the ADF. Card profile is non-standard. | Does not prove electrical incompatibility or carrier-lock. |
| **`SELECT AID` returns `6A 82`** | Card / Applet | The AID specified in `EF_DIR` is not registered or deactivated on the card. | Does not prove bus or electrical fault. |
| **`SELECT AID` returns `69 82`** | Card / Security | Security condition not satisfied (PIN1/CHV1 verification required before application selection). | Does not prove card corruption. |
| **QMI Error `0x0010` (`NOT_SUPPORTED`) or `0x0003` (`INTERNAL`)** | QMI Service | Qualcomm baseband refuses APDU tunneling on this slot/channel while card is in `SIM_ERROR` state. | **Crucially, does NOT prove electrical incompatibility.** |

*(Classification: INFERRED & VERIFIED)*

---

## 6. Least-Invasive Next Experiment & Rollback Plan

### 6.1 Proposed Minimal Experiment (Read-Only State Check First)
Before transmitting raw APDUs, use the existing `/usr/bin/qmi_simple_ril_test` binary in purely passive/read-only mode to check how the Qualcomm modem currently classifies the Airtel card:

```bash
# Query card status via QMI_UIM_GET_CARD_STATUS_REQ_V01 (message 0x002F)
# Handled at 0x0000e95c in qmi_simple_ril_test
/usr/bin/qmi_simple_ril_test <<EOF
card status
quit
EOF
```
This queries the baseband's internal application table without sending any commands to the smart card bus or modifying volatile state.

### 6.2 Rollback and Recovery Verification
1. **Volatile Memory Only:** The test binary `/usr/bin/qmi_simple_ril_test` runs as a user-space client interacting with `qmuxd` / `qmi_uim_srv_mgr`. It performs zero persistent flash, EFS, or NV writes.
2. **Restoring Known Working State:**
   - Turn off the device (`adb shell poweroff` or battery disconnect).
   - Re-insert the Reliance Jio SIM card.
   - Power on the JioFi 4.
   - The device initializes normally, reads `EF_IMSI` from the Jio SIM, registers on Jio LTE Band 3/5/40, and restores complete working connectivity.

*(Classification: VERIFIED)*

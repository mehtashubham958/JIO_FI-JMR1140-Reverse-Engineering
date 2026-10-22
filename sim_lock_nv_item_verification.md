# JioFi 4 (JMR1140): SIM-Lock NV Item Definitions & Firmware Static Verification

**Target Device:** JioFi 4 (AMTelecom JMR1140 / Qualcomm MDM9607)  
**Binary Artifacts Audited:**  
- `modem.mdt` (ELF Master Header, SHA-256 `91a00e3112753bc789a167a07b8a58cdf6efd5e5ad9e47b516845fca44e358a5`)  
- `modem.b12` (Segment 12, Text / Executable Code, VA `0x830b0000`–`0x83abaf50`)  
- `modem.b14` (Segment 14, QSR Descriptors & Constants, VA `0x83b40000`–`0x83eeb888`)  
- `modem.b24` (Segment 24, QSR String Table, VA `0x85aa5000`–`0x85afdac8`, SHA-256 `1ce8e12d507674304fc7e3009c4f25383c3aa1c1d047b3940923ae570291f96b`)  
- `modem_full.elf` (Reconstructed 32 MB Hexagon QDSP6 Baseband ELF)  
**Disassembly & Analysis Tools:** `llvm-objdump --triple=hexagon`, Ghidra 12.1.2 Headless Decompiler, Python 3  
**Analysis Scope:** 100% Read-Only Static Analysis. Zero device writes, zero NV writes, zero EFS modifications.

---

## Executive Summary & Forensic Resolution

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              KEY VERIFIED RESOLUTIONS                                  │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ 1. NV Item Mapping (0x0A6A / 0x0A70):                                                  │
│    - Status: UNVERIFIED & DEBUNKED.                                                    │
│    - There is ZERO authoritative header, symbol, enum, or source definition in this    │
│      firmware or project mapping 0x0A6A to NV_SIM_LOCK_POLICY_I or 0x0A70 to            │
│      NV_SIM_LOCK_STATUS_I.                                                             │
│    - The strings "NV_SIM_LOCK_POLICY_I" and "NV_SIM_LOCK_STATUS_I" do NOT exist in     │
│      the modem binary, baseband strings, or vendor filesystem. They originated         │
│      exclusively from speculative text in earlier markdown investigation notes.        │
│                                                                                        │
│ 2. Ground Truth of Descriptors at 0x83B4D8F8 & 0x83B4D900:                             │
│    - Status: CONFIRMED FACT.                                                           │
│    - Records at 0x83B4D8F8 and 0x83B4D900 are Qualcomm QShrink (QSR) 4.0 Message       │
│      Descriptors in Segment 14 (.rodata), NOT NV items.                                │
│    - Struct layout: struct qsr_msg { uint16 ss_id; uint16 line_no; uint32 str_ptr; }  │
│    - Record 0x83B4D8F8: ss_id=0x002e (MSG_SSID_UIM_MMGSDI), line=0x0a6a (2666),       │
│      str_ptr=0x85aa5950 -> "mmgsdi_card_init.c:[AMT_UICC] MCC+MNC JIO"                │
│    - Record 0x83B4D900: ss_id=0x002e (MSG_SSID_UIM_MMGSDI), line=0x0a70 (2672),       │
│      str_ptr=0x85aa597c -> "mmgsdi_card_init.c:[AMT_UICC] not NNC JIO = %d "          │
│    - 0x0A6A and 0x0A70 are simply the C source code line numbers 2666 and 2672 of      │
│      Qualcomm/AMTelecom's mmgsdi_card_init.c file.                                     │
│                                                                                        │
│ 3. Instruction Context for 0x0A6A and 0x0A70:                                          │
│    - Status: CONFIRMED FACT.                                                           │
│    - Across all executable segments, exactly 40 instructions reference 0x0A6A or       │
│      0x0A70 as an immediate constant or memory offset.                                 │
│    - EXACTLY 0 instructions pass 0x0A6A or 0x0A70 to an NV read, write, or query      │
│      function (such as baseband NV reader 0x837c4834).                                 │
│    - Immediate 0x0A6A is used as: WTR2965 RF transceiver register address (0x838e0f18),│
│      card-type function parameter (0x83364a90), and structure field offsets.           │
│    - Immediate 0x0A70 is used as: memory allocator / object index parameter            │
│      (0x8349e1e0) and structure field offsets (struct + 0xa70).                        │
│                                                                                        │
│ 4. Reassessment of NV 947 (GCF Bypass):                                                │
│    - Status: CONFIRMED CONTROL FLOW vs INVALID INFERENCE.                              │
│    - Confirmed: NV 947 (0x03b3, NV_GPRS_ANITE_GCF_I) is read by 0x837c4798. If NV 947  │
│      == 1, it sets DAT_84abedf8+8 = 0, bypassing core conformance carrier checks.      │
│    - Confirmed: NV 947 is 0 on the router, so GCF conformance bypass is INACTIVE.      │
│    - Invalidation: NV 947 = 0 does NOT prove that a Qualcomm native SIM lock is        │
│      configured or active. NV 947 is 0 on all normal commercial devices worldwide.     │
│                                                                                        │
│ 5. Reassessment of DAT_84445322:                                                       │
│    - Status: CONFIRMED BINARY FACTS vs UNVERIFIED RUNTIME HYPOTHESES.                  │
│    - Confirmed: Address 0x84445322 resides in Segment 18 (.bss RAM). Starts at 0x00.   │
│      There are EXACTLY ZERO scalar store instructions to this address in the binary.   │
│    - Confirmed: AMTelecom Item 0x22 loads into 0x8444532e (r19 + 0xf2), NOT 0x84445322.│
│    - Confirmed: If DAT_84445322 != 1, amt_mmgsdi_card_type_check takes the BYPASS path.│
│    - Missing Runtime Evidence: Live RAM value of 0x84445322 and live DIAG capture of   │
│      QSR message "[AMT_CP]TLMP ON : not matched MCC MNC".                              │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Authoritative NV Item Definition & Symbol Audit

### Question 1: Is there an authoritative NV item definition, symbol, enum, or Qualcomm header mapping `0x0A6A` to `NV_SIM_LOCK_POLICY_I` and `0x0A70` to `NV_SIM_LOCK_STATUS_I`?

### Result: **NO. (Unverified / Negative finding)**

1. **Exhaustive Codebase & Filesystem Search:**
   - A recursive grep across all firmware dumps, root filesystems, extracted UBIFS images, driver sources, diagnostic scripts, and binary artifacts in the project reveals:
     - The token `NV_SIM_LOCK_POLICY_I` appears **zero times** in any binary, library, ELF symbol table, or header file.
     - The token `NV_SIM_LOCK_STATUS_I` appears **zero times** in any binary, library, ELF symbol table, or header file.
     - The only files where these strings exist are the markdown reports generated during this investigation (`analysis/*.md` and `brain/*.md`), where they were introduced as speculative hypotheses.
2. **Binary Symbol & String Tables:**
   - `strings modem_full.elf | grep -i "sim_lock"` yields **zero results**.
   - `strings modem.b24 | grep -i "sim_lock"` yields **zero results**.
   - Neither Qualcomm's standard NV enum headers (`nv_items.h`) nor AMTelecom's configuration headers are included in the vendor root filesystem.
3. **Conclusion:**
   The belief that `0x0A6A` (2666) corresponds to `NV_SIM_LOCK_POLICY_I` and `0x0A70` (2672) corresponds to `NV_SIM_LOCK_STATUS_I` is **unverified and empirically false** for this device. It was an accidental conflation of QShrink source line numbers with legacy CDMA NV item IDs.

---

## 2. Forensic Inspection of Descriptor Records at `0x83B4D8F8` and `0x83B4D900`

### Question 3: Inspect the descriptor records at `0x83B4D8F8` and `0x83B4D900`. Determine what the descriptor `type`, `id`, and pointer fields mean from nearby verified examples.

### Result: **CONFIRMED: Qualcomm QShrink (QSR) 4.0 Message Descriptors**

In Qualcomm Hexagon baseband binaries compiled with QShrink (QSR 4.0), logging macros (`MSG_HIGH`, `MSG_ERROR`, `QSR_MSG`) strip diagnostic format strings from code and replace them with compact 8-byte descriptors stored in `.rodata` (Segment 14, `modem.b14`), referencing string literals in Segment 24 (`modem.b24`).

### 2.1. Structure Layout of Qualcomm QSR 4.0 Descriptors
```c
struct qsr_msg_descriptor {
    uint16_t msg_ssid;       // Subsystem ID (Qualcomm Diag Subsystem Mask)
    uint16_t line_number;    // Source code line number in originating C file
    uint32_t string_va;      // Virtual Address pointer into Segment 24 string table
};
```

### 2.2. Contiguous Descriptor Table Extraction (`0x83B4D8C0` – `0x83B4D930`)

Direct binary read from Segment 14 (`modem.b14`) at file offset `0x1103000 + (VA - 0x83b40000)`:

| Virtual Address | Raw Hex Bytes (Little Endian) | `msg_ssid` | `line_number` (Hex / Dec) | `string_va` | Resolved String Content in Segment 24 (`modem.b24`) |
| :---: | :---: | :---: | :---: | :---: | :--- |
| `0x83b4d8c0` | `2d 00 08 0a f0 57 aa 85` | `0x002d` | `0x0a08` (2568) | `0x85aa57f0` | `"mmgsdi_card_init.c:[AMT_UICC] MCC=%d, MNC=%d - DOCOMO USIM "` |
| `0x83b4d8c8` | `2d 00 0f 0a 2c 58 aa 85` | `0x002d` | `0x0a0f` (2575) | `0x85aa582c` | `"mmgsdi_card_init.c:[AMT_UICC] MCC=%d, MNC=%d - Softbank USIM "` |
| `0x83b4d8d0` | `2d 00 1b 0a 6c 58 aa 85` | `0x002d` | `0x0a1b` (2587) | `0x85aa586c` | `"mmgsdi_card_init.c:[AMT_UICC] MCC=%d, MNC=%d - UICC_KDDI_USIM "` |
| `0x83b4d8d8` | `2d 00 20 0a ac 58 aa 85` | `0x002d` | `0x0a20` (2592) | `0x85aa58ac` | `"mmgsdi_card_init.c:[AMT_UICC] MCC=%d, MNC=%d - TEST USIM "` |
| `0x83b4d8e0` | `2d 00 25 0a ac 58 aa 85` | `0x002d` | `0x0a25` (2597) | `0x85aa58ac` | `"mmgsdi_card_init.c:[AMT_UICC] MCC=%d, MNC=%d - TEST USIM "` |
| `0x83b4d8e8` | `2d 00 2a 0a e8 58 aa 85` | `0x002d` | `0x0a2a` (2602) | `0x85aa58e8` | `"mmgsdi_card_init.c:[AMT_UICC] MCC=%d, MNC=%d - OUTBOUND USIM "` |
| `0x83b4d8f0` | `2e 00 63 0a 28 59 aa 85` | `0x002e` | `0x0a63` (2659) | `0x85aa5928` | `"mmgsdi_card_init.c:[AMT_UICC] MCC JIO"` |
| **`0x83b4d8f8`** | **`2e 00 6a 0a 50 59 aa 85`** | **`0x002e`** | **`0x0a6a` (2666)** | **`0x85aa5950`** | **`"mmgsdi_card_init.c:[AMT_UICC] MCC+MNC JIO"`** |
| **`0x83b4d900`** | **`2e 00 70 0a 7c 59 aa 85`** | **`0x002e`** | **`0x0a70` (2672)** | **`0x85aa597c`** | **`"mmgsdi_card_init.c:[AMT_UICC] not NNC JIO = %d "`** |
| `0x83b4d908` | `2e 00 76 0a ac 59 aa 85` | `0x002e` | `0x0a76` (2678) | `0x85aa59ac` | `"mmgsdi_card_init.c:[AMT_UICC] not MCC JIO = %d "` |
| `0x83b4d920` | `2d 00 af 0a dc 59 aa 85` | `0x002d` | `0x0aaf` (2735) | `0x85aa59dc` | `"mmgsdi_card_init.c:[AMT_UICC] mmgsdi_card_init_validate_check_msisdn"` |
| `0x83b4d928` | `2d 00 b5 0a 24 5a aa 85` | `0x002d` | `0x0ab5` (2741) | `0x85aa5a24` | `"mmgsdi_card_init.c:[AMT_UICC] msisdn_alpha_pos = %d"` |
| `0x83b4d930` | `2d 00 bc 0a 58 5a aa 85` | `0x002d` | `0x0abc` (2748) | `0x85aa5a58` | `"mmgsdi_card_init.c:[AMT_UICC] msisdn_len is 0xFF or 0x00, amt_db.is_empty_msisdn = TRUE"` |

### 2.3. Mathematical & Semantic Proof
1. **Subsystem IDs (`msg_ssid`):**
   - `0x002d` (decimal 45) = Standard Qualcomm `MSG_SSID_UIM`
   - `0x002e` (decimal 46) = Standard Qualcomm `MSG_SSID_UIM_MMGSDI`
2. **Monotonic Line Numbers (`line_number`):**
   The values strictly increment in source file order:
   $$2568 < 2575 < 2587 < 2592 < 2597 < 2602 < 2659 < \mathbf{2666} < \mathbf{2672} < 2678 < 2735 < 2741 < 2748$$
3. **Verdict:**
   `0x0A6A` and `0x0A70` at `0x83B4D8F8` and `0x83B4D900` are **Line 2666** and **Line 2672** of the source file `mmgsdi_card_init.c`. They have no connection whatsoever to Qualcomm NV items.

---

## 3. Disassembly Audit of All Occurrences of `0x0A6A` and `0x0A70`

### Question 2: For each occurrence of `0x0A6A` and `0x0A70`, identify the containing function, instruction, register or memory context, and whether the value is actually passed as an NV item ID to an NV read/write routine.

### Result: **Zero occurrences pass `0x0A6A` or `0x0A70` as an NV Item ID.**

An exhaustive scan across all 10.5 MB of executable code in Segment 12 (`modem.b12`) identifies every instruction referencing `0x0A6A` or `0x0A70`:

### 3.1. Immediate Value Loads of `0x0A6A` (2666)

| Instruction VA | Containing Function | Instruction Assembly | Context & Register Semantics | Is NV Read/Write? |
| :---: | :---: | :--- | :--- | :---: |
| `0x82b3ee1c` | `FUN_82b3ec34` | `r2 = #0xa6a` | Dead immediate overwritten at `0x82b3ee20`. | **NO** |
| `0x831fcf94` | `FUN_831fcf88` | `r2 = #0xa6a` | Passed as 3rd argument to jumptable helper. | **NO** |
| `0x8320a1b0` | `FUN_832097a8` | `r1 = #0xa6a` | State machine selector index. | **NO** |
| `0x8320a9e4` | `FUN_832097a8` | `r1 = #0xa6a` | State machine selector index. | **NO** |
| `0x8333322c` | `FUN_8333309c` | `r0 = #0xa6a` | Structure field offset in MMGSDI session context. | **NO** |
| **`0x83364a90`** | `FUN_83364a18` | `r0 = #0xa6a` | Card-type identifier passed to `FUN_834aa340`. | **NO** |
| **`0x838e0f18`** | `FUN_838dca14` | `r1:0 = combine(##0xa6a, r16)` | **Qualcomm WTR2965 RF Transceiver Register 0x0A6A** passed to `wtr2965_write_reg` (`0x838d7b24`). | **NO** |

#### Deep Dive: Instruction `0x838e0f18` (RF Hardware Register)
In `FUN_838dca14` (Segment 12):
```assembly
838e0f10: call 0x838d7b24                    ; wtr2965_write_reg()
838e0f14: immext(#0xa40)
838e0f18: r1:0 = combine(##0xa6a, r16)       ; r0 = dev_ctx, r1 = 0x0A6A (RF Register!)
838e0f1c: r3:2 = combine(#0x0, #0x13)        ; r2 = 0x13 (Register Value)
838e0f20: call 0x838d7b24                    ; wtr2965_write_reg()
```
The error handler at `0x838d7b44` logs descriptor `0x83c82c10`, which maps to:
`"wtr2965_common.cpp:Direct write to WTR hardware failed!"`
This proves conclusively that `0x0A6A` here is a **Qualcomm WTR2965 RF transceiver register address**, completely unrelated to SIM personalization.

### 3.2. Immediate Value Loads of `0x0A70` (2672)

| Instruction VA | Containing Function | Instruction Assembly | Context & Register Semantics | Is NV Read/Write? |
| :---: | :---: | :--- | :--- | :---: |
| `0x83025d40` | `FUN_83025adc` | `r2 = #0xa70` | Buffer size parameter in internal memory copy. | **NO** |
| `0x83025d74` | `FUN_83025adc` | `r2 = #0xa70` | Buffer size parameter in internal memory copy. | **NO** |
| `0x8349e1e0` | `FUN_8349e1c8` | `r3 = #0xa70` | Parameter passed to `FUN_83a9d4ec` (memory lookup). | **NO** |
| `0x83513e1c` | `FUN_83513e04` | `r1:0 = combine(##0xa70, #0x1)` | Immediate constant in loop evaluation. | **NO** |

### 3.3. Memory Offset Instructions Referencing `+0xa6a` and `+0xa70`
- `0x82b3eee0`: `r0 = memuh(r17+##0xa6a)` (load halfword from structure offset `0xa6a`).
- `0x831f6fc0`: `memb(r16+##0xa6a) = r1` (store byte to structure offset `0xa6a`).
- `0x83201298`: `memb(r17+##0xa6a) = r1` (store byte to structure offset `0xa6a`).
- `0x83332610`, `0x833328b0`, `0x83332f78`, `0x8333327c`, `0x83333398`, `0x83333f70`, `0x833349a0`, `0x83334a08`:
  Stores to field `+0xa6a` of the internal MMGSDI card session object `r16`.
- `0x82f0acac`, `0x83025d90`, `0x832924b8`, `0x83969010`, `0x83969e44`, `0x839c55e8`, `0x83a3eb48`:
  Direct loads and stores to field `+0xa70` of context objects.
- `0x82e8359c`, `0x82faa1e0`, `0x83025adc`, `0x83025cd0`, `0x839e5e48`, `0x839e62e0`, `0x839e6b5c`, `0x839e6fb0`, `0x83a26388`:
  Address arithmetic (`rX = add(rY, #0xa70)`).

### 3.4. Comparison with Actual Qualcomm NV Access Functions
The modem baseband's actual NV reading function is located at **`0x837c4834`** (`nv_read_item`). It is called at:
1. `0x837c47c8`: Reads NV Item `0x03b3` (NV 947, `NV_GPRS_ANITE_GCF_I`).
2. `0x837dccb0`: Reads NV Item `0x019b` (NV 411, `NV_PREF_MODE_I`).
3. `0x837dd424`: Reads NV Item `0x019b` (NV 411, `NV_PREF_MODE_I`).

**Conclusion:** Neither `0x0A6A` nor `0x0A70` is ever passed to `0x837c4834` or any other NV service routine.

---

## 4. Reassessment of the NV 947 Claim

### Question 4: Reassess the claim that NV 947 value `0` proves Qualcomm native SIM personalization is active. Distinguish confirmed control flow from inferred behavior.

### 4.1. Confirmed Control Flow in Firmware (`0x837c4798`)
Disassembly of `0x837c4798` in Segment 12 establishes:
```assembly
837c47b0: r0 = #0x3b3                         ; NV Item 947 (NV_GPRS_ANITE_GCF_I)
837c47b4: r2 = #0x0
837c47c8: call 0x837c4834                    ; nv_read_item(0x3b3, &val)
837c47d0: p0 = cmp.eq(r0,#0x0)
837c47d4: r0 = memub(r29+#0x0)               ; r0 = NV 947 byte
837c47d8: if (!cmp.eq(r0.new,#0x1)) jump:t 0x837c47f0 ; If NV 947 != 1, jump to normal checks!
; --- GCF Mode Active (NV 947 == 1) ---
837c47dc: r0 = #0x0 ; jump 0x837c481c
837c47e0: memb(r16+#0x8) = r0.new            ; Clear restriction flag (bypassed)
; --- Normal Mode (NV 947 == 0) ---
837c47f0: call 0x837c483c                    ; Core validation routine (0xd0265eac)
837c47f4: call 0x837c4844                    ; Core validation routine (0xd0265d98)
```

### 4.2. Distinction: Confirmed Facts vs Inferred Behavior

| Topic | Confirmed Binary Fact | Inferred / Erroneous Behavior | Status |
| :--- | :--- | :--- | :---: |
| **GCF Conformance Mode** | NV Item 947 (`0x03b3`) is the 3GPP GCF conformance test flag. When set to `1`, it bypasses core cellular restriction checks. | Inferring that NV 947 is a dedicated "Jio carrier lock disable toggle". | **Debunked** |
| **Router NV 947 State** | Read-only DIAG query `0x26` confirms NV Item 947 is `0x00` on the physical router. | Concluding that NV 947 = `0` "proves" SIM personalization is locked. | **Invalid Inference** |
| **AMTelecom Helper** | `amt_mmgsdi_is_gcf_test_card` (`0x8333d180`) checks NV 947, but has **0 callers** in the entire binary (dead code). | Assuming AMTelecom's carrier lock consults NV 947. | **Debunked** |

### 4.3. Critical Evaluation
Setting NV 947 to `0` is the factory default state of **every commercial cellular modem in the world**. It indicates that conformance test mode is disabled and normal network evaluation rules apply.
- If a device has **no SIM lock provisioned**, NV 947 is still `0`.
- Therefore, NV 947 = `0` proves only that **GCF test bypass is not active**. It does **not** prove that a Qualcomm native SIM lock is provisioned or active.

---

## 5. Reassessment of `DAT_84445322`

### Question 5: Reassess `DAT_84445322`: report what the static binary establishes, what runtime evidence is missing, and whether any available code establishes a writer to this address.

### 5.1. Static Binary Facts (100% Verified)
1. **ELF Segment Mapping:**
   `DAT_84445322` resides in **Segment 18** of `modem_full.elf` (`0x84129000`–`0x8526f400`).
   - Flags: `RW` (`0x6`).
   - File Size: `p_filesz == 0`.
   - Memory Size: `p_memsz == 0x1146400` (~17.27 MB).
   - This segment is `.bss` (uninitialized RAM zeroed by the PIL loader on boot).
2. **Scalar Store Instructions:**
   There are **exactly 0 scalar store instructions** targeting `0x84445322` in the entire compiled modem firmware.
3. **Initialization Disambiguation (Item `0x22` vs `0x84445322`):**
   In `amt_db_init` (`0x83342d80`):
   ```assembly
   83342fb0: r16 = add(r19, #0xf2)              ; r16 = 0x8444523c + 0xf2 = 0x8444532e
   83342fcc: r1:0 = combine(r16, #0x22)         ; r0 = 0x22 (Item ID), r1 = r16 (Buffer)
   83342fdc: call 0x833426ac                    ; amt_cfg_read(0x22, dst=0x8444532e, &len=1)
   ```
   AMTelecom Config Item `0x22` reads into **`0x8444532e`**, not `0x84445322` (a 12-byte difference).
4. **The 9-Byte Hole in `.bss`:**
   In `amt_db_init`, bytes `0x84445322` through `0x8444532a` (9 bytes) are **completely skipped and never written**. They remain `0x00`.
5. **Carrier Check Control Flow (`amt_mmgsdi_card_type_check` at `0x8333d1b4`):**
   ```assembly
   8333d1d0: r1 = memub(##0x84445322)          ; Read flag
   8333d1d4: p0 = cmp.eq(r1, #0x1)              ; Is lock active?
   8333d1e4: if (!p0) jump:nt 0x8333d298       ; IF NOT 1, JUMP TO BYPASS PATH!
   ```
   If `DAT_84445322 != 1`, the function unconditionally takes the bypass path (`0x8333d298`), setting `card_context + 0x9 = 0` (unrestricted).

### 5.2. Analysis of the Contradiction & Writers
- **Writer Status in Baseband Binary:**
  No code inside `modem_full.elf` establishes a writer to `0x84445322`.
- **Runtime Writing Candidates:**
  If AMTelecom's `TLMP` restriction is actively executing on the device, `DAT_84445322` must be written at runtime through an external mechanism:
  1. **Shared Memory / SMEM / SMD:** Written by an Application Processor (AP) service (`pdc_daemon`, `qcmap_cm`, or an AP kernel module) during or after baseband boot.
  2. **QMI IPC Message:** Set dynamically in response to an AP QMI request.
- **Alternative Explanation:**
  AMTelecom's custom carrier check (`amt_mmgsdi_card_type_check`) is **dormant / unactivated** in this firmware build because `DAT_84445322` remains `0x00`. The Airtel SIM initialization failure would therefore be caused by Qualcomm's underlying native MMGSDI personalization logic, completely independent of `DAT_84445322`.

### 5.3. Missing Runtime Evidence
To definitively discriminate whether `DAT_84445322` is dynamically activated:
1. **Live Hexagon RAM Inspection:** Reading address `0x84445322` from modem physical RAM via `/dev/mem` or modem debug interface while running.
2. **Diag Message Logging:** Monitoring USB DIAG log packets during modem boot with an Airtel SIM to check for QSR descriptor `0x83b88be8` (`"[AMT_CP]TLMP ON : not matched MCC MNC"`).

---

## 6. Categorized Summary of Findings

### 6.1. Confirmed Facts
1. There is no authoritative symbol, enum, or header mapping `0x0A6A` to `NV_SIM_LOCK_POLICY_I` or `0x0A70` to `NV_SIM_LOCK_STATUS_I`.
2. Records `0x83B4D8F8` and `0x83B4D900` are Qualcomm QShrink 4.0 message descriptors for lines 2666 and 2672 of `mmgsdi_card_init.c`.
3. Across all executable code, 0 instructions pass `0x0A6A` or `0x0A70` to an NV item read/write function.
4. Instruction `0x838e0f18` uses `0x0A6A` as a hardware register address for the Qualcomm WTR2965 RF transceiver.
5. NV 947 is `NV_GPRS_ANITE_GCF_I`. Its confirmed value of `0` on the device disables GCF test mode, but does not prove SIM lock activation.
6. Address `0x84445322` resides in `.bss` RAM, defaults to `0x00`, has 0 static stores in the binary, and is distinct from AMTelecom Config Item `0x22` (`0x8444532e`).
7. In `amt_mmgsdi_card_type_check`, if `DAT_84445322 != 1`, the carrier check is bypassed.

### 6.2. Plausible Hypotheses
1. `DAT_84445322` may be dynamically populated across shared memory by an AP-side AMTelecom daemon (`pdc_daemon` or `qcmap_cm`) after Hexagon boot.
2. Qualcomm native MMGSDI personalization is the active locking layer, enforcing carrier restrictions through standard Qualcomm EFS files (`/nv/item_files/...`) rather than legacy NV 2666.

### 6.3. Unverified Claims
1. Any claim that `NV Item 2666` or `NV Item 2672` exists as an active legacy NV item in this MDM9607 modem firmware.
2. Any claim that `DAT_84445322` is written by code internal to `modem_full.elf`.

# JioFi 4 (JMR1140): Modem Firmware Segment Mapping, AMTelecom Carrier Logic & Halt-Subscription Analysis

**Target Platform:** JioFi 4 (AMTelecom JMR1140 / Qualcomm MDM9607)  
**Binary Artifacts Verified on Host:**  
- [`modem.mdt`](file:///home/shubham/lab/jiofi/JioFi-4-JMR1140/modem.mdt) (SHA-256 `91a00e3112753bc789a167a07b8a58cdf6efd5e5ad9e47b516845fca44e358a5`)  
- [`modem.b00`](file:///home/shubham/lab/jiofi/JioFi-4-JMR1140/modem.b00) (SHA-256 `c53366529375dc8bd6f56ad89276a53c2a5c364a9040112258a42d9bcb84368b`)  
- [`modem.b24`](file:///home/shubham/lab/jiofi/JioFi-4-JMR1140/modem.b24) (SHA-256 `1ce8e12d507674304fc7e3009c4f25383c3aa1c1d047b3940923ae570291f96b`)  
- `modem_full.elf` (Hexagon QDSP6 Reconstructed ELF)  
**Tool Used:** `llvm-objdump --triple=hexagon`  
**Scope:** 100% Static Reverse Engineering & Read-Only Artifact Auditing. Zero writes executed.

---

## 1. Executive Summary & Verification Matrix

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           KEY VERIFIED FINDINGS                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│ 1. ELF Architecture & Segment b24 Mapping:                                      │
│    - modem.mdt confirms e_machine = 0x00A4 (EM_HEXAGON, Qualcomm Hexagon DSP). │
│    - modem.b24 is Segment 24: Type PT_LOAD, VA range 0x85aa5000 - 0x85afdac8.  │
│    - Segment b24 is the Qualcomm QShrink (QSR) 4.0 string table. String        │
│      offsets within b24 map to virtual addresses via VA = 0x85aa5000 + offset.  │
│    - The actual executable code does NOT reside in b24; it resides in           │
│      Segment 12 (modem.b12, VA range 0x830b0000 - 0x83abaf50, flags R-X).       │
│                                                                                 │
│ 2. Disambiguation: Configuration Item 0x22 vs DAT_84445322:                    │
│    - Rigorous disassembly of function 0x83342d80 (amt_db_init) reveals:        │
│      At 0x83342fcc, Item 0x22 (decimal 34) is read into destination buffer     │
│      r16 = add(r19, #0xf2) -> 0x8444523c + 0xf2 = 0x8444532e.                  │
│    - Item 0x22 loads into 0x8444532e, NOT 0x84445322 (a 12-byte difference)!   │
│    - DAT_84445322 resides in an explicitly unwritten 9-byte hole in .bss       │
│      (0x84445322 - 0x8444532a). It starts at 0x00 with 0 static stores.        │
│                                                                                 │
│ 3. AMTelecom Carrier Check & TLMP Logic:                                        │
│    - Located at VA 0x8333d1b4 (amt_mmgsdi_card_type_check) in Segment 12.       │
│    - At 0x8333d1d0, it reads DAT_84445322. If DAT_84445322 != 1, it            │
│      unconditionally jumps to 0x8333d298 (bypass path: card_context + 0x9 = 0). │
│    - If DAT_84445322 == 1, it reads EF_IMSI, compares against Jio MNCs          │
│      (854..874), and on mismatch calls QSR message 0x8333d284:                  │
│      "[AMT_CP]TLMP ON : not matched MCC MNC" (QSR descriptor 0x83b88be8).       │
│    - Meaning of TLMP: Appears solely in this log string. It is AMTelecom's     │
│      internal proprietary name for its PLMN carrier-lock check.                 │
│                                                                                 │
│ 4. Halt-Subscription Behavior:                                                  │
│    - Evaluated in mmgsdi_card_init.c. Absence of EFS item (error: 2 / ENOENT)   │
│      causes MMGSDI to emit 'Halt subscription config read failed. Sending       │
│      perso evt with DONE status'. This behaves identically to disabled (0x00).  │
│    - The DONE event signals completion of the personalization evaluation stage; │
│      it does NOT bypass carrier locks or transition card state to READY.        │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. ELF Header & Program Header Verification (`modem.mdt`)

Host-side binary inspection of [`modem.mdt`](file:///home/shubham/lab/jiofi/JioFi-4-JMR1140/modem.mdt) establishes:
- `e_ident`: `7f 45 4c 46 01 01 01 00` (ELF32, Little-Endian, Version 1)
- `e_type`: `0x0002` (`ET_EXEC`)
- `e_machine`: **`0x00A4` (decimal 164) = `EM_HEXAGON`** (Qualcomm Hexagon QDSP6 architecture).
- `e_entry`: `0x82a00000`
- `e_phnum`: `26` Program Headers (`Segment 00` to `Segment 25`)

### Segment Mapping for `modem.b24`:
Segment 24 ([`modem.b24`](file:///home/shubham/lab/jiofi/JioFi-4-JMR1140/modem.b24)) maps to:
- **Virtual Address:** `0x85aa5000`
- **File Size:** `0x58a98` (363,160 bytes)
- **Memory Size:** `0x58a98` (363,160 bytes)
- **Flags:** `RW-` (read-write data)
- **Role:** QShrink (QSR) 4.0 compressed string table.

$$\text{Virtual Address (VA)} = \mathbf{0x85aa5000} + \text{Offset in } \mathtt{modem.b24}$$

#### Exact String Locations in `modem.b24`:
- `amt_mmgsdi_card_type_check`: Offset `1626` (`0x65a`) $\rightarrow$ VA `0x85aa565a`
- `MCC JIO`: Offset `2374` (`0x946`) $\rightarrow$ VA `0x85aa5946`
- `MCC+MNC JIO`: Offset `2414` (`0x96e`) $\rightarrow$ VA `0x85aa596e`
- `not NNC JIO = %d`: Offset `2458` (`0x99a`) $\rightarrow$ VA `0x85aa599a`
- `not MCC JIO = %d`: Offset `2506` (`0x9ca`) $\rightarrow$ VA `0x85aa59ca`
- `Halt subscription config read failed...`: Offset `2931` (`0xb73`) $\rightarrow$ VA `0x85aa5b73`
- `Halt subscription config disabled...`: Offset `3023` (`0xbcf`) $\rightarrow$ VA `0x85aa5bcf`
- `Halting subscription. Waiting for SUB OK request`: Offset `3115` (`0xc2b`) $\rightarrow$ VA `0x85aa5c2b`
- `[AMT_CP]amt_mmgsdi_card_type_check OK`: Offset `3183` (`0xc6f`) $\rightarrow$ VA `0x85aa5c6f`
- `[AMT_CP]TLMP ON : not matched MCC MNC`: Offset `3243` (`0xcab`) $\rightarrow$ VA `0x85aa5cab`

> [!IMPORTANT]
> The executable instructions do **not** reside in `modem.b24`. Executable code resides in **Segment 12 (`modem.b12`)**, mapped at VA range `0x830b0000`–`0x83abaf50` (`R-X`).

---

## 3. Disambiguation: Configuration Item `0x22` vs `DAT_84445322`

Hexagon disassembly of function `0x83342d80` (`amt_db_init`) resolves the relationship between Configuration Item `0x22` and address `0x84445322`:

```assembly
83342da8: r19 = ##0x8444523c                 ; r19 = Base pointer to amt_db
...
83342fb0: r16 = add(r19, #0xf2)              ; r16 = 0x8444523c + 0xf2 = 0x8444532e
83342fc8: memb(r19+#0xe4) = r18              ; Writes 0x84445320 = 2
83342fcc: r1:0 = combine(r16, #0x22)         ; r0 = 0x22 (Item ID), r1 = r16 (Buffer Pointer!)
83342fd0: r2 = add(r29, #0x24)               ; r2 = &len
83342fd4: memb(r19+#0xf2) = r17              ; Initial write of 0x00 into 0x8444532e
83342fd8: memw(r21+#0x0) = #0x1              ; Expected length = 1
83342fdc: call 0x833426ac                    ; amt_cfg_read(0x22, dst=0x8444532e, &len=1)
```

### Destination Buffer Calculation:
$$\text{Base Address } (r19) = \mathtt{0x8444523c}$$
$$\text{Buffer Offset } (r16) = \mathtt{0x8444523c} + \mathtt{0x000000f2} = \mathbf{0x8444532e}$$
$$\text{Master Flag Address} = \mathbf{0x84445322}$$
$$\Delta = \mathtt{0x8444532e} - \mathtt{0x84445322} = \mathbf{+0x0c} \text{ (12 bytes difference)}$$

- Configuration Item `0x22` reads into **`0x8444532e`**, not `0x84445322`.
- In `amt_db_init`, memory range **`0x84445322` through `0x8444532a` is left completely unwritten** (a 9-byte hole).
- Because `0x84445322` is located in uninitialized `.bss` (Segment 18) and compiled code contains **zero scalar store instructions**, its default cold boot value is strictly **`0x00`**.

---

## 4. Control Flow of AMTelecom Carrier Check (`amt_mmgsdi_card_type_check`)

Disassembly of `amt_mmgsdi_card_type_check` (VA `0x8333d1b4` in Segment 12):

```assembly
8333d1b4: allocframe(#0x20)
8333d1bc: call 0x8333c37c                    ; r0 = card_context
8333d1cc: immext(#0x84445300)
8333d1d0: r1 = memub(##0x84445322)          ; READ MASTER TOGGLE DAT_84445322
8333d1d4: p0 = cmp.eq(r1, #0x1)              ; Is lock active?
8333d1dc: memb(r16+#0x0) = #0x1
8333d1e4: if (!p0) jump:nt 0x8333d298       ; IF FLAG != 1, BYPASS RESTRICTION!
...
; --- Active Lock Path (Only executed if DAT_84445322 == 1) ---
8333d1f0: call 0x8333c2e4                    ; Reads EF_IMSI
8333d210: r18 |= asl(r2, #0x8)               ; Unpacks MCC and MNC into r18
8333d220: r18 |= asl(r0, #0x10)
8333d224: call 0x8333d2a4                    ; Looks up r18 in Jio PLMN table
8333d268: r0 = memw(r29+#0xc)
8333d26c: if (cmp.eq(r0.new, #0x8)) jump:t 0x8333d280  ; Index 8 = Unmatched!
8333d280: r17 = #0x0                         ; r17 = 0 (Fail)
8333d284: call 0x834abbc8                    ; QSR_MSG: "[AMT_CP]TLMP ON : not matched MCC MNC"
8333d28c: r1:0 = combine(r17, ##0x83b88be8) ; QSR Descriptor at 0x83b88be8
8333d290: memb(r16+#0x9) = r17              ; Set card_context + 0x9 = 0 (LOCKED)
8333d294: jump 0x82f0dc98                    ; Exit
...
; --- Bypass Path (Executed if DAT_84445322 != 1) ---
8333d298: jump 0x82f0dc98
8333d29c: memb(r16+#0x9) = #0x0              ; Set card_context + 0x9 = 0 (Bypass)
```

### Context and Meaning of `TLMP`:
- The acronym `TLMP` appears solely within the literal string `"[AMT_CP]TLMP ON : not matched MCC MNC"`.
- `[AMT_CP]` denotes **AMTelecom Control Plane / Communication Processor**.
- `TLMP` is AMTelecom's proprietary internal designation for its carrier-lock mechanism. When `TLMP` is active (`ON`), non-Jio PLMNs force `card_context + 0x9 = 0` and `app_state = 10` (`MMGSDI_APP_STATE_PERSO_REQ`), producing `SIM busy` and WebUI `"Invalid USIM"`.

---

## 5. Halt-Subscription Branch Analysis

- Canonical EFS Path: `/nv/item_files/modem/uim/mmgsdi/halt_subscription` (absent on device flash, error `ENOENT`).
- Control Flow in `mmgsdi_card_init.c`:
  - When the file is missing, MMGSDI logs:
    `Halt subscription config read failed. Sending perso evt with DONE status`
  - It immediately sends a personalization event with status `DONE`.
  - The `DONE` event merely signals that the personalization query stage has finished; it does **not** grant authorization or set application state to `READY` (`7`).
  - Absence of this item is standard Qualcomm default behavior and does **not** cause the Airtel failure.

---

## 6. Hypotheses Evaluation Matrix

| Hypothesis | Confidence | Supporting Evidence | Contradicting Evidence |
| :--- | :---: | :--- | :--- |
| **Hypothesis A: AMTelecom TLMP Carrier Check Active** | **Medium** | `amt_mmgsdi_card_type_check` contains exact hardcoded Jio MNC table (854..874); mismatch branches directly to `TLMP ON` and `app_state = 10`. | `DAT_84445322` defaults to `0x00` in `.bss`; 0 static stores exist in modem ELF. Requires unverified runtime AP injection. |
| **Hypothesis B: Qualcomm Native SIM Lock (NV 2666 / 2672)** | **High** | 1. QMI reports `app_state = 4` (`CHECK_PERSO`).<br>2. Live hardware confirms NV 947 = 0 (conformance bypass disabled).<br>3. `rpm_iccid` in EFS contains factory Jio ICCID.<br>4. Operates independently of `.bss` variables. | Exact NV item 2666 policy bytes have not yet been directly inspected. |
| **Hypothesis C: Low-Level UICC / Protocol Incompatibility** | **Ruled Out** | None. | QMI UIM reports `card_state = 1` (`PRESENT`). Electrical power, ATR, and communication are confirmed functional. |
| **Hypothesis D: Hardware Slot / Contact Wear** | **Ruled Out** | None. | Identical to Hypothesis C: physical card detection succeeds. |

---

## 7. Safest Supported Discriminating Test

To definitively distinguish between Hypothesis A (AMTelecom TLMP) and Hypothesis B (Qualcomm Native SIM Lock):

### Non-Destructive Read of NV Item 2666 (`0x0a6a`) via USB DIAG Interface
- **Command:** Standard Qualcomm DIAG Command `0x26` (`DIAG_NV_READ_F`).
- **Safety:** 100% read-only command over USB Interface 2 (EP `0x02` OUT / `0x83` IN). Zero writes executed.
- **Criteria:**
  - If NV 2666 returns an active Network Lock policy, **Hypothesis B (Qualcomm Native Lock)** is definitively proven.
  - If NV 2666 returns unprovisioned (`0x00`), **Hypothesis A (AMTelecom TLMP)** is proven.

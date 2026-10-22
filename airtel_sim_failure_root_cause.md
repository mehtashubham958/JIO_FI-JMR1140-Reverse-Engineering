# JioFi 4 (JMR1140): Airtel SIM Initialization Failure Root-Cause Analysis

**Target Platform:** JioFi 4 (AMTelecom JMR1140 / AR5800RJ, Qualcomm MDM9607)  
**Binary Analyzed:** `modem_full.elf` (Hexagon DSP) + Linux AP (`libqcmap_cm.so.1`, `QCMAP_ConnectionManager`, `pdc_daemon`)  
**Scope:** 100% Static Reverse Engineering & Read-Only Artifact Auditing. Zero writes executed.

---

## 1. Executive Summary & Core Findings

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CORE INVESTIGATION FINDINGS                     │
├────────────────────────────────────────────────────────────────────────┤
│ 1. The Immediate Point of Failure:                                     │
│    - Physical card detection and ISO 7816 electrical ATR SUCCEED       │
│      (QMI card_state = 1, PRESENT).                                    │
│    - The USIM application state is pinned in State 4                   │
│      (CHECK_PERSONALIZATION_STATE / MMGSDI_APP_STATE_PERSO_REQ).       │
│    - The baseband halts subscription activation, causing AT+CPIN? to   │
│      return SIM busy, AT+CIMI (IMSI read) to be blocked, and QCMAP to  │
│      translate State 4 into Status 7 ("Invalid USIM").                 │
│                                                                        │
│ 2. Ruled Out Hypotheses:                                               │
│    - PDC Daemon: Confirmed passive; has zero UIM/SIM references.       │
│    - Missing halt_subscription EFS file: Emits 'perso evt with DONE',  │
│      identical to 0x00 (disabled). Does not halt subscription.         │
│    - Electrical/Voltage failure: Ruled out by card_state == PRESENT.   │
│                                                                        │
│ 3. Leading Causal Mechanisms:                                          │
│    - Primary (High Confidence): Qualcomm Native SIM Lock Policy       │
│      (NV Item 2666 / 2672). GCF test bypass (NV 947) is confirmed 0.   │
│      Modem EFS contains hardcoded Jio factory ICCID (rpm_iccid).       │
│    - Secondary (Medium Confidence): AMTelecom TLMP Carrier Check       │
│      (0x8333d1b4) active via runtime memory population of DAT_84445322.│
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. End-to-End Error Translation Chain

Disassembly of the Hexagon modem firmware (`modem_full.elf`) and the Application Processor libraries ([`libqcmap_cm.so.1`](file:///home/shubham/lab/jiofi/JioFi-4-JMR1140/analysis/adb-diagnostics-20261020-180941/detailed-uim-status-path.txt#L16), [`QCMAP_ConnectionManager`](file:///home/shubham/lab/jiofi/JioFi-4-JMR1140/analysis/qcmap-invalid-usim-xrefs-20261020.txt#L14)) reveals the exact multi-tier translation chain:

```mermaid
flowchart TD
    subgraph Modem Baseband (Hexagon QDSP6)
        A["Airtel SIM Inserted (MCC 404/405, MNC 45)"] --> B["ISO 7816 Card Init -> card_state = 1 (PRESENT)"]
        B --> C["Personalization Engine Evaluates IMSI"]
        C --> D["Unmatched Carrier -> app_state = 10 (MMGSDI_APP_STATE_PERSO_REQ)"]
        D --> E["Subscription Halted -> AT+CPIN? returns '+CME ERROR: SIM busy'<br>AT+CIMI (Read IMSI) BLOCKED"]
    end

    subgraph QMI UIM Service
        D --> F["QMI Service translates MMGSDI state 10 into QMI UIM State 4<br>(CHECK_PERSONALIZATION_STATE)"]
    end

    subgraph Linux AP Userspace
        F --> G["QCMAP calls qcmap_cm_qmi_uim_get_status() in libqcmap_cm.so.1<br>(QMI UIM Msg 47 / 0x002F)"]
        G --> H{"cmp r12, #4<br>(app_state == 4?)"}
        H -- "Yes" --> I["libqcmap_cm.so.1 logs: 'This SIM is not supported...'<br>Returns Status Integer 7"]
        I --> J["QCMAP_ConnectionManager (VA 0x2ce8c):<br>Status 7 - 1 = Index 6 -> String 'Invalid USIM'"]
        J --> K["Web UI displays: 'Invalid USIM'<br>Data Call Activation Blocked"]
    end
```

### Direct Technical Explanations of Confirmed Observations:
- **`AT+CPIN?` $\rightarrow$ `+CME ERROR: SIM busy`:** In Qualcomm ATCoP (`dsat`), when the USIM application is held in `CHECK_PERSONALIZATION_STATE` and subscription activation is halted, ATCoP returns numeric error 14 (`DSAT_CME_SIM_BUSY`).
- **IMSI read failure:** Under 3GPP TS 31.102, elementary file `EF_IMSI` (`6F07`) requires the USIM application to reach `READY` state (`app_state == 7`). Access is refused in State 4.
- **`AT$QCSIMSTAT?` $\rightarrow$ `0,UNKNOWN`:** Return code `0` represents `SIM_INIT_NOT_COMPLETE`.
- **`AT^SYSINFO` $\rightarrow$ `1,0,1,9,255` & `^CARDMODE` $\rightarrow$ `255`:** State `255` represents no valid subscription / invalid card mode.
- **Web UI $\rightarrow$ `"Invalid USIM"`:** `libqcmap_cm.so.1` decodes QMI UIM Message 47 (`QMI_UIM_GET_CARD_STATUS`). When `card_state == 1` (`PRESENT`) and `app_state == 4` (`CHECK_PERSONALIZATION_STATE`), it returns status code **7**. `QCMAP_ConnectionManager` maps status 7 directly to `"Invalid USIM"`.

---

## 3. Subsystem Audits & Evidence Evaluation

### 3.1. `pdc_daemon` (Persistent Device Configuration Daemon)
- Disassembly of `/usr/bin/pdc_daemon` confirms it connects exclusively to the Qualcomm QMI PDC service (`pdc_get_service_object_v01`).
- It has **zero references** to UIM, MMGSDI, PIN, or SIM status.
- It exists solely to inspect `/firmware/image/<carrier_desc>/` if multi-carrier firmware packages are installed. On this router, `/firmware/image/` contains only static stock firmware dated July 2017; no carrier directories exist.
- Live inspection of `/data/log/pdclg.txt` confirms `pdc_daemon` registered indications and received **zero configuration change events**. It is completely inert and has no link to the SIM failure.

### 3.2. EFS2 Backup Audit (`analysis/efs_backup/`)
- **`/nv/item_files/modem/uim/mmgsdi/rpm_iccid` (30 bytes):** Contains raw BCD `981930907139205629f2...`, decoding to Jio factory ICCID **`8991030917930265922...`**. This proves the modem maintains persistent hardware binding to Reliance Jio.
- **`/nv/item_files/modem/uim/mmgsdi/halt_subscription`:** Confirmed **absent** (`error: 2` / `ENOENT`). Disassembly of `mmgsdi_card_init.c` proves that when this file is absent, MMGSDI emits `Halt subscription config read failed. Sending perso evt with DONE status`, which behaves identically to a file with value `0x00`. It is **not** the cause of restriction.

### 3.3. AMTelecom TLMP Logic & `DAT_84445322`
- In `modem_full.elf`, `amt_mmgsdi_card_type_check` (`0x8333d1b4`) contains AMTelecom's hardcoded PLMN table (MCC 405, MNCs 854..874). If unmatched, it logs `[AMT_CP]TLMP ON : not matched MCC MNC` and sets `card_context + 0x9 = 0`.
- However, both `amt_check_carrier_restriction_8333cf00` (`0x8333cf14`) and `amt_mmgsdi_card_type_check` (`0x8333d1d0`) test `DAT_84445322 == 1`. If not `1`, both functions completely bypass the restriction.
- `DAT_84445322` resides in `.bss` (Segment 18) and defaults to `0x00`. No static compiled store instructions write to it. If this check is active on physical hardware, `DAT_84445322` must be populated dynamically across the AP-to-DSP boundary during Linux system startup.

### 3.4. Qualcomm Native Personalization Engine (NV 2666 / 2672 / 947)
- Qualcomm baseband includes its standard 3GPP TS 22.022 personalization engine configured via **NV Item 2666 (`NV_SIM_LOCK_POLICY_I`, `0x0a6a`)** and **NV Item 2672 (`NV_SIM_LOCK_STATUS_I`, `0x0a70`)**.
- In `modem_full.elf` at `0x837c4798`, baseband checks NV 947 (`NV_GPRS_ANITE_GCF_I`, `0x03b3`). If NV 947 == 1, it sets `DAT_84abedf8 = 0`, bypassing Qualcomm native carrier checks.
- Direct read-only DIAG queries on the live hardware confirmed **NV 947 is `0`**. Therefore, Qualcomm native carrier validation is fully active.

---

## 4. Ranked Hypotheses

| Rank | Hypothesis | Confidence | Supporting Evidence | Contradicting / Missing Evidence |
| :---: | :--- | :---: | :--- | :--- |
| **1** | **Qualcomm Native SIM Lock (NV 2666 / 2672 Active)** | **High** | 1. QMI reports `card_state = 1` and `app_state = 4` (`CHECK_PERSO`).<br>2. Modem NV 947 is confirmed `0` on live device.<br>3. `rpm_iccid` in EFS contains factory Jio ICCID.<br>4. Does not require unproven runtime RAM writes. | NV 2666 policy bytes have not yet been read via DIAG. |
| **2** | **AMTelecom TLMP Lock Active via Runtime Injection (`DAT_84445322 = 1`)** | **Medium** | 1. `amt_mmgsdi_card_type_check` contains exact Jio MNC table.<br>2. Unmatched PLMN transitions directly to `PERSO_REQ` (`app_state = 10`), matching WebUI `Invalid USIM`. | `DAT_84445322` defaults to `0` in `.bss`; no static stores exist in modem ELF. |
| **3** | **Missing EFS Subscription Handshake** | **Low** | 1. `/nv/item_files/modem/uim/mmgsdi/halt_subscription` is absent. | Static analysis proves absent file emits `perso evt with DONE`, identical to `0x00`. Does not halt. |
| **4** | **PDC Daemon Misconfiguration** | **Ruled Out** | None. | `pdc_daemon` has no UIM/SIM references; logs show zero activity. |
| **5** | **Physical SIM Contact / Voltage Incompatibility** | **Ruled Out** | None. | `card_state` is confirmed `1` (`PRESENT`). If electrical contact failed, state would be `ABSENT` (`0`) or `ERROR` (`2`). |

---

## 5. Safest Supported Diagnostic Step

To definitively distinguish between Hypothesis 1 (Qualcomm Native Lock) and Hypothesis 2 (AMTelecom TLMP Lock), the single most useful, non-intrusive diagnostic experiment is:

### Perform a Read-Only NV Item 2666 & 2672 Query via USB DIAG Interface
- **Interface:** USB Interface 2 (Qualcomm DIAG endpoint `1ecb:02e1`, EP `0x02` OUT / `0x83` IN).
- **Protocol Command:** Standard Qualcomm DIAG Command `0x26` (`DIAG_NV_READ_F`).
- **Target Items:**
  - NV Item 2666 (`0x0a6a`, `NV_SIM_LOCK_POLICY_I`): 132 bytes.
  - NV Item 2672 (`0x0a70`, `NV_SIM_LOCK_STATUS_I`): Lock status and retry counters.
- **Safety:** 100% read-only command. Uses the exact same QCDM diagnostic mechanism previously used to safely read NV 947. Zero writes to device flash.
- **Distinguishing Criteria:**
  - **If NV 2666 contains an active policy lock (Category 1 Network Lock enabled):** Hypothesis 1 is conclusively proven. The failure is standard Qualcomm 3GPP TS 22.022 carrier personalization.
  - **If NV 2666 returns all categories unlocked (`0x00`):** Hypothesis 2 is proven. The failure is driven by AMTelecom's proprietary TLMP overlay populated at runtime.

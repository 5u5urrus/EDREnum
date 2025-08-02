# EDREnum

**EDREnum** is an advanced, stealthy EDR detection tool for Windows. It leverages low-level NT API calls and a comprehensive database of known EDR signatures to enumerate endpoint detection and response products running on a system.

---

## Features

* **Stealth Detection:** Uses direct NT API calls (`NtQuerySystemInformation`) to enumerate processes and loaded drivers without invoking high-level Windows APIs.
* **EDR Registry Scanning:** Scans for known EDR-related registry keys.
* **Extensive Signature Database:** Contains verified process, driver, and registry signatures for 30+ enterprise-grade EDR products, including:

  * Microsoft Defender for Endpoint
  * CrowdStrike Falcon
  * SentinelOne
  * Carbon Black
  * Palo Alto Cortex XDR
  * Sophos Intercept X
  * And many more...
* **Compact & Fast:** Minimal dependencies and efficient memory use for fast enumeration.
* **Detection Summary:** Consolidated output listing all matched EDR signatures across process, driver, and registry layers.

---

## Build Instructions

Compile using the **Microsoft C++ (MSVC) command-line compiler**:

```cmd
cl edrenum.c
```

This will output `edrenum.exe` in the same directory.

---

## Usage

```bash
edrenum.exe
```

No arguments required. The tool will perform:

* Process enumeration
* Driver enumeration
* Registry key checks

Example output:

```
===================================================
    Enhanced Stealthy EDR Enumeration Tool v2.1
    NT API + Registry Detection + Expanded Database
===================================================

[+] Starting Enhanced Stealthy EDR Enumeration...

[*] Enumerating processes via NT API...
    EDR Product                         Type       Component                 PID
    --------------------------------------------------------------------------------
    Microsoft Defender                  Process    MsMpEng.exe               5200
    Microsoft Defender                  Process    MpDefenderCoreService.exe 5472
    Microsoft Defender                  Process    NisSrv.exe                15016

[*] Enumerating drivers via NT API...
    EDR Product                         Type       Component                 Base Address
    --------------------------------------------------------------------------------
    Microsoft Defender                  Driver     WdFilter.sys              0x0000000000000000
    Microsoft Defender                  Driver     WdNisDrv.sys              0x0000000000000000

[*] Checking registry signatures...
    EDR Product                         Type       Registry Key
    --------------------------------------------------------------------------------
    Microsoft Defender                  Registry   HKLM\SOFTWARE\Microsoft\Windows Defender
    Microsoft Defender                  Registry   HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection
    Microsoft Defender                  Registry   HKLM\SYSTEM\CurrentControlSet\Services\WinDefend
    Microsoft Defender                  Registry   HKLM\SYSTEM\CurrentControlSet\Services\Sense

===============================================
               DETECTION SUMMARY
===============================================

[!] Microsoft Defender (Microsoft Corporation)
    └─ Processes: 3 detected
    └─ Drivers:   2 detected
    └─ Registry:  4 detected

===============================================
Total EDR products detected: 1
===============================================

[*] Enumeration complete
```


---

## Included Detection Tiers

* **Tier 1:** Major enterprise EDRs (CrowdStrike, SentinelOne, Carbon Black, etc.)
* **Tier 2:** AV products with EDR capabilities (ESET, Bitdefender, McAfee, etc.)
* **Tier 3:** Specialized and regional EDRs (FireEye, Fortinet, Cisco AMP, etc.)
* **Tier 4:** SMB and consumer solutions (Avast, AVG, Comodo, etc.)
* **Monitoring Tools:** Sysmon, Elastic, Splunk Forwarder

---

## How It Works

EDREnum compares discovered:

* **Running processes**
* **Loaded kernel drivers**
* **Registry keys**

against a database of known EDR fingerprints.

By using `NtQuerySystemInformation`, it avoids suspicious API calls typically monitored by user-mode hooks or AVs.

---

## Notes

* Detection does **not guarantee** that an EDR is fully functional—only that artifacts were found.
* Absence of detection does **not guarantee** the system is unmonitored (e.g., unknown or custom EDRs).
* This tool is intended for **educational and authorized red team** use only.

---

## Legal

> This tool is provided for educational and authorized security testing purposes only.
> The author is not responsible for misuse or damages caused by this tool.
> Always ensure you have proper authorization before scanning systems.

---

## License

MIT License

---

## Author

**Vahe Demirkhanyan**

## Credits

Inspired by [`EnumEDR-s`](https://github.com/0xJs/EnumEDR-s) by [0xJs](https://github.com/0xJs), and this program was in turn inspired by [EvasionLab](https://www.alteredsecurity.com/evasionlab) by Altered Security.

# Detect WerFault/WerFaultSecure used to freeze EDR processes

## Detection KQL Query
```kusto
let lookback = 14d;
let edr_images = dynamic([
  "mssense.exe","senseir.exe","msmpeng.exe","nissrv.exe",   // Microsoft Defender
  "csfalconservice.exe",  // CrowdStrike
  "sentinelagent.exe","sentinelhelperservice.exe",   // SentinelOne
  "repsvc.exe","repux.exe",   // Carbon Black
  "elastic-endpoint.exe",  // Elastic
  "sophosfs.exe","sophosrtpservice.exe","sophosedr.exe","sophomcsclient.exe",   // Sophos
  "tmccsf.exe",   // Trend Micro
  "avp.exe","kavfs.exe",   // Kaspersky
  "bdservicehost.exe",   // Bitdefender
  "ekrn.exe",   // ESET
  "xagt.exe","taniumclient.exe","qualysagent.exe"   // Others (XDR/IT hygiene often protected)
]);
// 1) Find werfault/werfaultsecure launching with /pid and extract target PID/TID
let wer_invocations =
    DeviceProcessEvents
    | where Timestamp >= ago(lookback)
    | where FileName in~ ("WerFaultSecure.exe","WerFault.exe")
    | where ProcessCommandLine has "/pid"
    | extend TargetPid = toint(extract(@"(?i)/pid\s+(\d+)", 1, ProcessCommandLine))
    | extend TargetTid = toint(extract(@"(?i)/tid\s+(\d+)", 1, ProcessCommandLine))
    | where TargetPid > 0
    | project
        WER_Time=Timestamp,
        DeviceId, DeviceName,
        WER_Image=FileName,
        WER_CommandLine=ProcessCommandLine,
        TargetPid, TargetTid,
        InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessCommandLine,
        ReportId;
// 2) Join the target PID to its process creation to learn what was being dumped
wer_invocations
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp >= ago(1d)
    | where ActionType == "ProcessCreated"
    | project
        TargetProcessStartTime=Timestamp,
        DeviceName,
        TargetProcessId=ProcessId,
        TargetProcessImage=FileName,
        TargetProcessCmd=ProcessCommandLine
) on $left.DeviceName == $right.DeviceName and $left.TargetPid == $right.TargetProcessId
// 3) Ensure the target process existed before the WER call
| where isnull(TargetProcessStartTime)
      or (TargetProcessStartTime <= WER_Time and WER_Time - TargetProcessStartTime < 7d)
// 4) Flag if the target is an EDR process
| extend TargetProcessImage_l = tolower(TargetProcessImage)
| extend IsEDR = iff(isnotempty(TargetProcessImage_l)
                     and array_index_of(edr_images, TargetProcessImage_l) != -1, true, false)
// 5) Final Result
| where IsEDR == 1
| project
    WER_Time, DeviceName,
    WER_Image, WER_CommandLine,
    TargetPid, TargetTid,
    TargetProcessImage, TargetProcessCmd, TargetProcessStartTime,
    IsEDR,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    ReportId
| order by WER_Time desc

````
## Description

Recent research shows adversaries can abuse Windows Error Reporting to suspend or dump security tools by launching **WerFaultSecure.exe** with undocumented switches against a target PID. Because WerFaultSecure runs with **Protected Process Light (PPL)** privileges and uses **MiniDumpWriteDump** (which suspends all target threads while dumping), an attacker can race-suspend WerFaultSecure and leave the EDR or AV process “frozen,” degrading telemetry and prevention. Public PoC tooling (**EDR-Freeze**) and helper loaders (**CreateProcessAsPPL**) make this practical on modern Windows builds, including Windows 11 24H2.

---
### Query Illustration
- Pivot on **WerFault.exe** or **WerFaultSecure.exe** launching with a `/pid` argument.
- Correlate that PID to a process creation event to identify the targeted image.
- Flag if the resolved image matches a curated list of common **EDR/AV binaries**.
- Behavior is rare in ordinary crash reporting and aligns with **EDR-Freeze** tradecraft, including WerFaultSecure’s **PPL** context and **MiniDumpWriteDump** thread-suspension semantics.

---

## Possible Attack Scenario

* After admin/service-level foothold, adversary uses **CreateProcessAsPPL** to spawn **WerFaultSecure** as a protected process.

  * Points it at **MsMpEng.exe** or another EDR agent using `/pid` (and optional `/tid`).
  * As the dump starts, the attacker **suspends WerFaultSecure**, keeping the EDR’s threads halted to:

    * disable hooks,
    * harvest credentials,
    * operate hands-on-keyboard with reduced detection.
  * Variants may leverage legacy WerFaultSecure builds and undocumented flags.

---

## Suggested Investigation Steps

1. Review WerFault/WerFaultSecure command line; extract PID/TID & switches; confirm targeted image is EDR/AV.
2. Trace process tree for helpers like **CreateProcessAsPPL** or launchers with unusual token privileges.
3. Check for **EDR watchdog/heartbeat gaps**, sensor errors, or service logs near the timestamp.
4. Hunt for dump artifacts or **MiniDumpWriteDump** file handles; verify if target process resumed or stayed suspended.
5. Pivot across the estate for similar WerFaultSecure executions in the same window to assess spread/automation.

---

## Suggested Response Actions

* **Containment:** Isolate host; restore endpoint protections (restart services under change control or reboot if safe).
* **Eradication:** Block/quarantine tooling (CreateProcessAsPPL, EDR-Freeze binaries/scripts).
* **Credentials & Secrets:** Invalidate/rotate impacted credentials and secrets; review high-risk actions during freeze window.
* **Hardening:**

  * WDAC/AppLocker allow-listing to constrain WerFaultSecure execution context.
  * Alert on WerFaultSecure with parameters.
  * Tune EDR self-protection/watchdogs so sensor loss triggers immediate containment.

---

## Possible False Positives

* Legitimate crash-triage or vendor-guided support may run WerFault/WerFaultSecure with parameters.
* Targeting EDR/AV binaries is uncommon — validate via ticket/support context, developer machines, or controlled lab activity before escalation.

---

## Detection Blind Spots

* Focuses on WerFault/WerFaultSecure with `/pid`:

  * Adversaries may suspend EDR threads via other APIs (e.g., `NtSuspendProcess`) without WerFault.
  * Other undocumented WerFaultSecure args may be abused.
* If process-creation telemetry is missing or too narrowly scoped, the join may fail to resolve targets.
* Some EDRs rename processes or use watchdogs, reducing signal or shortening freeze windows.

---

## MITRE Technique

* [T1562 — Impair Defenses] https://attack.mitre.org/techniques/T1562/
* [T1218 — Signed Binary Proxy Execution] - https://attack.mitre.org/techniques/T1562/

---

## References

* https://www.zerosalarium.com/2025/09/EDR-Freeze-Puts-EDRs-Antivirus-Into-Coma.html "EDR-Freeze: A Tool That Puts EDRs And Antivirus Into A Coma State"
* https://github.com/TwoSevenOneT/CreateProcessAsPPL "CreateProcessAsPPL: run a program with PPL protection"
* https://github.com/TwoSevenOneT/EDR-Freeze "EDR-Freeze PoC"


# Detect DLL Hijacking / Side-Loading via Shadowed DLL Loads and Writable Path Abuse

## Detection KQL Query
```kusto
// DLL Hijacking / Side-Loading hunting rule
//
// Idea:
// 1) Learn which DLL names are normally loaded from Windows system locations (baseline).
// 2) Hunt recent loads where the SAME DLL name is loaded from non-system paths (shadowing).
// 3) Add strong signals: user-writable load paths, EXE from Program Files/Windows loading DLL from writable,
//    DLL loaded from same directory as EXE, unsigned DLL, rarity, and “recently written DLL then loaded”.
let lookbackRecent   = 1h;
let lookbackBaseline = 30d;
let WritablePathRegex = @"(?i)^c:\\users\\|^c:\\programdata\\|^c:\\windows\\temp\\|\\appdata\\|\\temp\\|\\downloads\\|\\desktop\\|\\public\\|\\onedrive\\";
let SystemDirRegex    = @"(?i)^c:\\windows\\(system32|syswow64|winsxs)\\";
let ProgramDirsRegex  = @"(?i)^c:\\windows\\|^c:\\program files\\|^c:\\program files \(x86\)\\";
let GetDir = (p: string) { replace_regex(tolower(p), @"\\[^\\]+$", "") };

let KnownSystemDllNames =
    DeviceImageLoadEvents
    | where Timestamp between (ago(lookbackBaseline) .. ago(lookbackRecent))
    | extend DllName = tolower(FileName), DllPath = tolower(FolderPath)
    | where DllName endswith ".dll"
    | where DllPath matches regex SystemDirRegex
    | summarize by DllName;

let BaselineLoadsTbl =
    DeviceImageLoadEvents
    | where Timestamp between (ago(lookbackBaseline) .. ago(lookbackRecent))
    | extend Device = coalesce(DeviceName, DeviceId)
    | extend ProcName = tolower(InitiatingProcessFileName)
    | extend ProcPath = tolower(InitiatingProcessFolderPath)
    | extend DllName  = tolower(FileName)
    | extend DllPath  = tolower(FolderPath)
    | where DllName endswith ".dll"
    | summarize BaselineLoads=count() by Device, ProcName, ProcPath, DllName, DllPath;

let FileContext =
    DeviceFileEvents
    | where Timestamp > ago(lookbackBaseline)
    | where ActionType in ("FileCreated", "FileRenamed", "FileModified", "FileCreatedFromCompressedFile", "FileCreatedFromNetworkShare")
    | extend DllName = tolower(FileName), DllPath = tolower(FolderPath)
    | where DllName endswith ".dll"
    | summarize
        DllFileFirstSeen=min(Timestamp),
        DllFileLastSeen=max(Timestamp),
        DllFileActions=make_set(ActionType, 10),
        DllWriterProcs=make_set(InitiatingProcessFileName, 10),
        DllWriterCmds=make_set(InitiatingProcessCommandLine, 5)
        by DllName, DllPath, DllSHA256=SHA256;

DeviceImageLoadEvents
| where Timestamp > ago(lookbackRecent)
| extend Device = coalesce(DeviceName, DeviceId)
| extend ProcName = tolower(InitiatingProcessFileName)
| extend ProcPath = tolower(InitiatingProcessFolderPath)
| extend DllName  = tolower(FileName)
| extend DllPath  = tolower(FolderPath)
| extend ProcDir = GetDir(ProcPath)
| extend DllDir  = GetDir(DllPath)
| extend
    DllSigStatus  = tostring(column_ifexists("SignatureStatus", "")),
    DllSigner     = tostring(column_ifexists("Signer", "")),
    ProcSigStatus = tostring(column_ifexists("InitiatingProcessSignatureStatus", "")),
    ProcSigner    = tostring(column_ifexists("InitiatingProcessSigner", ""))
| extend
    ProcCmd    = InitiatingProcessCommandLine,
    ProcSHA256 = InitiatingProcessSHA256,
    DllSHA256  = SHA256
| where DllName endswith ".dll"
| extend IsSystemDllPath       = DllPath matches regex SystemDirRegex
| extend IsWritableDllPath     = DllPath matches regex WritablePathRegex
| extend IsProcInProgramDirs   = ProcPath matches regex ProgramDirsRegex
| extend IsSameDir             = (DllDir == ProcDir)
| extend IsShadowingSystemName = (DllName in (KnownSystemDllNames) and not(IsSystemDllPath))
| extend HasDllSigData         = isnotempty(DllSigStatus) or isnotempty(DllSigner)
| extend HasProcSigData        = isnotempty(ProcSigStatus) or isnotempty(ProcSigner)
| extend DllUnsignedOrUnknown  = iff(HasDllSigData, DllSigStatus !in~ ("Signed", "Valid"), false)
| extend ProcMicrosoftSigned   = iff(HasProcSigData, (ProcSigStatus in~ ("Signed", "Valid") and ProcSigner has "Microsoft"), false)
| extend CrossDirStrong        = (IsProcInProgramDirs and IsWritableDllPath)
| extend Score =
    toint(IsShadowingSystemName) +
    toint(IsWritableDllPath) +
    toint(IsSameDir) +
    toint(CrossDirStrong) +
    toint(DllUnsignedOrUnknown) +
    toint(ProcMicrosoftSigned)
| where Score >= 2
    or IsShadowingSystemName
    or CrossDirStrong
    or (IsSameDir and IsWritableDllPath)
| join kind=leftouter BaselineLoadsTbl on Device, ProcName, ProcPath, DllName, DllPath
| join kind=leftouter FileContext on DllName, DllPath, DllSHA256
| extend BaselineLoads = coalesce(BaselineLoads, 0)
| extend MinutesSinceLastWrite = iff(isnotempty(DllFileLastSeen), datetime_diff("minute", Timestamp, DllFileLastSeen), long(null))
| where BaselineLoads <= 2 or (isnotempty(MinutesSinceLastWrite) and MinutesSinceLastWrite between (0 .. 180))
| extend ReasonSet = pack_array(
                         iff(IsShadowingSystemName, "ShadowingSystemDllName", ""),
                         iff(IsWritableDllPath, "LoadedFromWritablePath", ""),
                         iff(CrossDirStrong, "ProcInWindowsOrProgramFiles_LoadedDllFromWritable", ""),
                         iff(IsSameDir, "LoadedFromExeDirectory", ""),
                         iff(DllUnsignedOrUnknown, "DllUnsignedOrUnknown", ""),
                         iff(ProcMicrosoftSigned, "ProcMicrosoftSigned", ""),
                         iff(isnotempty(MinutesSinceLastWrite) and MinutesSinceLastWrite between (0 .. 180), "DllRecentlyWrittenThenLoaded", ""),
                         strcat("BaselineLoads=", tostring(BaselineLoads))
                     )
| mv-apply r = ReasonSet on (
    where r != ""
    | summarize ReasonSet = make_set(r, 20)
    )
| project
    Timestamp,
    DeviceName,
    AccountName=InitiatingProcessAccountName,
    ProcName=InitiatingProcessFileName,
    ProcPath=InitiatingProcessFolderPath,
    ProcCmd,
    ProcSHA256,
    DllName=FileName,
    DllPath=FolderPath,
    DllSHA256,
    DllSigStatus,
    DllSigner,
    BaselineLoads,
    DllFileLastSeen,
    DllFileActions,
    DllWriterProcs,
    MinutesSinceLastWrite,
    Score,
    ReasonSet
| order by Score desc, BaselineLoads asc, Timestamp desc
```

## Description

Adversaries frequently abuse the Windows DLL search order to execute malicious code by planting a rogue DLL with the same name as a legitimate dependency in a location that is searched before the intended system directory. When a trusted or Microsoft-signed executable loads this shadowed DLL, attacker-controlled code executes within a trusted process context, enabling defense evasion, persistence, or privilege escalation. This detection identifies such abuse by learning normal DLL load behavior and flagging deviations that strongly align with real-world DLL hijacking and side-loading tradecraft.

---

### Query Illustration

- Build a **baseline** of DLL names normally loaded from trusted system directories (System32, SysWOW64, WinSxS).
- Detect **shadowing** where the same DLL name is loaded from a non-system or user-writable path.
- Increase confidence when:
  - DLLs load from **user-writable directories**
  - Trusted or Microsoft-signed binaries load DLLs from writable paths
  - DLL loads occur from the **same directory as the executable**
  - DLLs are **unsigned or have invalid signatures**
  - DLLs are **rare** for the device/process baseline
  - DLLs are **recently written** immediately before loading

---

## Possible Attack Scenario

* After initial access, an adversary drops a malicious DLL named identically to a legitimate Windows system DLL into a user-writable directory such as AppData or Downloads.

  * A trusted application from Program Files is launched or abused.
  * Due to the Windows DLL search order, the malicious DLL is loaded instead of the legitimate system DLL.
  * The attacker executes code under a trusted process context without introducing a new executable.
  * The technique supports persistence, privilege escalation, or stealthy post-exploitation activity.

---

## Suggested Investigation Steps

1. Confirm whether the DLL name matches a known Windows system DLL and validate the expected legitimate load path.
2. Review DLL digital signature status, signer, and hash reputation.
3. Analyze file creation and modification timestamps to identify recent writes prior to execution.
4. Inspect the initiating process command line, parent process, and trust level.
5. Determine whether loading the DLL from the observed path is expected application behavior.
6. Pivot on the DLL hash and file path across the environment to identify additional abuse.

---

## Suggested Response Actions

* **Containment:** Isolate the affected endpoint if malicious behavior is confirmed.
* **Eradication:** Quarantine or delete the malicious DLL and block its hash across endpoint controls.
* **Root Cause:** Identify how the attacker achieved write access to the directory.
* **Hardening:**
  * Restrict write permissions on sensitive directories.
  * Monitor for DLL shadowing patterns across the estate.
  * Apply application allow-listing where feasible.

---

## Possible False Positives

* Legitimate third-party software that ships DLLs alongside executables.
* Custom or internally developed applications using non-standard DLL load paths.
* Software updates or installers temporarily writing DLLs before execution.

---

## Detection Blind Spots

* DLL hijacking occurring entirely within trusted system directories.
* Signed but malicious DLLs using valid certificates.
* Environments lacking full DLL load or file creation telemetry.

---

## MITRE Technique

* **T1574.001 – DLL Search Order Hijacking**  
  https://attack.mitre.org/techniques/T1574/001/

---

## References

* https://attack.mitre.org/techniques/T1574/001/ "DLL Search Order Hijacking"
* https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order "Windows DLL search order documentation"
* https://omartarekzayed.medium.com/why-baselining-is-the-missing-piece-in-dll-hijacking-detections-771545f1505c "Why “baselining” is the missing piece in DLL hijacking detections"


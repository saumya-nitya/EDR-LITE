# EDR-Lite Development Log

A phase-by-phase record of how this project was built, what decisions were made along the way, and what went wrong before things went right. Written partly as documentation, partly as a reference for anyone trying to understand why certain choices were made over more obvious alternatives.

---

## Background

The goal from the start: build something that doesn't just *monitor* file changes, but actually knows *which process* caused them, and responds automatically. That distinction - attribution, not just observation - is what separates a file integrity monitor from something that can actually claim to do endpoint detection.

C# was a deliberate choice. It has native access to Windows-specific APIs (ETW, WMI, the process table) that would require workarounds or gaps in other languages. Real EDR products are largely written in C++ or C# for exactly this reason. This was also my first C# project.

---

## Phase 1 - Project Setup

Nothing unusual here. .NET 10 SDK installed, console app scaffolded with `dotnet new console`.

One thing worth noting for anyone new to C#: modern .NET projects use top-level statements by default, so the generated `Program.cs` is just:

```csharp
Console.WriteLine("Hello, World!");
```

No explicit `class`, no `Main` method visible. The compiler wraps it automatically. This threw me for a second coming from languages where entry points are always explicit - but it's just syntactic sugar, nothing structural changes underneath.

---

## Phase 2 - File Watcher

First working component: `FileSystemWatcher`, a built-in .NET class that hooks into Windows' native file system change notifications (`ReadDirectoryChangesW` under the hood). Event-driven rather than polling, which matters for a tool like this - polling would add CPU overhead and latency on every change.

The implementation went smoothly. Three event handlers (`FileIOCreate`, `FileIOWrite`, `FileIORename`), a test folder, and a simple console print per event. One quirk that showed up immediately during testing: a single file save triggers multiple `Changed` events - one for the content write, one for the metadata update (last-write timestamp). This is a Windows file system behavior, not a bug in the watcher. It matters later for Phase 5 because a naive event count would double-count writes and skew the detection threshold.

### Why FileSystemWatcher wasn't enough

`FileSystemWatcher` tells you what changed and when. It doesn't tell you which process caused the change. That's a hard limitation - there's no property on the event args, no workaround, it's just not information the API surfaces. For a file integrity monitor that's fine. For something trying to kill the process doing the damage, it's a dealbreaker.

This realization pushed the project toward ETW, which came later in Phase 4.

---

## Phase 3 - Process Monitoring

Goal: enumerate running processes and their parent-child relationships. C#'s built-in `System.Diagnostics.Process` class handles basic process listing, but it doesn't expose parent process information directly - that requires WMI (`System.Management` package, added via NuGet).

WMI queries look like SQL against the OS:

```csharp
new ManagementObjectSearcher("SELECT ProcessId, ParentProcessId, Name, ExecutablePath FROM Win32_Process")
```
This returns a flat list of every running process with its parent PID. To make the parent-child relationships queryable, the flat list gets restructured into a `Dictionary<int, List<ProcessInfo>>` mapping each parent PID to its children - then a recursive `PrintNode` method walks the tree and prints it indented.

Running this on a live machine produced something like:

    - System (PID: 4)
      - smss.exe (PID: 944)
      - services.exe (PID: 1472)
        - svchost.exe (PID: 1656)
          - RuntimeBroker.exe (PID: 16480)
          - SearchHost.exe (PID: 4488)
        - MsMpEng.exe (PID: 5124)
        ...
    - explorer.exe (PID: 20920)
      - Code.exe (PID: 2316)
        - powershell.exe (PID: 26644)
          - dotnet.exe (PID: 16116)
            - EdrLite.exe (PID: 27344)

EDR-Lite showing up at the bottom of its own process tree was a good sanity check that the parent-child logic was correct.

One real-world quirk: some processes show up as roots even when they're not actually top-level - their parent process already exited, so the PPID points to a PID that no longer exists in the running process list. The root-detection logic handles this correctly: "if your parent PID isn't in our list, you're a root," which covers both genuinely top-level processes and orphaned ones.


One CA1416 warning showed up from the compiler here and repeats throughout the project:
warning CA1416: 'ManagementObjectSearcher' is only supported on: 'windows'

This is the compiler flagging that WMI is Windows-only while the project targets the cross-platform .NET runtime. Since EDR-Lite is explicitly a Windows security tool, the fix is adding `<TargetFramework>net10.0-windows</TargetFramework>` to the `.csproj`. The warnings don't block anything - the project runs fine - but they're worth acknowledging rather than ignoring silently.

## Phase 4 - ETW Correlation

This is the core of the project and the part that took the most work to get right.

### What ETW is

ETW (Event Tracing for Windows) is a kernel-level logging system built into Windows. It works on providers (sources of events) and keywords (categories within a provider). Unlike `FileSystemWatcher`, kernel file I/O events through ETW carry the triggering PID directly - no guessing, no timing heuristics, no approximation. This is the same mechanism Sysinternals Process Monitor and real EDR products use under the hood.

The .NET wrapper for this is `Microsoft.Diagnostics.Tracing.TraceEvent`, added via NuGet:

```powershell
dotnet add package Microsoft.Diagnostics.Tracing.TraceEvent
```

### The FileKey problem

The first real technical obstacle: ETW's `FileIOWrite` event doesn't carry a filename. It carries a `FileObject` - an opaque handle reference the kernel uses internally to track open file handles. The filename only appears on `FileIOCreate` (when the file handle is first opened).

The fix is a lookup table: whenever a `FileIOCreate` fires, cache the mapping (`FileObject -> filename`). When a `FileIOWrite` comes in with just a `FileObject`, look it up in that cache to recover the actual path. This is the standard approach for ETW file monitoring - the kernel doesn't repeat the filename on every write for performance reasons, so you have to maintain the mapping yourself.

```csharp
private readonly Dictionary<ulong, string> _fileKeyToName = new();

// on CREATE:
_fileKeyToName[data.FileObject] = data.FileName;

// on WRITE:
if (_fileKeyToName.TryGetValue(data.FileObject, out var fileName))
{
    // now we have the filename
}
```

### Casing mismatches in TraceEvent

The first build attempt failed with:
error CS1061: 'KernelTraceEventParser' does not contain a definition for 'FileIoCreate'
The actual property name is `FileIOCreate` - fully uppercase `IO`, not Pascal-cased `Io`. Same for `FileIORename` and `FileIOWrite`. The TraceEvent library is inconsistent about this across its API surface, so the only way to find it is to hit the compiler error and check. Not a hard fix, but worth documenting since it's not obvious from the method signatures alone.

### Path filtering

Without filtering, ETW captures file I/O for the entire system - every browser cache write, every Windows background service, everything. The first unfiltered run produced hundreds of lines per second of unrelated noise. The fix is straightforward: check whether each event's filename starts with the target watch path before doing anything with it.

```csharp
private bool IsInWatchPath(string fileName)
{
    if (string.IsNullOrEmpty(fileName)) return false;
    return fileName.ToLowerInvariant().StartsWith(_watchPath);
}
```

Lowercasing both sides before comparing handles the case where Windows reports paths with inconsistent capitalization (which it does, fairly often).

### The Smart App Control block

After getting the ETW code compiling and filtering correctly, running it produced a different kind of failure:
Unhandled exception. System.IO.FileLoadException: Could not load file or assembly 'EdrLite.dll'.
An Application Control policy has blocked this file. (0x800711C7)

This wasn't a code error - Windows Smart App Control was blocking the compiled binary from loading at all. Smart App Control is a Windows 11 security feature that blocks unsigned, unrecognized executables from running, and an unsigned binary doing kernel-level file monitoring is exactly the kind of thing it's designed to be suspicious of.

The debugging path here went longer than it needed to. Initial steps (checking Protection History, looking for a "allow this file" option) came up empty. The next attempt was setting up a Windows VM in VirtualBox to run the project in an isolated environment where Smart App Control wouldn't apply.

### The VirtualBox detour

Setting up a VM turned into its own debugging session:

- First boot attempt: black screen, VM frozen at EFI stage `DXE_AP` / `PciHostBridgeDxe.efi`
- Root cause investigation via VBox.log revealed `VMX - Virtual Machine Extensions = 0 (0)` - VirtualBox couldn't access hardware virtualization extensions
- Identified two likely causes: `Virtual Machine Platform` (a Windows feature) conflicting with VirtualBox's hypervisor access, and `Core Isolation / Memory Integrity` doing the same
- Disabled both, restarted - VM still froze at the same EFI stage
- Log confirmed the freeze point hadn't changed: last entry still `EFI: debug point DXE_AP`
- Switched paravirtualization interface from Default/Hyper-V to KVM - no change
- Further investigation revealed `Core Isolation (Memory Integrity): ENABLED` in the VBox.log CPUID dump, suggesting VT-x still wasn't fully accessible despite the earlier changes

At this point the VM approach was costing more time than it was worth. Stepping back and checking the Windows build number (26200.8655) confirmed that this build supports the newer reversible Smart App Control toggle - meaning SAC could be turned off, the project tested, and SAC turned back on, without any permanent system change.

That's what ended up working. One toggle, one `dotnet run`, and the ETW session started cleanly. The VM detour was unnecessary in retrospect, but the VBox.log debugging was a useful exercise in reading low-level boot diagnostics.

### Verified output after filtering

Once SAC was off and the path filter in place, the output was clean:

    ETW session started. Watching: e:\vs code projects\edr-lite\test-folder
    [CREATE] PID=2316 File=E:\VS CODE projects\edr-lite\test-folder\test2.txt
    [WRITE]  PID=2316 File=E:\VS CODE projects\edr-lite\test-folder\test2.txt
    [RENAME] PID=2316 File=E:\VS CODE projects\edr-lite\test-folder\test2.txt

PID 2316 is VS Code - it was touching the test file while it was open in the editor. This is exactly the kind of legitimate but noteworthy attribution that `FileSystemWatcher` alone could never provide.

---

## Phase 5 - Detection Logic

### The sliding window

The detection rule: if a single process generates 20 or more file events within any 5-second window, flag it as suspicious.

This is implemented as a sliding window in `ActivityTracker`. For each PID, a list of event timestamps is maintained. On every new event:

1. Add the current timestamp to that PID's list
2. Remove any timestamps older than 5 seconds
3. Check if the remaining count is >= 20

```csharp
public bool RecordActivity(int pid)
{
    var now = DateTime.Now;

    if (!_activityByPid.ContainsKey(pid))
        _activityByPid[pid] = new List<DateTime>();

    var timestamps = _activityByPid[pid];
    timestamps.Add(now);
    timestamps.RemoveAll(t => now - t > _windowSize);

    return timestamps.Count >= _thresholdCount;
}
```

This pattern - "keep only recent items, discard old ones, count what remains" - is a standard approach for rate-based detection. The same logic applies to brute force detection, DDoS mitigation, and API rate limiting. The specific numbers (20 events, 5 seconds) were chosen to be clearly triggerable by the demo script while being well above what normal IDE background activity generates.

### First detection test

Testing with a rapid file creation loop:

```powershell
for ($i=1; $i -le 25; $i++) { echo "x" > "test-folder\rapid$i.txt" }
```

Output confirmed the detection fired correctly - at file 10-11 (since each file generates both a `CREATE` and `WRITE` event, 10 files = 20 events = threshold), the alert triggered and continued firing on every subsequent event.

One thing the first test made obvious: without a "respond once per PID" guard, the alert fires on every single event past the threshold, not just the first crossing. That's addressed in Phase 6.

### Duplicate event noise

The double-`Changed` behavior from Phase 2 shows up again here. A single file write from the PowerShell loop consistently generated two ETW events per file - one `CREATE` (opening the file handle) and one `WRITE` (the actual content). This actually works in favor of detection sensitivity: 10 files = 20 events = threshold crossed. If the double-counting is ever a problem (i.e., it causes too many false positives at lower thresholds), deduplication logic on the `FileObject` within a short time window would address it.

## Phase 6 - Automated Response

### Killing the process

Once a PID crosses the detection threshold, the response is straightforward: terminate the process using `System.Diagnostics.Process.Kill()`.

```csharp
var process = Process.GetProcessById(pid);
string processName = process.ProcessName;
process.Kill();
```

`GetProcessById` looks up the live process by PID - the same number that's been flowing through the event handlers from the start. `Kill()` is the equivalent of "End Task" in Task Manager, immediate and unconditional.

### Respond once per PID

The first test of Phase 5 made clear that without a guard, the alert and response logic fires on every event past the threshold - not just the first crossing. For logging that's just noise, but for process termination it's a real problem: calling `Kill()` on an already-dead process throws an exception, and spamming kill attempts on a PID that hasn't died yet is just unnecessary churn.

The fix is a `HashSet<int>` tracking which PIDs have already been handled:

```csharp
private readonly HashSet<int> _respondedPids = new();

public void HandleSuspiciousActivity(int pid, string triggeringFile)
{
    if (_respondedPids.Contains(pid))
        return;

    _respondedPids.Add(pid);
    // ... alert and kill
}
```

First event past threshold for a given PID - handle it, add to the set. Every subsequent event for the same PID - return immediately. One response per process, regardless of how many more events come in after.

### Error handling

Two failure cases showed up in live testing:

**Case 1 - successful kill:**
ALERT: PID=15944 crossed suspicious threshold (triggered by ...sim_file_4.txt)
RESPONSE: Killed PID=15944 (powershell)

The demo script's PowerShell process, killed cleanly. The terminal window running the script closed immediately - confirmation the kill took effect.

**Case 2 - access denied:**
ALERT: PID=4 crossed suspicious threshold (triggered by ...sim_file_20.txt)
RESPONSE FAILED: Could not kill PID=4. Reason: Access is denied.

PID 4 is `System` - the Windows kernel process. Nothing can kill it, including an admin-elevated EDR tool. This is correct behavior from Windows' perspective - System is a protected process that sits outside the reach of normal process termination APIs regardless of privilege level.

Both cases are handled by wrapping the kill attempt in a `try/catch`:

```csharp
try
{
    process.Kill();
    _logger.Log($"RESPONSE: Killed PID={pid} ({processName})");
}
catch (Exception ex)
{
    _logger.Log($"RESPONSE FAILED: Could not kill PID={pid}. Reason: {ex.Message}");
}
```

The tool logs the failure and keeps running. A monitoring tool that crashes on its first protected process isn't useful.

### Side effect worth documenting

During testing, the demo script was run from VS Code's integrated terminal. EDR-Lite correctly identified that terminal's PowerShell process as the offending PID and killed it - which took VS Code's terminal panel down with it. The project files were untouched, but the integrated terminal session disappeared mid-run.

This isn't a bug. It's an expected consequence of running the attacker and the defender in the same shell environment. The fix is simple: run the demo script from a standalone PowerShell window rather than an IDE-embedded terminal, so the kill only takes down the simulation, not your working environment.

---

## Phase 7 - Logging

### Why persistent logging matters

Console output disappears when the terminal closes. For a security tool, that's a problem - the whole point of detection and response is having an audit trail of what happened and when. `Logger.cs` handles this by writing every event, alert, and response to `edr-lite.log` with a consistent timestamp format.

```csharp
public void Log(string message)
{
    string timestamped = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}";
    Console.WriteLine(timestamped);
    File.AppendAllText(_logFilePath, timestamped + Environment.NewLine);
}
```

`File.AppendAllText` opens the file, appends the line, and closes it - one call, no file handle to manage. Simple and correct for this use case. The same `Log()` call prints to console and writes to disk, so there's no divergence between what you see live and what gets persisted.

### What the log looks like

From an actual session:

    [2026-06-30 20:37:22] ETW session started. Watching: e:\vs code projects\edr-lite\test-folder
    [2026-06-30 20:37:36] [CREATE] PID=15944 File=E:\VS CODE projects\edr-lite\test-folder\sim_file_1.txt
    [2026-06-30 20:37:36] [WRITE]  PID=15944 File=E:\VS CODE projects\edr-lite\test-folder\sim_file_1.txt
    [2026-06-30 20:37:36] [RENAME] PID=15944 File=E:\VS CODE projects\edr-lite\test-folder\sim_file_1.txt
    [2026-06-30 20:37:36] ALERT: PID=15944 crossed suspicious threshold (triggered by ...sim_file_4.txt)
    [2026-06-30 20:37:36] RESPONSE: Killed PID=15944 (powershell)
    [2026-06-30 20:37:39] ALERT: PID=4 crossed suspicious threshold (triggered by ...sim_file_20.txt)
    [2026-06-30 20:37:39] RESPONSE FAILED: Could not kill PID=4. Reason: Access is denied.

The timestamp format (`yyyy-MM-dd HH:mm:ss`) is sortable lexicographically - useful if logs from multiple sessions ever get merged or parsed programmatically.

### Known limitation

`Logger` writes to disk on every single event. During the demo simulation (25 files, each generating multiple ETW events), this means dozens of disk writes in under two seconds. For a short demo session that's fine. For a long-running monitoring session on a busy machine, this would be a performance problem - production logging systems batch writes and flush on a timer rather than writing synchronously on every event. Worth noting as a design tradeoff, not something that affects the current use case.

---

## Phase 8 - Safe Demo Script

### Why a dedicated script

The manual PowerShell loop used during development:

```powershell
for ($i=1; $i -le 25; $i++) { echo "x" > "test-folder\rapid$i.txt" }
```

works, but it's not something you'd put in a README or run during a demo. `demo-ransomware-sim.ps1` formalizes the same behavior into something reusable, readable, and clearly documented as harmless.

### What it does

Creates 25 dummy `.txt` files in `test-folder/`, writes content to each, then renames them to `.locked` - mimicking the create-write-rename cycle real ransomware uses when encrypting files (the actual encryption step is just absent here, since the goal is triggering the file event pattern, not doing anything destructive).

```powershell
for ($i = 1; $i -le $fileCount; $i++) {
    $fileName = "$targetFolder\sim_file_$i.txt"
    "This is dummy content for simulation file $i" | Out-File -FilePath $fileName

    Start-Sleep -Milliseconds 50

    Rename-Item -Path $fileName -NewName "sim_file_$i.locked"

    Write-Host "Created and renamed: sim_file_$i.txt -> sim_file_$i.locked"
}
```

The 50ms delay between operations is deliberate - without it, file operations can happen faster than ETW can cleanly surface each one as a distinct event, which can make the output harder to read and the detection timing less predictable.

### Detection result from the demo script

The script triggers detection faster than the raw loop, because each iteration produces three distinct events (CREATE, WRITE, RENAME) rather than two (CREATE, WRITE). Detection fired at `sim_file_4.txt` - 4 files * ~5 events each = threshold crossed in under a second.
[2026-06-30 20:37:36] ALERT: PID=15944 crossed suspicious threshold (triggered by ...sim_file_4.txt)
[2026-06-30 20:37:36] RESPONSE: Killed PID=15944 (powershell)

The offending process was killed, its terminal closed, and EDR-Lite kept running and logging subsequent activity - including the OS flushing delayed writes to disk after the process was already dead, which shows up as `PID=4` (System) write events in the log shortly after.

---

## Summary

The full pipeline, from file event to terminated process, in one run:

1. ETW fires `FileIOCreate` for `sim_file_4.txt`, PID=15944
2. `EtwFileMonitor` checks the path - it's in `test-folder`, passes filter
3. `ActivityTracker.RecordActivity(15944)` adds the timestamp, cleans up old entries, returns `true` (threshold crossed)
4. `ResponseHandler.HandleSuspiciousActivity(15944, ...)` checks `_respondedPids` - PID not seen before, proceeds
5. `Process.GetProcessById(15944).Kill()` - process terminated
6. `Logger.Log(...)` - alert and response written to `edr-lite.log` with timestamp
7. EDR-Lite continues running, watching for the next suspicious PID

Total time from threshold crossing to process termination: under 100 milliseconds in live testing.
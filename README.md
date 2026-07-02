# EDR-Lite

A lightweight Endpoint Detection & Response engine built in C# (.NET 10) that correlates file system activity with the process responsible for it, flags ransomware-like behavior using a threshold-based rule, and automatically kills the offending process.

## What it does

Most beginner security projects that monitor file changes use `FileSystemWatcher`, which tells you *what* changed but never *who* changed it. EDR-Lite uses Windows kernel-level tracing (ETW) instead, so every file event comes with the actual process ID attached - no guessing.

The core loop: watch a folder -> correlate every create/write/rename with the PID that caused it -> if a single process touches 20+ files within 5 seconds, flag it as suspicious -> kill that process -> log everything with timestamps.

It's not a production EDR. It's a portfolio project that implements the same core mechanism real EDR tools use, scoped down to something one person can build and actually understand end to end.

## Architecture

EDR-Lite is built in 8 phases, each one a working layer on top of the last:

1. **File watcher** - early prototype using `FileSystemWatcher` (later replaced for correlation, see below)
2. **Process monitoring** - enumerates running processes and parent-child relationships via WMI (`Win32_Process`)
3. **ETW correlation** - the real core. Subscribes to Windows kernel file I/O events (`FileIOCreate`, `FileIOWrite`, `FileIORename`), which carry the triggering PID directly
4. **Detection logic** - a sliding-window threshold: if a PID generates 20+ file events within a 5-second window, it's flagged
5. **Automated response** - kills the flagged process via `System.Diagnostics.Process`, with a "respond once per PID" guard so it doesn't spam-kill or alert repeatedly
6. **Logging** - every event, alert, and response is timestamped and written to `edr-lite.log`
7. **Safe demo script** - a PowerShell script that creates and renames dummy files to simulate ransomware-style file churn, used to trigger detection without anything actually harmful happening

### Why ETW instead of `FileSystemWatcher`

`FileSystemWatcher` was the obvious first approach and it's where this project started, but it has a hard limitation: it tells you a file changed, not which process did it. That's a dealbreaker for anything claiming to do real correlation - you can't build "kill the process that's encrypting your files" on top of an API that doesn't know which process that is.

ETW (Event Tracing for Windows) is the same kernel-level mechanism real tools like Sysinternals' Process Monitor and actual EDR products use. It's lower-level, the documentation is thin, and it requires admin privileges to run - but it gives you the PID on every single file event, which is the whole point.

## Tech stack

- C# / .NET 10
- `Microsoft.Diagnostics.Tracing.TraceEvent` - ETW kernel event consumption
- `System.Management` - WMI process enumeration
- `System.Diagnostics.Process` - process termination
- PowerShell - demo/simulation script

## Project structure
edr-lite/
├── Program.cs
├── Monitoring/
│   └── ProcessMonitor.cs      # process listing + parent-child tree
├── Etw/
│   └── EtwFileMonitor.cs      # kernel-level file/process correlation
├── Detection/
│   ├── ActivityTracker.cs     # sliding-window threshold logic
│   ├── ResponseHandler.cs     # kill + alert-once-per-PID logic
│   └── Logger.cs              # timestamped file logging
├── demo-ransomware-sim.ps1    # safe simulation script
└── edr-lite.log               # generated at runtime
## How to run it

**Requirements:** Windows 10/11, .NET 10 SDK, Administrator privileges (ETW kernel tracing requires elevation).

```powershell
git clone <your-repo-url>
cd edr-lite
dotnet run
```

Run this from an **elevated (Administrator) terminal** - ETW will fail to start its kernel session otherwise.

### A heads-up about Smart App Control

If you're running this on a clean Windows 11 install, Windows Smart App Control may block the compiled binary outright with an error like:
Unhandled exception. System.IO.FileLoadException: Could not load file or assembly '...\EdrLite.dll'.
An Application Control policy has blocked this file. (0x800711C7)
This happens because Smart App Control is wary of unsigned binaries that do kernel-level monitoring - which, fair, is exactly what this does. On Windows builds 26100.8116 / 26200.8116 and later, Smart App Control can be toggled off and back on safely (Settings -> Windows Security -> App & browser control -> Smart App Control settings). On older builds, this used to be a one-way decision, so check your build number first.

I ran into this directly while building EDR-Lite and spent a while debugging it the hard way. The short version: it's a config issue, not a bug in the code.

## Demo script

`demo-ransomware-sim.ps1` creates 25 dummy `.txt` files in `test-folder/` and rapidly renames them to `.locked`, mimicking the create-then-rename pattern real ransomware uses. It doesn't encrypt, delete, or touch anything outside that folder.

Run EDR-Lite in one terminal, then in a separate terminal:

```powershell
.\demo-ransomware-sim.ps1
```

Worth noting: if you run the demo script from VS Code's integrated terminal, and that shell process is what gets flagged, EDR-Lite will kill it - taking the terminal panel down with it. Run it from a standalone terminal window to avoid that.

## Sample output

Trimmed from an actual run:
[2026-06-30 20:37:36] [CREATE] PID=15944 File=...test-folder\sim_file_4.txt
[2026-06-30 20:37:36] [RENAME] PID=15944 File=...test-folder\sim_file_4.txt
[2026-06-30 20:37:36] ALERT: PID=15944 crossed suspicious threshold (triggered by ...sim_file_4.txt)
[2026-06-30 20:37:36] RESPONSE: Killed PID=15944 (powershell)
And a case where the kill correctly failed - PID 4 is `System`, a protected Windows process that nothing should be able to kill, including this tool:
[2026-06-30 20:37:39] ALERT: PID=4 crossed suspicious threshold (triggered by ...sim_file_20.txt)
[2026-06-30 20:37:39] RESPONSE FAILED: Could not kill PID=4. Reason: Access is denied.
EDR-Lite logs the failure and keeps running instead of crashing - which matters, since a monitoring tool that dies on its first edge case isn't much of a monitoring tool.

## Known limitations / what I'd improve next

- Flat threshold, no baselining. Right now it's "20 events in 5 seconds, no exceptions" - it doesn't distinguish a backup tool from actual ransomware. Per-process baselining or an allowlist for trusted processes would cut false positives.
- Kill-on-first-detection is aggressive. There's no alert-only/dry-run mode yet, which would be safer for tuning thresholds without auto-killing things.
- `_fileKeyToName` grows unbounded. It never evicts entries for closed/deleted files. Fine for a demo session, not fine for a long-running process.
- Process monitoring (Phase 2) isn't wired into detection yet. I built a process tree view with parent-child relationships, but alerts don't currently look up or log the offending process's parent chain - which would give a lot more context.
- Hardcoded config. Watch path, threshold, time window, and log path are all set in code. Should be a config file or CLI args.
- No automated tests yet. `ActivityTracker`'s sliding-window logic has no external dependencies and would be easy to unit test - just haven't done it.
- Unsigned binary. Code-signing it would resolve the Smart App Control issue properly instead of working around it.

## What I learned

- ETW is genuinely powerful but the documentation is sparse - a lot of this came down to reading compiler errors carefully and matching them against the actual `TraceEvent` type names (turns out `FileIoCreate` isn't a thing, `FileIOCreate` is - that casing mismatch alone cost me a build).
- Getting something to compile and getting it to actually *run* on a real Windows machine are two different problems. Smart App Control blocking the binary outright was a new category of obstacle, and chasing it down was its own lesson in knowing when to step back and try a more direct fix.
- Sliding-window rate limiting is a recurring pattern in security tooling once you start recognizing it - the same concept applies to brute force detection, DDoS mitigation, and file-based anomaly detection. The implementation details differ but the core idea doesn't.
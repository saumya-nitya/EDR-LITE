using System;
using System.Collections.Generic;
using System.Management;

namespace EdrLite.Monitoring
{
    public class ProcessInfo
    {
        public int ProcessId { get; set; }
        public int ParentProcessId { get; set; }
        public string Name { get; set; } = string.Empty;
        public string ExecutablePath { get; set; } = string.Empty;
    }

    public class ProcessMonitor
    {
        public List<ProcessInfo> GetRunningProcesses()
        {
            var processes = new List<ProcessInfo>();

            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, ParentProcessId, Name, ExecutablePath FROM Win32_Process");

            foreach (ManagementObject obj in searcher.Get())
            {
                processes.Add(new ProcessInfo
                {
                    ProcessId = Convert.ToInt32(obj["ProcessId"]),
                    ParentProcessId = Convert.ToInt32(obj["ParentProcessId"]),
                    Name = obj["Name"]?.ToString() ?? "Unknown",
                    ExecutablePath = obj["ExecutablePath"]?.ToString() ?? string.Empty
                });
            }

            return processes;
        }
        public void PrintProcessTree(List<ProcessInfo> processes)
{
    // Build a lookup: parentPid -> list of children
    var childrenByParent = new Dictionary<int, List<ProcessInfo>>();

    foreach (var p in processes)
    {
        if (!childrenByParent.ContainsKey(p.ParentProcessId))
        {
            childrenByParent[p.ParentProcessId] = new List<ProcessInfo>();
        }
        childrenByParent[p.ParentProcessId].Add(p);
    }

    // Roots are processes whose parent PID doesn't exist in our process list
    var allPids = new HashSet<int>();
    foreach (var p in processes) allPids.Add(p.ProcessId);

    var roots = new List<ProcessInfo>();
    foreach (var p in processes)
    {
        if (!allPids.Contains(p.ParentProcessId))
        {
            roots.Add(p);
        }
    }

    foreach (var root in roots)
    {
        PrintNode(root, childrenByParent, 0);
    }
}

private void PrintNode(ProcessInfo node, Dictionary<int, List<ProcessInfo>> childrenByParent, int depth)
{
    string indent = new string(' ', depth * 2);
    Console.WriteLine($"{indent}- {node.Name} (PID: {node.ProcessId})");

    if (childrenByParent.ContainsKey(node.ProcessId))
    {
        foreach (var child in childrenByParent[node.ProcessId])
        {
            PrintNode(child, childrenByParent, depth + 1);
        }
    }
}
    }
}
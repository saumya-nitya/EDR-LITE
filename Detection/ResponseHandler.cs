using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace EdrLite.Detection
{
    public class ResponseHandler
    {
        private readonly HashSet<int> _respondedPids = new();
        private readonly Logger _logger;

        public ResponseHandler(Logger logger)
        {
            _logger = logger;
        }

        public void HandleSuspiciousActivity(int pid, string triggeringFile)
        {
            if (_respondedPids.Contains(pid))
            {
                return;
            }

            _respondedPids.Add(pid);

            _logger.Log($"ALERT: PID={pid} crossed suspicious threshold (triggered by {triggeringFile})");

            try
            {
                var process = Process.GetProcessById(pid);
                string processName = process.ProcessName;

                process.Kill();

                _logger.Log($"RESPONSE: Killed PID={pid} ({processName})");
            }
            catch (Exception ex)
            {
                _logger.Log($"RESPONSE FAILED: Could not kill PID={pid}. Reason: {ex.Message}");
            }
        }
    }
}
using System;
using System.Collections.Generic;
using EdrLite.Detection;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.Parsers;

namespace EdrLite.Etw
{
    public class EtwFileMonitor
    {
        private readonly string _watchPath;
        private readonly Dictionary<ulong, string> _fileKeyToName = new();
        private readonly ActivityTracker _tracker;
        private readonly ResponseHandler _responder;
        private readonly Logger _logger;

        public EtwFileMonitor(string watchPath)
        {
            _watchPath = watchPath.ToLowerInvariant();
            _tracker = new ActivityTracker(thresholdCount: 20, windowSize: TimeSpan.FromSeconds(5));
            _logger = new Logger(@"E:\VS CODE projects\edr-lite\edr-lite.log");
            _responder = new ResponseHandler(_logger);
        }

        public void Start()
        {
            using var session = new TraceEventSession(KernelTraceEventParser.KernelSessionName);

            session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.FileIOInit |
                KernelTraceEventParser.Keywords.FileIO
            );

            session.Source.Kernel.FileIOCreate += data =>
            {
                if (IsInWatchPath(data.FileName))
                {
                    _fileKeyToName[data.FileObject] = data.FileName;
                    _logger.Log($"[CREATE] PID={data.ProcessID} File={data.FileName}");

                    if (_tracker.RecordActivity(data.ProcessID))
                    {
                        _responder.HandleSuspiciousActivity(data.ProcessID, data.FileName);
                    }
                }
            };

            session.Source.Kernel.FileIORename += data =>
            {
                if (IsInWatchPath(data.FileName))
                {
                    _logger.Log($"[RENAME] PID={data.ProcessID} File={data.FileName}");

                    if (_tracker.RecordActivity(data.ProcessID))
                    {
                        _responder.HandleSuspiciousActivity(data.ProcessID, data.FileName);
                    }
                }
            };

            session.Source.Kernel.FileIOWrite += data =>
            {
                if (_fileKeyToName.TryGetValue(data.FileObject, out var fileName))
                {
                    _logger.Log($"[WRITE]  PID={data.ProcessID} File={fileName}");

                    if (_tracker.RecordActivity(data.ProcessID))
                    {
                        _responder.HandleSuspiciousActivity(data.ProcessID, fileName);
                    }
                }
            };

            _logger.Log($"ETW session started. Watching: {_watchPath}");
            session.Source.Process();
        }

        private bool IsInWatchPath(string fileName)
        {
            if (string.IsNullOrEmpty(fileName)) return false;
            return fileName.ToLowerInvariant().StartsWith(_watchPath);
        }
    }
}
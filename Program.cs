using EdrLite.Etw;

var etwMonitor = new EtwFileMonitor(@"E:\VS CODE projects\edr-lite\test-folder");
etwMonitor.Start();
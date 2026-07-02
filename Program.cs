using EdrLite.Etw;

string watchPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "test-folder");
var etwMonitor = new EtwFileMonitor(watchPath);
etwMonitor.Start();
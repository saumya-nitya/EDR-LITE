using System;
using System.IO;

namespace EdrLite.Detection
{
    public class Logger
    {
        private readonly string _logFilePath;

        public Logger(string logFilePath)
        {
            _logFilePath = logFilePath;
        }

        public void Log(string message)
        {
            string timestamped = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}";
            Console.WriteLine(timestamped);
            File.AppendAllText(_logFilePath, timestamped + Environment.NewLine);
        }
    }
}
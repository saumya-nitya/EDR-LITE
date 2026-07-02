using System;
using System.Collections.Generic;

namespace EdrLite.Detection
{
    public class ActivityTracker
    {
        private readonly Dictionary<int, List<DateTime>> _activityByPid = new();
        private readonly int _thresholdCount;
        private readonly TimeSpan _windowSize;

        public ActivityTracker(int thresholdCount, TimeSpan windowSize)
        {
            _thresholdCount = thresholdCount;
            _windowSize = windowSize;
        }
        public bool RecordActivity(int pid)
        {
            var now = DateTime.Now;

            if (!_activityByPid.ContainsKey(pid))
            {
                _activityByPid[pid] = new List<DateTime>();
            }
            var timestamps = _activityByPid[pid];
            timestamps.Add(now);

            timestamps.RemoveAll(t => now - t > _windowSize);

            return timestamps.Count >= _thresholdCount;
        }
        
        
    }
}
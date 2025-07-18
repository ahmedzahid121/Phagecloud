using System;
using System.Collections.Generic;

namespace PhageVirus.Modules
{
    /// <summary>
    /// Unified ProcessInfo class used across multiple modules
    /// </summary>
    public class ProcessInfo
    {
        // Core fields used by all modules
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public string FilePath { get; set; } = "";
        public DateTime StartTime { get; set; }
        public TimeSpan CpuTime { get; set; }
        
        // Memory-related fields (used by multiple modules)
        public long MemoryUsage { get; set; }
        public long WorkingSet { get; set; }
        
        // System fields (used by BehaviorTest and UI)
        public int ThreadCount { get; set; }
        public int HandleCount { get; set; }
        public int Priority { get; set; }
        public bool Responding { get; set; }
        public string MainWindowTitle { get; set; } = "";
        
        // Security fields (used by SystemHacker and UI)
        public ThreatLevel ThreatLevel { get; set; }
        public List<string> MaliciousPatterns { get; set; } = new List<string>();
        public double FileEntropy { get; set; }
        
        // UI-specific fields (used by MainWindow)
        public string Status { get; set; } = "";
        public string CpuUsage { get; set; } = "0%";
        
        // Constructor for easy initialization
        public ProcessInfo()
        {
            StartTime = DateTime.Now;
            ThreatLevel = ThreatLevel.Normal;
        }
        
        // Helper method to get memory usage in MB
        public string GetMemoryUsageMB()
        {
            return $"{MemoryUsage / 1024 / 1024} MB";
        }
        
        // Helper method to get working set in MB
        public string GetWorkingSetMB()
        {
            return $"{WorkingSet / 1024 / 1024} MB";
        }
    }

    /// <summary>
    /// Unified EmailConfig class used by EmailReporter and DiagnosticTest
    /// </summary>
    public class EmailConfig
    {
        public string SmtpServer { get; set; } = "";
        public int Port { get; set; }
        public string Email { get; set; } = "";
        public string Subject { get; set; } = "";
        public string Body { get; set; } = "";
        public string[] Attachments { get; set; } = new string[0];
        
        // Optional authentication fields
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
        public bool UseSsl { get; set; } = true;
    }

    /// <summary>
    /// Threat level enumeration used across modules
    /// </summary>
    public enum ThreatLevel
    {
        Normal = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }

    /// <summary>
    /// Module health status used across the application
    /// </summary>
    public enum ModuleHealth
    {
        Running,
        Stressed,
        Failed,
        Stopped
    }
} 

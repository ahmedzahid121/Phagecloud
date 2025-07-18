using System;
using System.Collections.Generic;

namespace PhageVirus.Agent.Shared
{
    public class HeartbeatData
    {
        public string AgentId { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string Mode { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public SystemInfo SystemInfo { get; set; } = new();
        public Dictionary<string, object> Metrics { get; set; } = new();
    }

    public class SystemInfo
    {
        public string MachineName { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string OSVersion { get; set; } = string.Empty;
        public int ProcessorCount { get; set; }
        public long WorkingSet { get; set; }
        public bool Is64BitProcess { get; set; }
        public bool Is64BitOperatingSystem { get; set; }
        public long AvailableMemory { get; set; }
        public double CpuUsage { get; set; }
        public long DiskSpace { get; set; }
    }

    public class ThreatData
    {
        public string AgentId { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string ThreatType { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public Dictionary<string, object> Metadata { get; set; } = new();
        public byte[]? RawData { get; set; }
        public string Hash { get; set; } = string.Empty;
        public ThreatSeverity Severity { get; set; }
    }

    public class ThreatAnalysisResult
    {
        public string AnalysisId { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public double RiskScore { get; set; }
        public double Confidence { get; set; }
        public List<string> DetectedPatterns { get; set; } = new();
        public List<string> Recommendations { get; set; } = new();
        public string AnalysisSource { get; set; } = string.Empty;
        public ThreatSeverity CalculatedSeverity { get; set; }
        public bool RequiresImmediateAction { get; set; }
        public Dictionary<string, object> AnalysisMetadata { get; set; } = new();
    }

    public class TelemetryData
    {
        public string AgentId { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string DataType { get; set; } = string.Empty;
        public Dictionary<string, object> Data { get; set; } = new();
        public bool IsCompressed { get; set; }
        public bool IsEncrypted { get; set; }
        public string Checksum { get; set; } = string.Empty;
    }

    public class ProcessInfo
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public DateTime StartTime { get; set; }
        public long MemoryUsage { get; set; }
        public double CpuUsage { get; set; }
        public int ThreadCount { get; set; }
        public string CommandLine { get; set; } = string.Empty;
        public string ParentProcess { get; set; } = string.Empty;
        public ThreatSeverity ThreatLevel { get; set; }
    }

    public class MemoryRegionInfo
    {
        public IntPtr BaseAddress { get; set; }
        public long RegionSize { get; set; }
        public string Protection { get; set; } = string.Empty;
        public string State { get; set; } = string.Empty;
        public double Entropy { get; set; }
        public bool IsSuspicious { get; set; }
        public List<string> DetectedPatterns { get; set; } = new();
    }

    public class NetworkConnectionInfo
    {
        public string LocalAddress { get; set; } = string.Empty;
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; } = string.Empty;
        public int RemotePort { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public string State { get; set; } = string.Empty;
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public bool IsSuspicious { get; set; }
    }

    public class FileSystemEvent
    {
        public string FilePath { get; set; } = string.Empty;
        public string EventType { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public long FileSize { get; set; }
        public string FileHash { get; set; } = string.Empty;
        public string ProcessName { get; set; } = string.Empty;
        public bool IsSuspicious { get; set; }
    }

    public class RegistryEvent
    {
        public string KeyPath { get; set; } = string.Empty;
        public string ValueName { get; set; } = string.Empty;
        public string EventType { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public bool IsSuspicious { get; set; }
    }

    public class CredentialEvent
    {
        public string EventType { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public string Method { get; set; } = string.Empty;
        public bool IsSuspicious { get; set; }
        public ThreatSeverity Severity { get; set; }
    }

    public class AlertData
    {
        public string AlertId { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string AgentId { get; set; } = string.Empty;
        public string AlertType { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public ThreatSeverity Severity { get; set; }
        public bool RequiresImmediateAction { get; set; }
        public Dictionary<string, object> AlertData { get; set; } = new();
        public List<string> AffectedSystems { get; set; } = new();
    }

    public class ConfigurationData
    {
        public string AgentId { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public Dictionary<string, object> Settings { get; set; } = new();
        public string ConfigurationVersion { get; set; } = string.Empty;
        public bool RequiresRestart { get; set; }
    }

    public class HealthCheckData
    {
        public string AgentId { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string Status { get; set; } = string.Empty;
        public Dictionary<string, object> Metrics { get; set; } = new();
        public List<string> Issues { get; set; } = new();
        public bool IsHealthy { get; set; }
    }

    public enum ThreatSeverity
    {
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }

    public enum TelemetryType
    {
        Process,
        Memory,
        Network,
        FileSystem,
        Registry,
        Credential,
        System,
        Performance
    }

    public enum AlertType
    {
        ThreatDetected,
        SystemCompromise,
        UnauthorizedAccess,
        DataExfiltration,
        MalwareActivity,
        NetworkAttack,
        ConfigurationChange,
        SystemHealth
    }
} 
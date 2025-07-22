using System;
using System.Collections.Generic;

namespace PhageVirusDashboard.Models
{
    // Executive Summary Cards
    public class ExecutiveSummary
    {
        public EndpointSummary Endpoints { get; set; } = new();
        public ThreatSummary Threats { get; set; } = new();
        public CloudSummary Cloud { get; set; } = new();
        public IdentitySummary Identity { get; set; } = new();
        public HealthSummary Health { get; set; } = new();
        public TestSummary Tests { get; set; } = new();
    }

    public class EndpointSummary
    {
        public int OnlineCount { get; set; }
        public int TotalCount { get; set; }
        public double OnlinePercentage => TotalCount > 0 ? (double)OnlineCount / TotalCount * 100 : 0;
    }

    public class ThreatSummary
    {
        public int NewThreatsToday { get; set; }
        public int CriticalThreats { get; set; }
        public int TotalThreatsToday { get; set; }
    }

    public class CloudSummary
    {
        public int MisconfigAlerts { get; set; }
        public int PublicS3Buckets { get; set; }
        public int ExposedRoles { get; set; }
        public int CriticalGaps { get; set; }
    }

    public class IdentitySummary
    {
        public int SuspiciousLogins { get; set; }
        public int TokenMisuse { get; set; }
        public int MfaBypassAttempts { get; set; }
        public int SessionHijacks { get; set; }
    }

    public class HealthSummary
    {
        public int OutdatedAgents { get; set; }
        public int UnresponsiveAgents { get; set; }
        public int HealthyAgents { get; set; }
        public double HealthPercentage { get; set; }
    }

    public class TestSummary
    {
        public double PassRate { get; set; }
        public DateTime LastRun { get; set; }
        public int TotalTests { get; set; }
        public int PassedTests { get; set; }
    }

    // Threat Feed Models
    public class ThreatFeed
    {
        public List<ThreatEvent> RecentThreats { get; set; } = new();
        public List<ThreatEvent> HistoricalThreats { get; set; } = new();
    }

    public class ThreatEvent
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public DateTime Timestamp { get; set; }
        public string Type { get; set; } = string.Empty;
        public string AffectedAgent { get; set; } = string.Empty;
        public ThreatSeverity Severity { get; set; }
        public string ActionTaken { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public bool IsResolved { get; set; }
    }

    public enum ThreatSeverity
    {
        Low,
        Medium,
        High,
        Critical
    }

    // Endpoint Overview Models
    public class EndpointOverview
    {
        public List<EndpointInfo> Endpoints { get; set; } = new();
        public EndpointFilters Filters { get; set; } = new();
    }

    public class EndpointInfo
    {
        public string DeviceName { get; set; } = string.Empty;
        public EndpointStatus Status { get; set; }
        public DateTime LastScan { get; set; }
        public int ThreatsBlocked { get; set; }
        public string OperatingSystem { get; set; } = string.Empty;
        public string AgentVersion { get; set; } = string.Empty;
        public string Site { get; set; } = string.Empty;
        public string Department { get; set; } = string.Empty;
        public RiskLevel RiskLevel { get; set; }
        public DateTime LastSeen { get; set; }
        public double CpuUsage { get; set; }
        public double MemoryUsage { get; set; }
    }

    public enum EndpointStatus
    {
        Online,
        Offline,
        Unhealthy,
        Isolated
    }

    public enum RiskLevel
    {
        Low,
        Medium,
        High,
        Critical
    }

    public class EndpointFilters
    {
        public string? Site { get; set; }
        public string? Department { get; set; }
        public string? OperatingSystem { get; set; }
        public RiskLevel? RiskLevel { get; set; }
        public EndpointStatus? Status { get; set; }
    }

    // Cloud Posture Models
    public class CloudPosture
    {
        public AwsSummary Aws { get; set; } = new();
        public AzureSummary Azure { get; set; } = new();
        public CspmSummary Cspm { get; set; } = new();
    }

    public class AwsSummary
    {
        public int IamMisconfigs { get; set; }
        public int PublicS3Buckets { get; set; }
        public int ExposedRoles { get; set; }
        public List<string> CriticalIssues { get; set; } = new();
    }

    public class AzureSummary
    {
        public int FunctionCrashes { get; set; }
        public int AnomalousExecutions { get; set; }
        public int SecurityAlerts { get; set; }
        public List<string> CriticalIssues { get; set; } = new();
    }

    public class CspmSummary
    {
        public double CompliancePercentage { get; set; }
        public int CriticalGaps { get; set; }
        public int TotalResources { get; set; }
        public int CompliantResources { get; set; }
    }

    // Identity Protection Models
    public class IdentityProtection
    {
        public List<IdentityAlert> Alerts { get; set; } = new();
        public IdentityMetrics Metrics { get; set; } = new();
    }

    public class IdentityAlert
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Type { get; set; } = string.Empty;
        public int Count { get; set; }
        public string Description { get; set; } = string.Empty;
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public ThreatSeverity Severity { get; set; }
        public bool IsResolved { get; set; }
    }

    public class IdentityMetrics
    {
        public int MfaBypassAttempts { get; set; }
        public int SessionHijacks { get; set; }
        public int PrivilegeEscalations { get; set; }
        public int SuspiciousLogins { get; set; }
        public int TokenMisuse { get; set; }
    }

    // Actions Panel Models
    public class DashboardAction
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Icon { get; set; } = string.Empty;
        public ActionType Type { get; set; }
        public bool RequiresConfirmation { get; set; }
        public List<string> Parameters { get; set; } = new();
    }

    public enum ActionType
    {
        ForceScan,
        IsolateDevice,
        RunRedTeamSim,
        UpdatePolicy,
        ExportLogs,
        UpdateAgents
    }

    // Logs & Audit Trail Models
    public class AuditLog
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public DateTime Timestamp { get; set; }
        public string User { get; set; } = string.Empty;
        public string Action { get; set; } = string.Empty;
        public string Resource { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public bool Success { get; set; }
    }

    // Dashboard View Models
    public class DashboardViewModel
    {
        public ExecutiveSummary Summary { get; set; } = new();
        public ThreatFeed ThreatFeed { get; set; } = new();
        public EndpointOverview Endpoints { get; set; } = new();
        public CloudPosture Cloud { get; set; } = new();
        public IdentityProtection Identity { get; set; } = new();
        public List<DashboardAction> Actions { get; set; } = new();
        public List<AuditLog> RecentAuditLogs { get; set; } = new();
        public DateTime LastUpdated { get; set; }
    }

    // API Response Models
    public class ApiResponse<T>
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public T? Data { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

    public class DashboardStats
    {
        public int TotalEndpoints { get; set; }
        public int OnlineEndpoints { get; set; }
        public int ThreatsToday { get; set; }
        public int CriticalThreats { get; set; }
        public double SystemHealth { get; set; }
        public DateTime LastUpdate { get; set; }
    }
} 
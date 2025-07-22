using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using PhageVirusDashboard.Models;

namespace PhageVirusDashboard.Services
{
    public interface IDashboardService
    {
        Task<DashboardViewModel> GetDashboardDataAsync();
        Task<ExecutiveSummary> GetExecutiveSummaryAsync();
        Task<ThreatFeed> GetThreatFeedAsync();
        Task<EndpointOverview> GetEndpointOverviewAsync(EndpointFilters? filters = null);
        Task<CloudPosture> GetCloudPostureAsync();
        Task<IdentityProtection> GetIdentityProtectionAsync();
        Task<List<DashboardAction>> GetAvailableActionsAsync();
        Task<List<AuditLog>> GetRecentAuditLogsAsync();
        Task<ApiResponse<bool>> ExecuteActionAsync(string actionId, Dictionary<string, object> parameters);
        Task<DashboardStats> GetDashboardStatsAsync();
    }

    public class DashboardService : IDashboardService
    {
        private readonly Random _random = new();
        private readonly List<ThreatEvent> _threatHistory = new();
        private readonly List<EndpointInfo> _endpoints = new();
        private readonly List<AuditLog> _auditLogs = new();

        public DashboardService()
        {
            InitializeMockData();
        }

        public async Task<DashboardViewModel> GetDashboardDataAsync()
        {
            await Task.Delay(100); // Simulate async operation

            return new DashboardViewModel
            {
                Summary = await GetExecutiveSummaryAsync(),
                ThreatFeed = await GetThreatFeedAsync(),
                Endpoints = await GetEndpointOverviewAsync(),
                Cloud = await GetCloudPostureAsync(),
                Identity = await GetIdentityProtectionAsync(),
                Actions = await GetAvailableActionsAsync(),
                RecentAuditLogs = await GetRecentAuditLogsAsync(),
                LastUpdated = DateTime.Now
            };
        }

        public async Task<ExecutiveSummary> GetExecutiveSummaryAsync()
        {
            await Task.Delay(50);

            return new ExecutiveSummary
            {
                Endpoints = new EndpointSummary
                {
                    OnlineCount = 95,
                    TotalCount = 100
                },
                Threats = new ThreatSummary
                {
                    NewThreatsToday = 6,
                    CriticalThreats = 2,
                    TotalThreatsToday = 8
                },
                Cloud = new CloudSummary
                {
                    MisconfigAlerts = 3,
                    PublicS3Buckets = 1,
                    ExposedRoles = 2,
                    CriticalGaps = 1
                },
                Identity = new IdentitySummary
                {
                    SuspiciousLogins = 1,
                    TokenMisuse = 2,
                    MfaBypassAttempts = 1,
                    SessionHijacks = 2
                },
                Health = new HealthSummary
                {
                    OutdatedAgents = 3,
                    UnresponsiveAgents = 1,
                    HealthyAgents = 96,
                    HealthPercentage = 96.0
                },
                Tests = new TestSummary
                {
                    PassRate = 98.0,
                    LastRun = DateTime.Now.AddHours(-2),
                    TotalTests = 50,
                    PassedTests = 49
                }
            };
        }

        public async Task<ThreatFeed> GetThreatFeedAsync()
        {
            await Task.Delay(50);

            var recentThreats = _threatHistory
                .Where(t => t.Timestamp > DateTime.Now.AddHours(-24))
                .OrderByDescending(t => t.Timestamp)
                .Take(20)
                .ToList();

            var historicalThreats = _threatHistory
                .Where(t => t.Timestamp <= DateTime.Now.AddHours(-24))
                .OrderByDescending(t => t.Timestamp)
                .Take(50)
                .ToList();

            return new ThreatFeed
            {
                RecentThreats = recentThreats,
                HistoricalThreats = historicalThreats
            };
        }

        public async Task<EndpointOverview> GetEndpointOverviewAsync(EndpointFilters? filters = null)
        {
            await Task.Delay(100);

            var filteredEndpoints = _endpoints.AsEnumerable();

            if (filters != null)
            {
                if (!string.IsNullOrEmpty(filters.Site))
                    filteredEndpoints = filteredEndpoints.Where(e => e.Site == filters.Site);
                
                if (!string.IsNullOrEmpty(filters.Department))
                    filteredEndpoints = filteredEndpoints.Where(e => e.Department == filters.Department);
                
                if (!string.IsNullOrEmpty(filters.OperatingSystem))
                    filteredEndpoints = filteredEndpoints.Where(e => e.OperatingSystem == filters.OperatingSystem);
                
                if (filters.RiskLevel.HasValue)
                    filteredEndpoints = filteredEndpoints.Where(e => e.RiskLevel == filters.RiskLevel.Value);
                
                if (filters.Status.HasValue)
                    filteredEndpoints = filteredEndpoints.Where(e => e.Status == filters.Status.Value);
            }

            return new EndpointOverview
            {
                Endpoints = filteredEndpoints.ToList(),
                Filters = filters ?? new EndpointFilters()
            };
        }

        public async Task<CloudPosture> GetCloudPostureAsync()
        {
            await Task.Delay(75);

            return new CloudPosture
            {
                Aws = new AwsSummary
                {
                    IamMisconfigs = 2,
                    PublicS3Buckets = 1,
                    ExposedRoles = 2,
                    CriticalIssues = new List<string>
                    {
                        "Admin role has excessive permissions",
                        "S3 bucket publicly accessible",
                        "IAM user with console access"
                    }
                },
                Azure = new AzureSummary
                {
                    FunctionCrashes = 1,
                    AnomalousExecutions = 2,
                    SecurityAlerts = 3,
                    CriticalIssues = new List<string>
                    {
                        "Function app exposed to internet",
                        "Service principal with excessive permissions"
                    }
                },
                Cspm = new CspmSummary
                {
                    CompliancePercentage = 88.0,
                    CriticalGaps = 12,
                    TotalResources = 150,
                    CompliantResources = 132
                }
            };
        }

        public async Task<IdentityProtection> GetIdentityProtectionAsync()
        {
            await Task.Delay(50);

            return new IdentityProtection
            {
                Alerts = new List<IdentityAlert>
                {
                    new IdentityAlert
                    {
                        Type = "MFA Bypass Attempt",
                        Count = 1,
                        Description = "New IP, impossible travel detected",
                        FirstSeen = DateTime.Now.AddHours(-3),
                        LastSeen = DateTime.Now.AddHours(-1),
                        Severity = ThreatSeverity.High
                    },
                    new IdentityAlert
                    {
                        Type = "Session Hijack",
                        Count = 2,
                        Description = "Tokens reused from 2 locations",
                        FirstSeen = DateTime.Now.AddHours(-6),
                        LastSeen = DateTime.Now.AddHours(-2),
                        Severity = ThreatSeverity.Critical
                    },
                    new IdentityAlert
                    {
                        Type = "Privilege Escalation",
                        Count = 0,
                        Description = "No privilege escalation detected",
                        FirstSeen = DateTime.Now.AddDays(-1),
                        LastSeen = DateTime.Now.AddDays(-1),
                        Severity = ThreatSeverity.Low
                    }
                },
                Metrics = new IdentityMetrics
                {
                    MfaBypassAttempts = 1,
                    SessionHijacks = 2,
                    PrivilegeEscalations = 0,
                    SuspiciousLogins = 1,
                    TokenMisuse = 2
                }
            };
        }

        public async Task<List<DashboardAction>> GetAvailableActionsAsync()
        {
            await Task.Delay(25);

            return new List<DashboardAction>
            {
                new DashboardAction
                {
                    Name = "Force Scan",
                    Description = "Push scan to one or all devices",
                    Icon = "📡",
                    Type = ActionType.ForceScan,
                    RequiresConfirmation = true,
                    Parameters = new List<string> { "deviceId", "scanType" }
                },
                new DashboardAction
                {
                    Name = "Isolate Device",
                    Description = "Disconnect endpoint from network",
                    Icon = "⛔",
                    Type = ActionType.IsolateDevice,
                    RequiresConfirmation = true,
                    Parameters = new List<string> { "deviceId", "isolationType" }
                },
                new DashboardAction
                {
                    Name = "Run Red Team Sim",
                    Description = "Simulate attack (for testing)",
                    Icon = "🧠",
                    Type = ActionType.RunRedTeamSim,
                    RequiresConfirmation = true,
                    Parameters = new List<string> { "simulationType", "targetDevice" }
                },
                new DashboardAction
                {
                    Name = "Update Policy",
                    Description = "Change blocking/elevation rules",
                    Icon = "🧩",
                    Type = ActionType.UpdatePolicy,
                    RequiresConfirmation = true,
                    Parameters = new List<string> { "policyType", "policyData" }
                },
                new DashboardAction
                {
                    Name = "Export Logs",
                    Description = "Export audit logs and reports",
                    Icon = "📄",
                    Type = ActionType.ExportLogs,
                    RequiresConfirmation = false,
                    Parameters = new List<string> { "format", "dateRange" }
                },
                new DashboardAction
                {
                    Name = "Update Agents",
                    Description = "Push agent updates to endpoints",
                    Icon = "🔄",
                    Type = ActionType.UpdateAgents,
                    RequiresConfirmation = true,
                    Parameters = new List<string> { "targetDevices", "updateType" }
                }
            };
        }

        public async Task<List<AuditLog>> GetRecentAuditLogsAsync()
        {
            await Task.Delay(50);

            return _auditLogs
                .OrderByDescending(l => l.Timestamp)
                .Take(20)
                .ToList();
        }

        public async Task<ApiResponse<bool>> ExecuteActionAsync(string actionId, Dictionary<string, object> parameters)
        {
            await Task.Delay(200); // Simulate action execution

            // Log the action
            var auditLog = new AuditLog
            {
                Timestamp = DateTime.Now,
                User = "admin@phagevirus.com",
                Action = $"Executed action: {actionId}",
                Resource = "Dashboard",
                Details = $"Parameters: {string.Join(", ", parameters.Select(kv => $"{kv.Key}={kv.Value}"))}",
                IpAddress = "192.168.1.100",
                Success = true
            };

            _auditLogs.Add(auditLog);

            return new ApiResponse<bool>
            {
                Success = true,
                Message = "Action executed successfully",
                Data = true
            };
        }

        public async Task<DashboardStats> GetDashboardStatsAsync()
        {
            await Task.Delay(50);

            return new DashboardStats
            {
                TotalEndpoints = 100,
                OnlineEndpoints = 95,
                ThreatsToday = 8,
                CriticalThreats = 2,
                SystemHealth = 96.0,
                LastUpdate = DateTime.Now
            };
        }

        private void InitializeMockData()
        {
            // Initialize mock endpoints
            var sites = new[] { "HQ", "Branch-1", "Branch-2", "Remote" };
            var departments = new[] { "IT", "Sales", "Marketing", "Finance", "HR" };
            var osVersions = new[] { "Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022" };

            for (int i = 1; i <= 100; i++)
            {
                var status = _random.Next(100) < 95 ? EndpointStatus.Online : 
                           _random.Next(100) < 98 ? EndpointStatus.Unhealthy : EndpointStatus.Offline;

                _endpoints.Add(new EndpointInfo
                {
                    DeviceName = $"WIN-{sites[_random.Next(sites.Length)]}-{i:D3}",
                    Status = status,
                    LastScan = DateTime.Now.AddHours(-_random.Next(1, 24)),
                    ThreatsBlocked = _random.Next(0, 5),
                    OperatingSystem = osVersions[_random.Next(osVersions.Length)],
                    AgentVersion = $"v1.{_random.Next(1, 5)}.{_random.Next(1, 10)}",
                    Site = sites[_random.Next(sites.Length)],
                    Department = departments[_random.Next(departments.Length)],
                    RiskLevel = (RiskLevel)_random.Next(4),
                    LastSeen = DateTime.Now.AddMinutes(-_random.Next(1, 60)),
                    CpuUsage = _random.Next(5, 85),
                    MemoryUsage = _random.Next(20, 90)
                });
            }

            // Initialize mock threat history
            var threatTypes = new[] { "Ransomware", "Token Theft", "Exploit", "Phishing", "Malware", "DDoS" };
            var actions = new[] { "Blocked", "Quarantined", "Logged only", "Isolated" };
            var severities = new[] { ThreatSeverity.Low, ThreatSeverity.Medium, ThreatSeverity.High, ThreatSeverity.Critical };

            for (int i = 0; i < 100; i++)
            {
                _threatHistory.Add(new ThreatEvent
                {
                    Timestamp = DateTime.Now.AddHours(-_random.Next(1, 168)), // Last 7 days
                    Type = threatTypes[_random.Next(threatTypes.Length)],
                    AffectedAgent = $"Host-{_random.Next(1, 100):D3}",
                    Severity = severities[_random.Next(severities.Length)],
                    ActionTaken = actions[_random.Next(actions.Length)],
                    Description = $"Suspicious activity detected on {_random.Next(1, 100)} endpoints",
                    IsResolved = _random.Next(100) < 80 // 80% resolved
                });
            }

            // Initialize mock audit logs
            var auditActions = new[] { "Login", "Policy Update", "Device Isolation", "Scan Initiated", "Export Logs" };
            var users = new[] { "admin@phagevirus.com", "security@phagevirus.com", "analyst@phagevirus.com" };

            for (int i = 0; i < 50; i++)
            {
                _auditLogs.Add(new AuditLog
                {
                    Timestamp = DateTime.Now.AddHours(-_random.Next(1, 48)),
                    User = users[_random.Next(users.Length)],
                    Action = auditActions[_random.Next(auditActions.Length)],
                    Resource = $"Endpoint-{_random.Next(1, 100)}",
                    Details = $"Action performed successfully",
                    IpAddress = $"192.168.1.{_random.Next(1, 255)}",
                    Success = _random.Next(100) < 95 // 95% success rate
                });
            }
        }
    }
} 
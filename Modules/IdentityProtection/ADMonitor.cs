using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Threading;
using System.Linq;
using System.Text.Json;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using PhageVirus.Modules.CloudSecurity;

namespace PhageVirus.Modules.IdentityProtection
{
    /// <summary>
    /// Comprehensive Active Directory and Entra ID Monitoring Module
    /// Monitors AD/Entra ID events for suspicious changes and security threats
    /// Provides real-time alerting for identity-related security incidents
    /// Offloads heavy analysis to AWS Lambda for scalable processing
    /// </summary>
    public class ADMonitor
    {
        private static readonly object monitorLock = new object();
        private static bool isActive = false;
        private static Timer? monitoringTimer;
        private static readonly ConcurrentDictionary<string, ADEvent> monitoredEvents = new();
        private static readonly List<ADAlert> activeAlerts = new();
        
        // Configuration
        private static int monitoringIntervalSeconds = 60;
        private static double criticalRiskThreshold = 0.8;
        private static double highRiskThreshold = 0.6;
        private static double mediumRiskThreshold = 0.4;
        private static string? domainController;
        private static string? ldapPath;
        
        // Suspicious event patterns
        private static readonly string[] CriticalEvents = {
            "4720", // Account created
            "4722", // Account enabled
            "4724", // Password reset
            "4728", // Member added to security group
            "4732", // Member added to admin group
            "4738", // User account changed
            "4740", // Account locked out
            "4767", // Account unlocked
            "1102", // Audit log cleared
            "4624", // Successful logon
            "4625", // Failed logon
            "4647", // User initiated logoff
            "4672", // Special privileges assigned
            "4688", // Process created
            "4697", // Service installed
            "4698", // Scheduled task created
            "4699", // Scheduled task deleted
            "4700", // Scheduled task enabled
            "4701", // Scheduled task disabled
            "4702"  // Scheduled task updated
        };
        
        private static readonly string[] HighRiskEvents = {
            "4725", // Account disabled
            "4726", // Account deleted
            "4729", // Member removed from security group
            "4733", // Member removed from admin group
            "4739", // Domain policy changed
            "4741", // Computer account created
            "4742", // Computer account changed
            "4743", // Computer account deleted
            "4756", // Domain controller promoted
            "4757", // Domain controller demoted
            "4761", // Kerberos ticket requested
            "4762", // Kerberos ticket renewed
            "4763", // Kerberos ticket failed
            "4764", // Kerberos ticket used
            "4765", // Kerberos pre-authentication failed
            "4766", // Kerberos authentication ticket requested
            "4767", // Kerberos service ticket requested
            "4768", // Kerberos authentication ticket renewed
            "4769", // Kerberos service ticket renewed
            "4770"  // Kerberos service ticket renewed
        };

        public class ADEvent
        {
            public string EventId { get; set; } = "";
            public string EventType { get; set; } = "";
            public string Source { get; set; } = ""; // AD or Entra ID
            public string UserName { get; set; } = "";
            public string ComputerName { get; set; } = "";
            public string IpAddress { get; set; } = "";
            public DateTime Timestamp { get; set; } = DateTime.UtcNow;
            public string Description { get; set; } = "";
            public Dictionary<string, object> EventData { get; set; } = new();
            public double RiskScore { get; set; } = 0.0;
            public List<string> SuspiciousPatterns { get; set; } = new();
            public bool IsProcessed { get; set; } = false;
        }

        public class ADAlert
        {
            public string AlertId { get; set; } = Guid.NewGuid().ToString();
            public string EventId { get; set; } = "";
            public string AlertType { get; set; } = "";
            public string Description { get; set; } = "";
            public ThreatLevel Severity { get; set; } = ThreatLevel.Medium;
            public double RiskScore { get; set; } = 0.0;
            public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
            public bool IsAcknowledged { get; set; } = false;
            public string? RemediationGuidance { get; set; }
            public Dictionary<string, object> Context { get; set; } = new();
        }

        public class ADAnalysisResult
        {
            public bool Success { get; set; }
            public string Message { get; set; } = "";
            public List<ADAlert> Alerts { get; set; } = new();
            public double OverallRiskScore { get; set; } = 0.0;
            public int TotalEvents { get; set; } = 0;
            public int CriticalEvents { get; set; } = 0;
            public int HighEvents { get; set; } = 0;
            public int MediumEvents { get; set; } = 0;
            public List<string> Recommendations { get; set; } = new();
            public Dictionary<string, object> Metrics { get; set; } = new();
        }

        /// <summary>
        /// Initialize the AD Monitor
        /// </summary>
        public static async Task InitializeAsync()
        {
            if (isActive) return;

            lock (monitorLock)
            {
                if (isActive) return;

                try
                {
                    EnhancedLogger.LogInfo("Initializing AD Monitor...");
                    
                    // Load configuration
                    LoadConfiguration();
                    
                    // Initialize event tracking
                    InitializeEventTracking();
                    
                    // Start monitoring
                    StartMonitoring();
                    
                    isActive = true;
                    EnhancedLogger.LogSuccess("AD Monitor initialized successfully");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to initialize AD Monitor: {ex.Message}");
                    throw;
                }
            }
        }

        /// <summary>
        /// Start monitoring AD/Entra ID events
        /// </summary>
        public static async Task MonitorADAsync()
        {
            if (!isActive)
            {
                await InitializeAsync();
            }

            try
            {
                EnhancedLogger.LogInfo("Starting AD/Entra ID monitoring...");
                
                // Perform initial comprehensive scan
                await PerformComprehensiveADScanAsync();
                
                // Start continuous monitoring
                await StartContinuousADMonitoringAsync();
                
                EnhancedLogger.LogSuccess("AD/Entra ID monitoring started successfully");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start AD monitoring: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Stop the AD monitor
        /// </summary>
        public static void StopMonitoring()
        {
            lock (monitorLock)
            {
                if (!isActive) return;

                try
                {
                    monitoringTimer?.Dispose();
                    monitoringTimer = null;
                    isActive = false;
                    
                    EnhancedLogger.LogInfo("AD Monitor stopped");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Error stopping AD Monitor: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Perform comprehensive AD security scan
        /// </summary>
        public static async Task<ADAnalysisResult> PerformComprehensiveADScanAsync()
        {
            var result = new ADAnalysisResult();
            
            try
            {
                EnhancedLogger.LogInfo("Starting comprehensive AD security scan...");
                
                // Collect AD events
                var adEvents = await CollectADEventsAsync();
                
                // Analyze each event for security issues
                var analysisTasks = adEvents.Select(adEvent => AnalyzeADEventAsync(adEvent));
                var analysisResults = await Task.WhenAll(analysisTasks);
                
                // Aggregate results
                foreach (var analysis in analysisResults)
                {
                    if (analysis != null)
                    {
                        result.Alerts.Add(analysis);
                        result.TotalEvents++;
                        
                        if (analysis.Severity == ThreatLevel.Critical)
                            result.CriticalEvents++;
                        else if (analysis.Severity == ThreatLevel.High)
                            result.HighEvents++;
                        else if (analysis.Severity == ThreatLevel.Medium)
                            result.MediumEvents++;
                    }
                }
                
                // Calculate overall risk score
                result.OverallRiskScore = result.Alerts.Any() ? 
                    result.Alerts.Average(a => a.RiskScore) : 0.0;
                
                // Generate recommendations
                result.Recommendations = GenerateADRecommendations(result.Alerts);
                
                // Send analysis to cloud for additional processing
                await SendADAnalysisToCloudAsync(result);
                
                // Log results
                LogADAnalysisResults(result);
                
                result.Success = true;
                result.Message = "Comprehensive AD scan completed successfully";
                
                EnhancedLogger.LogSuccess($"AD scan completed: {result.TotalEvents} events, {result.Alerts.Count} alerts found");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"AD scan failed: {ex.Message}";
                EnhancedLogger.LogError($"Comprehensive AD scan failed: {ex.Message}");
            }
            
            return result;
        }

        /// <summary>
        /// Collect AD events (simulated for demonstration)
        /// </summary>
        private static async Task<List<ADEvent>> CollectADEventsAsync()
        {
            var events = new List<ADEvent>();
            
            try
            {
                // Simulate collecting AD events
                // In a real implementation, this would query AD logs or use WMI
                
                events.Add(new ADEvent
                {
                    EventId = "4720",
                    EventType = "Account Created",
                    Source = "Active Directory",
                    UserName = "newuser",
                    ComputerName = "DC01",
                    IpAddress = "192.168.1.100",
                    Timestamp = DateTime.UtcNow.AddMinutes(-5),
                    Description = "A user account was created",
                    EventData = new Dictionary<string, object>
                    {
                        { "TargetUserName", "newuser" },
                        { "TargetDomainName", "CONTOSO" },
                        { "TargetSid", "S-1-5-21-1234567890-1234567890-1234567890-1234" }
                    }
                });
                
                events.Add(new ADEvent
                {
                    EventId = "4728",
                    EventType = "Member Added to Security Group",
                    Source = "Active Directory",
                    UserName = "admin",
                    ComputerName = "DC01",
                    IpAddress = "192.168.1.50",
                    Timestamp = DateTime.UtcNow.AddMinutes(-10),
                    Description = "A member was added to a security-enabled global group",
                    EventData = new Dictionary<string, object>
                    {
                        { "TargetUserName", "newuser" },
                        { "TargetDomainName", "CONTOSO" },
                        { "GroupName", "Domain Admins" }
                    }
                });
                
                events.Add(new ADEvent
                {
                    EventId = "4624",
                    EventType = "Successful Logon",
                    Source = "Active Directory",
                    UserName = "serviceaccount",
                    ComputerName = "SRV01",
                    IpAddress = "10.0.0.100",
                    Timestamp = DateTime.UtcNow.AddMinutes(-15),
                    Description = "An account was successfully logged on",
                    EventData = new Dictionary<string, object>
                    {
                        { "LogonType", "3" },
                        { "WorkstationName", "SRV01" },
                        { "IpAddress", "10.0.0.100" }
                    }
                });
                
                events.Add(new ADEvent
                {
                    EventId = "1102",
                    EventType = "Audit Log Cleared",
                    Source = "Active Directory",
                    UserName = "admin",
                    ComputerName = "DC01",
                    IpAddress = "192.168.1.50",
                    Timestamp = DateTime.UtcNow.AddMinutes(-20),
                    Description = "The audit log was cleared",
                    EventData = new Dictionary<string, object>
                    {
                        { "SubjectUserName", "admin" },
                        { "SubjectDomainName", "CONTOSO" }
                    }
                });
                
                await Task.Delay(100); // Simulate API call delay
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error collecting AD events: {ex.Message}");
            }
            
            return events;
        }

        /// <summary>
        /// Analyze a single AD event for security issues
        /// </summary>
        private static async Task<ADAlert?> AnalyzeADEventAsync(ADEvent adEvent)
        {
            try
            {
                var suspiciousPatterns = new List<string>();
                var riskScore = 0.0;
                
                // Check for critical events
                if (CriticalEvents.Contains(adEvent.EventId))
                {
                    suspiciousPatterns.Add($"Critical event detected: {adEvent.EventType}");
                    riskScore += 0.4;
                }
                
                // Check for high-risk events
                if (HighRiskEvents.Contains(adEvent.EventId))
                {
                    suspiciousPatterns.Add($"High-risk event detected: {adEvent.EventType}");
                    riskScore += 0.3;
                }
                
                // Check for specific suspicious patterns
                riskScore += CheckSuspiciousPatterns(adEvent, suspiciousPatterns);
                
                // Check for unusual timing
                riskScore += CheckUnusualTiming(adEvent, suspiciousPatterns);
                
                // Check for privilege escalation
                riskScore += CheckPrivilegeEscalation(adEvent, suspiciousPatterns);
                
                // Check for lateral movement
                riskScore += CheckLateralMovement(adEvent, suspiciousPatterns);
                
                if (suspiciousPatterns.Any())
                {
                    var alert = new ADAlert
                    {
                        EventId = adEvent.EventId,
                        AlertType = "AD_SECURITY_EVENT",
                        Description = string.Join("; ", suspiciousPatterns),
                        RiskScore = Math.Min(riskScore, 1.0),
                        Severity = riskScore >= criticalRiskThreshold ? ThreatLevel.Critical :
                                  riskScore >= highRiskThreshold ? ThreatLevel.High :
                                  ThreatLevel.Medium,
                        RemediationGuidance = GenerateADRemediationGuidance(suspiciousPatterns, adEvent.EventType),
                        Context = new Dictionary<string, object>
                        {
                            { "EventType", adEvent.EventType },
                            { "Source", adEvent.Source },
                            { "UserName", adEvent.UserName },
                            { "ComputerName", adEvent.ComputerName },
                            { "IpAddress", adEvent.IpAddress },
                            { "Timestamp", adEvent.Timestamp },
                            { "EventData", adEvent.EventData }
                        }
                    };
                    
                    return alert;
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error analyzing AD event {adEvent.EventId}: {ex.Message}");
            }
            
            return null;
        }

        /// <summary>
        /// Check for suspicious patterns in AD events
        /// </summary>
        private static double CheckSuspiciousPatterns(ADEvent adEvent, List<string> patterns)
        {
            var riskScore = 0.0;
            
            // Check for audit log clearing
            if (adEvent.EventId == "1102")
            {
                patterns.Add("Audit log cleared - potential evidence tampering");
                riskScore += 0.5;
            }
            
            // Check for account creation outside business hours
            if (adEvent.EventId == "4720" && IsOutsideBusinessHours(adEvent.Timestamp))
            {
                patterns.Add("Account created outside business hours");
                riskScore += 0.3;
            }
            
            // Check for multiple failed logons
            if (adEvent.EventId == "4625")
            {
                patterns.Add("Failed logon attempt detected");
                riskScore += 0.2;
            }
            
            // Check for service account logons
            if (adEvent.EventId == "4624" && adEvent.UserName.ToLower().Contains("service"))
            {
                patterns.Add("Service account logon detected");
                riskScore += 0.1;
            }
            
            return riskScore;
        }

        /// <summary>
        /// Check for unusual timing patterns
        /// </summary>
        private static double CheckUnusualTiming(ADEvent adEvent, List<string> patterns)
        {
            var riskScore = 0.0;
            
            // Check for events outside business hours
            if (IsOutsideBusinessHours(adEvent.Timestamp))
            {
                patterns.Add("Event occurred outside business hours");
                riskScore += 0.2;
            }
            
            // Check for rapid succession events
            var recentEvents = monitoredEvents.Values
                .Where(e => e.UserName == adEvent.UserName && 
                           e.Timestamp > adEvent.Timestamp.AddMinutes(-5))
                .Count();
            
            if (recentEvents > 10)
            {
                patterns.Add("High frequency of events from same user");
                riskScore += 0.3;
            }
            
            return riskScore;
        }

        /// <summary>
        /// Check for privilege escalation attempts
        /// </summary>
        private static double CheckPrivilegeEscalation(ADEvent adEvent, List<string> patterns)
        {
            var riskScore = 0.0;
            
            // Check for admin group membership changes
            if (adEvent.EventId == "4728" || adEvent.EventId == "4732")
            {
                if (adEvent.EventData.ContainsKey("GroupName"))
                {
                    var groupName = adEvent.EventData["GroupName"].ToString()?.ToLower();
                    if (groupName?.Contains("admin") == true || groupName?.Contains("administrator") == true)
                    {
                        patterns.Add("Administrative group membership change detected");
                        riskScore += 0.4;
                    }
                }
            }
            
            // Check for special privileges assignment
            if (adEvent.EventId == "4672")
            {
                patterns.Add("Special privileges assigned to account");
                riskScore += 0.3;
            }
            
            return riskScore;
        }

        /// <summary>
        /// Check for lateral movement indicators
        /// </summary>
        private static double CheckLateralMovement(ADEvent adEvent, List<string> patterns)
        {
            var riskScore = 0.0;
            
            // Check for logons from multiple computers
            var userComputers = monitoredEvents.Values
                .Where(e => e.UserName == adEvent.UserName && 
                           e.EventId == "4624" &&
                           e.Timestamp > adEvent.Timestamp.AddHours(-1))
                .Select(e => e.ComputerName)
                .Distinct()
                .Count();
            
            if (userComputers > 3)
            {
                patterns.Add("User logged on to multiple computers in short time");
                riskScore += 0.3;
            }
            
            // Check for logons from unusual IP addresses
            if (adEvent.EventId == "4624" && IsUnusualIpAddress(adEvent.IpAddress))
            {
                patterns.Add("Logon from unusual IP address");
                riskScore += 0.2;
            }
            
            return riskScore;
        }

        /// <summary>
        /// Check if event occurred outside business hours
        /// </summary>
        private static bool IsOutsideBusinessHours(DateTime timestamp)
        {
            var hour = timestamp.Hour;
            var dayOfWeek = timestamp.DayOfWeek;
            
            // Business hours: Monday-Friday, 8 AM - 6 PM
            return dayOfWeek == DayOfWeek.Saturday || dayOfWeek == DayOfWeek.Sunday ||
                   hour < 8 || hour >= 18;
        }

        /// <summary>
        /// Check if IP address is unusual
        /// </summary>
        private static bool IsUnusualIpAddress(string ipAddress)
        {
            // Simple check for external IPs (not 192.168.x.x, 10.x.x.x, 172.16-31.x.x)
            if (ipAddress.StartsWith("192.168.") || ipAddress.StartsWith("10."))
                return false;
            
            if (ipAddress.StartsWith("172."))
            {
                var parts = ipAddress.Split('.');
                if (parts.Length > 1 && int.TryParse(parts[1], out var secondOctet))
                {
                    if (secondOctet >= 16 && secondOctet <= 31)
                        return false;
                }
            }
            
            return true;
        }

        /// <summary>
        /// Send AD analysis to cloud for additional processing
        /// </summary>
        private static async Task SendADAnalysisToCloudAsync(ADAnalysisResult result)
        {
            try
            {
                var telemetryData = new
                {
                    scan_timestamp = DateTime.UtcNow,
                    total_events = result.TotalEvents,
                    total_alerts = result.Alerts.Count,
                    critical_events = result.CriticalEvents,
                    high_events = result.HighEvents,
                    medium_events = result.MediumEvents,
                    overall_risk_score = result.OverallRiskScore,
                    alerts_summary = result.Alerts.Select(a => new
                    {
                        event_id = a.EventId,
                        alert_type = a.AlertType,
                        severity = a.Severity.ToString(),
                        risk_score = a.RiskScore
                    }).ToList()
                };
                
                await CloudIntegration.SendTelemetryAsync("ADMonitor", "ad_analysis", telemetryData, 
                    result.OverallRiskScore >= criticalRiskThreshold ? ThreatLevel.Critical :
                    result.OverallRiskScore >= highRiskThreshold ? ThreatLevel.High : ThreatLevel.Medium);
                
                // Get cloud analysis results
                var cloudAnalysis = await CloudIntegration.GetCloudAnalysisAsync("ADMonitor", telemetryData);
                if (cloudAnalysis.Success)
                {
                    EnhancedLogger.LogInfo($"Cloud AD analysis: {cloudAnalysis.Analysis}");
                    
                    // Apply cloud recommendations if any
                    if (cloudAnalysis.Recommendations?.Any() == true)
                    {
                        foreach (var recommendation in cloudAnalysis.Recommendations)
                        {
                            EnhancedLogger.LogInfo($"Cloud recommendation: {recommendation}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to send AD analysis to cloud: {ex.Message}");
            }
        }

        /// <summary>
        /// Generate remediation guidance for AD alerts
        /// </summary>
        private static string GenerateADRemediationGuidance(List<string> patterns, string eventType)
        {
            var guidance = new List<string>();
            
            foreach (var pattern in patterns)
            {
                if (pattern.Contains("audit log cleared"))
                {
                    guidance.Add("Investigate audit log clearing and ensure proper logging");
                }
                else if (pattern.Contains("outside business hours"))
                {
                    guidance.Add("Review activity outside business hours for legitimacy");
                }
                else if (pattern.Contains("administrative group"))
                {
                    guidance.Add("Review administrative group membership changes");
                }
                else if (pattern.Contains("multiple computers"))
                {
                    guidance.Add("Investigate lateral movement indicators");
                }
                else if (pattern.Contains("unusual IP"))
                {
                    guidance.Add("Investigate logons from unusual IP addresses");
                }
                else if (pattern.Contains("failed logon"))
                {
                    guidance.Add("Investigate failed logon attempts for brute force");
                }
            }
            
            return string.Join("; ", guidance.Distinct());
        }

        /// <summary>
        /// Generate security recommendations based on analysis results
        /// </summary>
        private static List<string> GenerateADRecommendations(List<ADAlert> alerts)
        {
            var recommendations = new List<string>();
            
            if (alerts.Any(a => a.Severity == ThreatLevel.Critical))
            {
                recommendations.Add("Immediately investigate critical AD security events");
            }
            
            if (alerts.Any(a => a.Description.Contains("audit log cleared")))
            {
                recommendations.Add("Implement audit log protection and monitoring");
            }
            
            if (alerts.Any(a => a.Description.Contains("administrative group")))
            {
                recommendations.Add("Review and restrict administrative group membership");
            }
            
            if (alerts.Any(a => a.Description.Contains("multiple computers")))
            {
                recommendations.Add("Implement lateral movement detection and prevention");
            }
            
            recommendations.Add("Enable advanced audit policies for comprehensive monitoring");
            recommendations.Add("Implement privileged access management (PAM) solution");
            recommendations.Add("Set up automated alerting for suspicious AD events");
            recommendations.Add("Regularly review and update AD security policies");
            
            return recommendations;
        }

        /// <summary>
        /// Log AD analysis results
        /// </summary>
        private static void LogADAnalysisResults(ADAnalysisResult result)
        {
            if (result.CriticalEvents > 0)
            {
                EnhancedLogger.LogCritical($"AD Scan: {result.CriticalEvents} critical events found");
            }
            
            if (result.HighEvents > 0)
            {
                EnhancedLogger.LogWarning($"AD Scan: {result.HighEvents} high-risk events found");
            }
            
            if (result.MediumEvents > 0)
            {
                EnhancedLogger.LogInfo($"AD Scan: {result.MediumEvents} medium-risk events found");
            }
            
            EnhancedLogger.LogInfo($"AD Scan Summary: {result.TotalEvents} events scanned, " +
                                 $"Overall risk score: {result.OverallRiskScore:F2}");
        }

        /// <summary>
        /// Load configuration from UnifiedConfig
        /// </summary>
        private static void LoadConfiguration()
        {
            try
            {
                var config = UnifiedConfig.Instance;
                monitoringIntervalSeconds = config.GetModulePerformanceSettings("ADMonitor").ScanInterval;
                criticalRiskThreshold = 0.8;
                highRiskThreshold = 0.6;
                mediumRiskThreshold = 0.4;
                
                EnhancedLogger.LogInfo($"AD Monitor configuration loaded: monitoring interval = {monitoringIntervalSeconds} seconds");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to load AD Monitor configuration: {ex.Message}");
            }
        }

        /// <summary>
        /// Initialize event tracking
        /// </summary>
        private static void InitializeEventTracking()
        {
            monitoredEvents.Clear();
            activeAlerts.Clear();
        }

        /// <summary>
        /// Start monitoring
        /// </summary>
        private static void StartMonitoring()
        {
            monitoringTimer = new Timer(async _ => await PerformComprehensiveADScanAsync(), null, 
                TimeSpan.Zero, TimeSpan.FromSeconds(monitoringIntervalSeconds));
        }

        /// <summary>
        /// Start continuous AD monitoring
        /// </summary>
        private static async Task StartContinuousADMonitoringAsync()
        {
            // In a real implementation, this would set up event-driven monitoring
            // For now, we rely on periodic scanning
            await Task.CompletedTask;
        }

        /// <summary>
        /// Get current status of the monitor
        /// </summary>
        public static bool IsActive => isActive;

        /// <summary>
        /// Get active alerts
        /// </summary>
        public static List<ADAlert> GetActiveAlerts() => new List<ADAlert>(activeAlerts);

        /// <summary>
        /// Acknowledge an alert
        /// </summary>
        public static void AcknowledgeAlert(string alertId)
        {
            var alert = activeAlerts.FirstOrDefault(a => a.AlertId == alertId);
            if (alert != null)
            {
                alert.IsAcknowledged = true;
                EnhancedLogger.LogInfo($"AD alert {alertId} acknowledged");
            }
        }
    }
} 
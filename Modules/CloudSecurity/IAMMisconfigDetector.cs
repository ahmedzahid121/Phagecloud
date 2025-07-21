using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Threading;
using System.Text.Json;
using System.Linq;
using PhageVirus.Modules.CloudSecurity;

namespace PhageVirus.Modules.CloudSecurity
{
    /// <summary>
    /// Comprehensive IAM Misconfiguration Detection and Analysis Module
    /// Monitors AWS IAM policies, roles, and permissions for security misconfigurations
    /// Offloads heavy analysis to AWS Lambda for real-time threat assessment
    /// </summary>
    public class IAMMisconfigDetector
    {
        private static readonly object detectorLock = new object();
        private static bool isActive = false;
        private static Timer? scanTimer;
        private static readonly ConcurrentDictionary<string, IAMResource> monitoredResources = new();
        private static readonly List<MisconfigurationAlert> activeAlerts = new();
        
        // Configuration thresholds
        private static int scanIntervalMinutes = 30;
        private static double criticalRiskThreshold = 0.8;
        private static double highRiskThreshold = 0.6;
        private static double mediumRiskThreshold = 0.4;
        
        // IAM Security Best Practices
        private static readonly string[] CriticalPermissions = {
            "iam:CreateAccessKey", "iam:DeleteAccessKey", "iam:UpdateAccessKey",
            "iam:CreateUser", "iam:DeleteUser", "iam:AttachUserPolicy",
            "iam:DetachUserPolicy", "iam:PutUserPolicy", "iam:DeleteUserPolicy",
            "iam:CreateRole", "iam:DeleteRole", "iam:AttachRolePolicy",
            "iam:DetachRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy",
            "iam:CreatePolicy", "iam:DeletePolicy", "iam:AttachPolicy",
            "iam:DetachPolicy", "iam:UpdateAssumeRolePolicy",
            "sts:AssumeRole", "sts:GetFederationToken", "sts:GetSessionToken"
        };
        
        private static readonly string[] HighRiskPermissions = {
            "ec2:RunInstances", "ec2:TerminateInstances", "ec2:StopInstances",
            "ec2:StartInstances", "ec2:RebootInstances", "ec2:ModifyInstanceAttribute",
            "s3:DeleteBucket", "s3:DeleteObject", "s3:PutBucketPolicy",
            "s3:DeleteBucketPolicy", "s3:PutBucketAcl", "s3:PutObjectAcl",
            "lambda:InvokeFunction", "lambda:UpdateFunctionCode", "lambda:DeleteFunction",
            "rds:DeleteDBInstance", "rds:ModifyDBInstance", "rds:CreateDBSnapshot",
            "cloudformation:DeleteStack", "cloudformation:UpdateStack",
            "ecs:DeleteService", "ecs:UpdateService", "ecs:DeleteTaskDefinition"
        };
        
        private static readonly string[] WildcardPatterns = {
            "*", "arn:aws:*", "arn:aws:iam::*", "arn:aws:s3:::*",
            "arn:aws:ec2:*:*:*", "arn:aws:lambda:*:*:*", "arn:aws:rds:*:*:*"
        };

        public class IAMResource
        {
            public string ResourceId { get; set; } = "";
            public string ResourceType { get; set; } = ""; // User, Role, Policy, Group
            public string ResourceName { get; set; } = "";
            public string Arn { get; set; } = "";
            public DateTime LastModified { get; set; }
            public List<string> AttachedPolicies { get; set; } = new();
            public List<string> InlinePolicies { get; set; } = new();
            public List<string> Permissions { get; set; } = new();
            public Dictionary<string, object> Metadata { get; set; } = new();
            public double RiskScore { get; set; } = 0.0;
            public List<string> Misconfigurations { get; set; } = new();
            public bool IsActive { get; set; } = true;
        }

        public class MisconfigurationAlert
        {
            public string AlertId { get; set; } = Guid.NewGuid().ToString();
            public string ResourceId { get; set; } = "";
            public string ResourceType { get; set; } = "";
            public string MisconfigurationType { get; set; } = "";
            public string Description { get; set; } = "";
            public ThreatLevel Severity { get; set; } = ThreatLevel.Medium;
            public double RiskScore { get; set; } = 0.0;
            public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
            public bool IsAcknowledged { get; set; } = false;
            public string? RemediationGuidance { get; set; }
            public Dictionary<string, object> Context { get; set; } = new();
        }

        public class IAMAnalysisResult
        {
            public bool Success { get; set; }
            public string Message { get; set; } = "";
            public List<MisconfigurationAlert> Alerts { get; set; } = new();
            public double OverallRiskScore { get; set; } = 0.0;
            public int TotalResources { get; set; } = 0;
            public int CriticalMisconfigs { get; set; } = 0;
            public int HighMisconfigs { get; set; } = 0;
            public int MediumMisconfigs { get; set; } = 0;
            public List<string> Recommendations { get; set; } = new();
            public Dictionary<string, object> Metrics { get; set; } = new();
        }

        /// <summary>
        /// Initialize the IAM Misconfiguration Detector
        /// </summary>
        public static async Task InitializeAsync()
        {
            if (isActive) return;

            lock (detectorLock)
            {
                if (isActive) return;

                try
                {
                    EnhancedLogger.LogInfo("Initializing IAM Misconfiguration Detector...");
                    
                    // Load configuration from UnifiedConfig
                    LoadConfiguration();
                    
                    // Initialize resource tracking
                    InitializeResourceTracking();
                    
                    // Start periodic scanning
                    StartPeriodicScanning();
                    
                    isActive = true;
                    EnhancedLogger.LogSuccess("IAM Misconfiguration Detector initialized successfully");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to initialize IAM Misconfiguration Detector: {ex.Message}");
                    throw;
                }
            }
        }

        /// <summary>
        /// Start the IAM misconfiguration detection process
        /// </summary>
        public static async Task StartDetectionAsync()
        {
            if (!isActive)
            {
                await InitializeAsync();
            }

            try
            {
                EnhancedLogger.LogInfo("Starting IAM misconfiguration detection...");
                
                // Perform initial comprehensive scan
                await PerformComprehensiveScanAsync();
                
                // Start continuous monitoring
                await StartContinuousMonitoringAsync();
                
                EnhancedLogger.LogSuccess("IAM misconfiguration detection started successfully");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start IAM misconfiguration detection: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Stop the IAM misconfiguration detection
        /// </summary>
        public static void StopDetection()
        {
            lock (detectorLock)
            {
                if (!isActive) return;

                try
                {
                    scanTimer?.Dispose();
                    scanTimer = null;
                    isActive = false;
                    
                    EnhancedLogger.LogInfo("IAM Misconfiguration Detector stopped");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Error stopping IAM Misconfiguration Detector: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Perform a comprehensive IAM security scan
        /// </summary>
        public static async Task<IAMAnalysisResult> PerformComprehensiveScanAsync()
        {
            var result = new IAMAnalysisResult();
            
            try
            {
                EnhancedLogger.LogInfo("Starting comprehensive IAM security scan...");
                
                // Collect IAM resources (simulate AWS API calls)
                var iamResources = await CollectIAMResourcesAsync();
                
                // Analyze each resource for misconfigurations
                var analysisTasks = iamResources.Select(resource => AnalyzeResourceAsync(resource));
                var analysisResults = await Task.WhenAll(analysisTasks);
                
                // Aggregate results
                foreach (var analysis in analysisResults)
                {
                    if (analysis != null)
                    {
                        result.Alerts.AddRange(analysis.Alerts);
                        result.TotalResources++;
                        
                        if (analysis.RiskScore >= criticalRiskThreshold)
                            result.CriticalMisconfigs++;
                        else if (analysis.RiskScore >= highRiskThreshold)
                            result.HighMisconfigs++;
                        else if (analysis.RiskScore >= mediumRiskThreshold)
                            result.MediumMisconfigs++;
                    }
                }
                
                // Calculate overall risk score
                result.OverallRiskScore = result.Alerts.Any() ? 
                    result.Alerts.Average(a => a.RiskScore) : 0.0;
                
                // Generate recommendations
                result.Recommendations = GenerateRecommendations(result.Alerts);
                
                // Send analysis to cloud for additional processing
                await SendAnalysisToCloudAsync(result);
                
                // Log results
                LogAnalysisResults(result);
                
                result.Success = true;
                result.Message = "Comprehensive IAM scan completed successfully";
                
                EnhancedLogger.LogSuccess($"IAM scan completed: {result.TotalResources} resources, {result.Alerts.Count} misconfigurations found");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"IAM scan failed: {ex.Message}";
                EnhancedLogger.LogError($"Comprehensive IAM scan failed: {ex.Message}");
            }
            
            return result;
        }

        /// <summary>
        /// Collect IAM resources from AWS (simulated)
        /// </summary>
        private static async Task<List<IAMResource>> CollectIAMResourcesAsync()
        {
            var resources = new List<IAMResource>();
            
            try
            {
                // Simulate collecting IAM users
                resources.Add(new IAMResource
                {
                    ResourceId = "user-admin",
                    ResourceType = "User",
                    ResourceName = "admin",
                    Arn = "arn:aws:iam::123456789012:user/admin",
                    LastModified = DateTime.UtcNow.AddDays(-5),
                    AttachedPolicies = new List<string> { "AdministratorAccess" },
                    InlinePolicies = new List<string>(),
                    Permissions = new List<string> { "*" }
                });
                
                // Simulate collecting IAM roles
                resources.Add(new IAMResource
                {
                    ResourceId = "role-lambda-execution",
                    ResourceType = "Role",
                    ResourceName = "lambda-execution-role",
                    Arn = "arn:aws:iam::123456789012:role/lambda-execution-role",
                    LastModified = DateTime.UtcNow.AddDays(-2),
                    AttachedPolicies = new List<string> { "AWSLambdaBasicExecutionRole" },
                    InlinePolicies = new List<string> { "S3FullAccess" },
                    Permissions = new List<string> { "s3:*", "logs:*" }
                });
                
                // Simulate collecting IAM policies
                resources.Add(new IAMResource
                {
                    ResourceId = "policy-overly-permissive",
                    ResourceType = "Policy",
                    ResourceName = "OverlyPermissivePolicy",
                    Arn = "arn:aws:iam::123456789012:policy/OverlyPermissivePolicy",
                    LastModified = DateTime.UtcNow.AddDays(-1),
                    AttachedPolicies = new List<string>(),
                    InlinePolicies = new List<string>(),
                    Permissions = new List<string> { "ec2:*", "s3:*", "lambda:*" }
                });
                
                await Task.Delay(100); // Simulate API call delay
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error collecting IAM resources: {ex.Message}");
            }
            
            return resources;
        }

        /// <summary>
        /// Analyze a single IAM resource for misconfigurations
        /// </summary>
        private static async Task<MisconfigurationAlert?> AnalyzeResourceAsync(IAMResource resource)
        {
            try
            {
                var misconfigurations = new List<string>();
                var riskScore = 0.0;
                
                // Check for overly permissive policies
                if (resource.Permissions.Contains("*"))
                {
                    misconfigurations.Add("Overly permissive policy with wildcard permissions");
                    riskScore += 0.8;
                }
                
                // Check for critical permissions
                var criticalPermCount = resource.Permissions.Count(p => CriticalPermissions.Contains(p));
                if (criticalPermCount > 0)
                {
                    misconfigurations.Add($"Contains {criticalPermCount} critical IAM permissions");
                    riskScore += criticalPermCount * 0.2;
                }
                
                // Check for high-risk permissions
                var highRiskPermCount = resource.Permissions.Count(p => HighRiskPermissions.Contains(p));
                if (highRiskPermCount > 0)
                {
                    misconfigurations.Add($"Contains {highRiskPermCount} high-risk permissions");
                    riskScore += highRiskPermCount * 0.1;
                }
                
                // Check for wildcard patterns
                var wildcardCount = resource.Permissions.Count(p => WildcardPatterns.Any(w => p.Contains(w)));
                if (wildcardCount > 0)
                {
                    misconfigurations.Add($"Contains {wildcardCount} wildcard patterns");
                    riskScore += wildcardCount * 0.15;
                }
                
                // Check for inactive resources
                if (!resource.IsActive)
                {
                    misconfigurations.Add("Inactive IAM resource should be cleaned up");
                    riskScore += 0.1;
                }
                
                // Check for old resources
                if (resource.LastModified < DateTime.UtcNow.AddDays(-90))
                {
                    misconfigurations.Add("IAM resource hasn't been reviewed in over 90 days");
                    riskScore += 0.1;
                }
                
                if (misconfigurations.Any())
                {
                    var alert = new MisconfigurationAlert
                    {
                        ResourceId = resource.ResourceId,
                        ResourceType = resource.ResourceType,
                        MisconfigurationType = "IAM_MISCONFIGURATION",
                        Description = string.Join("; ", misconfigurations),
                        RiskScore = Math.Min(riskScore, 1.0),
                        Severity = riskScore >= criticalRiskThreshold ? ThreatLevel.Critical :
                                  riskScore >= highRiskThreshold ? ThreatLevel.High :
                                  ThreatLevel.Medium,
                        RemediationGuidance = GenerateRemediationGuidance(misconfigurations),
                        Context = new Dictionary<string, object>
                        {
                            { "ResourceArn", resource.Arn },
                            { "ResourceName", resource.ResourceName },
                            { "LastModified", resource.LastModified },
                            { "Permissions", resource.Permissions },
                            { "AttachedPolicies", resource.AttachedPolicies },
                            { "InlinePolicies", resource.InlinePolicies }
                        }
                    };
                    
                    return alert;
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error analyzing IAM resource {resource.ResourceId}: {ex.Message}");
            }
            
            return null;
        }

        /// <summary>
        /// Send analysis results to cloud for additional processing
        /// </summary>
        private static async Task SendAnalysisToCloudAsync(IAMAnalysisResult result)
        {
            try
            {
                var telemetryData = new
                {
                    scan_timestamp = DateTime.UtcNow,
                    total_resources = result.TotalResources,
                    total_alerts = result.Alerts.Count,
                    critical_alerts = result.CriticalMisconfigs,
                    high_alerts = result.HighMisconfigs,
                    medium_alerts = result.MediumMisconfigs,
                    overall_risk_score = result.OverallRiskScore,
                    alerts_summary = result.Alerts.Select(a => new
                    {
                        resource_type = a.ResourceType,
                        misconfiguration_type = a.MisconfigurationType,
                        severity = a.Severity.ToString(),
                        risk_score = a.RiskScore
                    }).ToList()
                };
                
                await CloudIntegration.SendTelemetryAsync("IAMMisconfigDetector", "iam_analysis", telemetryData, 
                    result.OverallRiskScore >= criticalRiskThreshold ? ThreatLevel.Critical :
                    result.OverallRiskScore >= highRiskThreshold ? ThreatLevel.High : ThreatLevel.Medium);
                
                // Get cloud analysis results
                var cloudAnalysis = await CloudIntegration.GetCloudAnalysisAsync("IAMMisconfigDetector", telemetryData);
                if (cloudAnalysis.Success)
                {
                    EnhancedLogger.LogInfo($"Cloud IAM analysis: {cloudAnalysis.Analysis}");
                    
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
                EnhancedLogger.LogWarning($"Failed to send IAM analysis to cloud: {ex.Message}");
            }
        }

        /// <summary>
        /// Generate remediation guidance for misconfigurations
        /// </summary>
        private static string GenerateRemediationGuidance(List<string> misconfigurations)
        {
            var guidance = new List<string>();
            
            foreach (var misconfig in misconfigurations)
            {
                if (misconfig.Contains("wildcard"))
                {
                    guidance.Add("Replace wildcard permissions with specific resource ARNs");
                }
                else if (misconfig.Contains("critical"))
                {
                    guidance.Add("Review and restrict critical IAM permissions to minimum required access");
                }
                else if (misconfig.Contains("high-risk"))
                {
                    guidance.Add("Review high-risk permissions and implement least privilege access");
                }
                else if (misconfig.Contains("inactive"))
                {
                    guidance.Add("Remove inactive IAM resources to reduce attack surface");
                }
                else if (misconfig.Contains("reviewed"))
                {
                    guidance.Add("Implement regular IAM resource review process");
                }
            }
            
            return string.Join("; ", guidance.Distinct());
        }

        /// <summary>
        /// Generate security recommendations based on analysis results
        /// </summary>
        private static List<string> GenerateRecommendations(List<MisconfigurationAlert> alerts)
        {
            var recommendations = new List<string>();
            
            if (alerts.Any(a => a.Severity == ThreatLevel.Critical))
            {
                recommendations.Add("Immediately address critical IAM misconfigurations");
            }
            
            if (alerts.Any(a => a.Description.Contains("wildcard")))
            {
                recommendations.Add("Implement least privilege access by removing wildcard permissions");
            }
            
            if (alerts.Any(a => a.Description.Contains("critical")))
            {
                recommendations.Add("Restrict critical IAM permissions to specific use cases only");
            }
            
            if (alerts.Any(a => a.Description.Contains("inactive")))
            {
                recommendations.Add("Clean up inactive IAM resources to reduce attack surface");
            }
            
            recommendations.Add("Implement automated IAM policy validation in CI/CD pipeline");
            recommendations.Add("Enable AWS Config rules for IAM compliance monitoring");
            recommendations.Add("Schedule regular IAM access reviews and cleanup");
            
            return recommendations;
        }

        /// <summary>
        /// Log analysis results
        /// </summary>
        private static void LogAnalysisResults(IAMAnalysisResult result)
        {
            if (result.CriticalMisconfigs > 0)
            {
                EnhancedLogger.LogCritical($"IAM Scan: {result.CriticalMisconfigs} critical misconfigurations found");
            }
            
            if (result.HighMisconfigs > 0)
            {
                EnhancedLogger.LogWarning($"IAM Scan: {result.HighMisconfigs} high-risk misconfigurations found");
            }
            
            if (result.MediumMisconfigs > 0)
            {
                EnhancedLogger.LogInfo($"IAM Scan: {result.MediumMisconfigs} medium-risk misconfigurations found");
            }
            
            EnhancedLogger.LogInfo($"IAM Scan Summary: {result.TotalResources} resources scanned, " +
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
                scanIntervalMinutes = config.GetModulePerformanceSettings("IAMMisconfigDetector").ScanInterval / 60;
                criticalRiskThreshold = 0.8; // Could be configurable
                highRiskThreshold = 0.6;
                mediumRiskThreshold = 0.4;
                
                EnhancedLogger.LogInfo($"IAM Misconfig Detector configuration loaded: scan interval = {scanIntervalMinutes} minutes");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to load IAM Misconfig Detector configuration: {ex.Message}");
            }
        }

        /// <summary>
        /// Initialize resource tracking
        /// </summary>
        private static void InitializeResourceTracking()
        {
            monitoredResources.Clear();
            activeAlerts.Clear();
        }

        /// <summary>
        /// Start periodic scanning
        /// </summary>
        private static void StartPeriodicScanning()
        {
            scanTimer = new Timer(async _ => await PerformComprehensiveScanAsync(), null, 
                TimeSpan.Zero, TimeSpan.FromMinutes(scanIntervalMinutes));
        }

        /// <summary>
        /// Start continuous monitoring
        /// </summary>
        private static async Task StartContinuousMonitoringAsync()
        {
            // In a real implementation, this would set up event-driven monitoring
            // For now, we rely on periodic scanning
            await Task.CompletedTask;
        }

        /// <summary>
        /// Get current status of the detector
        /// </summary>
        public static bool IsActive => isActive;

        /// <summary>
        /// Get active alerts
        /// </summary>
        public static List<MisconfigurationAlert> GetActiveAlerts() => new List<MisconfigurationAlert>(activeAlerts);

        /// <summary>
        /// Acknowledge an alert
        /// </summary>
        public static void AcknowledgeAlert(string alertId)
        {
            var alert = activeAlerts.FirstOrDefault(a => a.AlertId == alertId);
            if (alert != null)
            {
                alert.IsAcknowledged = true;
                EnhancedLogger.LogInfo($"Alert {alertId} acknowledged");
            }
        }
    }
} 
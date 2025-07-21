using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Threading;
using System.Linq;
using System.Text.Json;
using PhageVirus.Modules.CloudSecurity;

namespace PhageVirus.Modules.CloudSecurity
{
    /// <summary>
    /// Comprehensive Serverless and Container Workload Protection Module
    /// Monitors AWS Lambda, ECS, EKS, and other serverless/container workloads
    /// Provides real-time threat detection and response capabilities
    /// Offloads heavy analysis to AWS Lambda for scalable processing
    /// </summary>
    public class ServerlessContainerMonitor
    {
        private static readonly object monitorLock = new object();
        private static bool isActive = false;
        private static Timer? monitoringTimer;
        private static readonly ConcurrentDictionary<string, WorkloadInfo> monitoredWorkloads = new();
        private static readonly List<WorkloadAlert> activeAlerts = new();
        
        // Configuration
        private static int monitoringIntervalSeconds = 60;
        private static double criticalRiskThreshold = 0.8;
        private static double highRiskThreshold = 0.6;
        private static double mediumRiskThreshold = 0.4;
        
        // Security patterns for detection
        private static readonly string[] SuspiciousLambdaPatterns = {
            "eval(", "exec(", "system(", "subprocess", "os.system",
            "base64", "gzip", "zlib", "marshal", "pickle",
            "urllib", "requests", "http", "ftp", "smtp",
            "crypto", "hashlib", "hmac", "ssl", "tls"
        };
        
        private static readonly string[] SuspiciousContainerPatterns = {
            "docker.sock", "/var/run/docker.sock", "privileged: true",
            "hostNetwork: true", "hostPID: true", "hostIPC: true",
            "runAsUser: 0", "allowPrivilegeEscalation: true",
            "readOnlyRootFilesystem: false", "capabilities:"
        };
        
        private static readonly string[] HighRiskPorts = {
            "22", "23", "3389", "445", "1433", "3306", "5432", "6379", "27017"
        };

        public class WorkloadInfo
        {
            public string WorkloadId { get; set; } = "";
            public string WorkloadType { get; set; } = ""; // Lambda, ECS, EKS, Fargate
            public string WorkloadName { get; set; } = "";
            public string Arn { get; set; } = "";
            public string Region { get; set; } = "";
            public DateTime LastModified { get; set; }
            public WorkloadStatus Status { get; set; } = WorkloadStatus.Unknown;
            public Dictionary<string, object> Configuration { get; set; } = new();
            public List<string> SecurityIssues { get; set; } = new();
            public double RiskScore { get; set; } = 0.0;
            public Dictionary<string, object> Metrics { get; set; } = new();
            public bool IsActive { get; set; } = true;
        }

        public class WorkloadAlert
        {
            public string AlertId { get; set; } = Guid.NewGuid().ToString();
            public string WorkloadId { get; set; } = "";
            public string WorkloadType { get; set; } = "";
            public string AlertType { get; set; } = "";
            public string Description { get; set; } = "";
            public ThreatLevel Severity { get; set; } = ThreatLevel.Medium;
            public double RiskScore { get; set; } = 0.0;
            public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
            public bool IsAcknowledged { get; set; } = false;
            public string? RemediationGuidance { get; set; }
            public Dictionary<string, object> Context { get; set; } = new();
        }

        public class WorkloadAnalysisResult
        {
            public bool Success { get; set; }
            public string Message { get; set; } = "";
            public List<WorkloadAlert> Alerts { get; set; } = new();
            public double OverallRiskScore { get; set; } = 0.0;
            public int TotalWorkloads { get; set; } = 0;
            public int CriticalIssues { get; set; } = 0;
            public int HighIssues { get; set; } = 0;
            public int MediumIssues { get; set; } = 0;
            public List<string> Recommendations { get; set; } = new();
            public Dictionary<string, object> Metrics { get; set; } = new();
        }

        public enum WorkloadStatus
        {
            Unknown,
            Active,
            Inactive,
            Error,
            Scaling,
            Updating,
            Stopped
        }

        /// <summary>
        /// Initialize the Serverless and Container Monitor
        /// </summary>
        public static async Task InitializeAsync()
        {
            if (isActive) return;

            lock (monitorLock)
            {
                if (isActive) return;

                try
                {
                    EnhancedLogger.LogInfo("Initializing Serverless and Container Monitor...");
                    
                    // Load configuration
                    LoadConfiguration();
                    
                    // Initialize workload tracking
                    InitializeWorkloadTracking();
                    
                    // Start monitoring
                    StartMonitoring();
                    
                    isActive = true;
                    EnhancedLogger.LogSuccess("Serverless and Container Monitor initialized successfully");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to initialize Serverless and Container Monitor: {ex.Message}");
                    throw;
                }
            }
        }

        /// <summary>
        /// Start monitoring serverless and container workloads
        /// </summary>
        public static async Task MonitorWorkloadsAsync()
        {
            if (!isActive)
            {
                await InitializeAsync();
            }

            try
            {
                EnhancedLogger.LogInfo("Starting serverless and container workload monitoring...");
                
                // Perform initial comprehensive scan
                await PerformComprehensiveWorkloadScanAsync();
                
                // Start continuous monitoring
                await StartContinuousWorkloadMonitoringAsync();
                
                EnhancedLogger.LogSuccess("Serverless and container workload monitoring started successfully");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start workload monitoring: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Stop the workload monitoring
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
                    
                    EnhancedLogger.LogInfo("Serverless and Container Monitor stopped");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Error stopping Serverless and Container Monitor: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Perform comprehensive workload security scan
        /// </summary>
        public static async Task<WorkloadAnalysisResult> PerformComprehensiveWorkloadScanAsync()
        {
            var result = new WorkloadAnalysisResult();
            
            try
            {
                EnhancedLogger.LogInfo("Starting comprehensive workload security scan...");
                
                // Collect workload information
                var workloads = await CollectWorkloadsAsync();
                
                // Analyze each workload for security issues
                var analysisTasks = workloads.Select(workload => AnalyzeWorkloadAsync(workload));
                var analysisResults = await Task.WhenAll(analysisTasks);
                
                // Aggregate results
                foreach (var analysis in analysisResults)
                {
                    if (analysis != null)
                    {
                        result.Alerts.AddRange(analysis.Alerts);
                        result.TotalWorkloads++;
                        
                        if (analysis.RiskScore >= criticalRiskThreshold)
                            result.CriticalIssues++;
                        else if (analysis.RiskScore >= highRiskThreshold)
                            result.HighIssues++;
                        else if (analysis.RiskScore >= mediumRiskThreshold)
                            result.MediumIssues++;
                    }
                }
                
                // Calculate overall risk score
                result.OverallRiskScore = result.Alerts.Any() ? 
                    result.Alerts.Average(a => a.RiskScore) : 0.0;
                
                // Generate recommendations
                result.Recommendations = GenerateWorkloadRecommendations(result.Alerts);
                
                // Send analysis to cloud for additional processing
                await SendWorkloadAnalysisToCloudAsync(result);
                
                // Log results
                LogWorkloadAnalysisResults(result);
                
                result.Success = true;
                result.Message = "Comprehensive workload scan completed successfully";
                
                EnhancedLogger.LogSuccess($"Workload scan completed: {result.TotalWorkloads} workloads, {result.Alerts.Count} issues found");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"Workload scan failed: {ex.Message}";
                EnhancedLogger.LogError($"Comprehensive workload scan failed: {ex.Message}");
            }
            
            return result;
        }

        /// <summary>
        /// Collect workload information from AWS (simulated)
        /// </summary>
        private static async Task<List<WorkloadInfo>> CollectWorkloadsAsync()
        {
            var workloads = new List<WorkloadInfo>();
            
            try
            {
                // Simulate collecting Lambda functions
                workloads.Add(new WorkloadInfo
                {
                    WorkloadId = "lambda-telemetry-processor",
                    WorkloadType = "Lambda",
                    WorkloadName = "phagevirus-telemetry-processor",
                    Arn = "arn:aws:lambda:us-east-1:123456789012:function:phagevirus-telemetry-processor",
                    Region = "us-east-1",
                    LastModified = DateTime.UtcNow.AddDays(-1),
                    Status = WorkloadStatus.Active,
                    Configuration = new Dictionary<string, object>
                    {
                        { "Runtime", "dotnet8" },
                        { "MemorySize", 512 },
                        { "Timeout", 30 },
                        { "EnvironmentVariables", new Dictionary<string, string>
                            {
                                { "AWS_REGION", "us-east-1" },
                                { "S3_BUCKET", "phagevirus-logs" }
                            }
                        }
                    },
                    Metrics = new Dictionary<string, object>
                    {
                        { "Invocations", 1500 },
                        { "Duration", 250 },
                        { "Errors", 5 },
                        { "Throttles", 0 }
                    }
                });
                
                // Simulate collecting ECS services
                workloads.Add(new WorkloadInfo
                {
                    WorkloadId = "ecs-webapp-service",
                    WorkloadType = "ECS",
                    WorkloadName = "webapp-service",
                    Arn = "arn:aws:ecs:us-east-1:123456789012:service/webapp-cluster/webapp-service",
                    Region = "us-east-1",
                    LastModified = DateTime.UtcNow.AddDays(-2),
                    Status = WorkloadStatus.Active,
                    Configuration = new Dictionary<string, object>
                    {
                        { "Cluster", "webapp-cluster" },
                        { "TaskDefinition", "webapp-task:1" },
                        { "DesiredCount", 3 },
                        { "RunningCount", 3 },
                        { "NetworkMode", "awsvpc" },
                        { "SecurityGroups", new List<string> { "sg-12345678" } }
                    },
                    Metrics = new Dictionary<string, object>
                    {
                        { "CPUUtilization", 45.2 },
                        { "MemoryUtilization", 67.8 },
                        { "NetworkRxBytes", 1024000 },
                        { "NetworkTxBytes", 512000 }
                    }
                });
                
                // Simulate collecting EKS pods
                workloads.Add(new WorkloadInfo
                {
                    WorkloadId = "eks-api-pod",
                    WorkloadType = "EKS",
                    WorkloadName = "api-pod",
                    Arn = "arn:aws:eks:us-east-1:123456789012:cluster/api-cluster",
                    Region = "us-east-1",
                    LastModified = DateTime.UtcNow.AddHours(-6),
                    Status = WorkloadStatus.Active,
                    Configuration = new Dictionary<string, object>
                    {
                        { "Cluster", "api-cluster" },
                        { "Namespace", "default" },
                        { "Image", "nginx:latest" },
                        { "Ports", new List<int> { 80, 443 } },
                        { "SecurityContext", new Dictionary<string, object>
                            {
                                { "RunAsUser", 1000 },
                                { "ReadOnlyRootFilesystem", true },
                                { "AllowPrivilegeEscalation", false }
                            }
                        }
                    },
                    Metrics = new Dictionary<string, object>
                    {
                        { "CPUUsage", 25.5 },
                        { "MemoryUsage", 128 },
                        { "NetworkIO", 2048000 }
                    }
                });
                
                await Task.Delay(100); // Simulate API call delay
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error collecting workloads: {ex.Message}");
            }
            
            return workloads;
        }

        /// <summary>
        /// Analyze a single workload for security issues
        /// </summary>
        private static async Task<WorkloadAlert?> AnalyzeWorkloadAsync(WorkloadInfo workload)
        {
            try
            {
                var securityIssues = new List<string>();
                var riskScore = 0.0;
                
                // Analyze based on workload type
                switch (workload.WorkloadType.ToLower())
                {
                    case "lambda":
                        riskScore += AnalyzeLambdaWorkload(workload, securityIssues);
                        break;
                    case "ecs":
                        riskScore += AnalyzeECSWorkload(workload, securityIssues);
                        break;
                    case "eks":
                        riskScore += AnalyzeEKSWorkload(workload, securityIssues);
                        break;
                    default:
                        securityIssues.Add($"Unknown workload type: {workload.WorkloadType}");
                        riskScore += 0.1;
                        break;
                }
                
                // Check for common security issues
                riskScore += CheckCommonSecurityIssues(workload, securityIssues);
                
                // Check for suspicious metrics
                riskScore += CheckSuspiciousMetrics(workload, securityIssues);
                
                if (securityIssues.Any())
                {
                    var alert = new WorkloadAlert
                    {
                        WorkloadId = workload.WorkloadId,
                        WorkloadType = workload.WorkloadType,
                        AlertType = "WORKLOAD_SECURITY_ISSUE",
                        Description = string.Join("; ", securityIssues),
                        RiskScore = Math.Min(riskScore, 1.0),
                        Severity = riskScore >= criticalRiskThreshold ? ThreatLevel.Critical :
                                  riskScore >= highRiskThreshold ? ThreatLevel.High :
                                  ThreatLevel.Medium,
                        RemediationGuidance = GenerateWorkloadRemediationGuidance(securityIssues, workload.WorkloadType),
                        Context = new Dictionary<string, object>
                        {
                            { "WorkloadArn", workload.Arn },
                            { "WorkloadName", workload.WorkloadName },
                            { "Region", workload.Region },
                            { "Status", workload.Status.ToString() },
                            { "Configuration", workload.Configuration },
                            { "Metrics", workload.Metrics }
                        }
                    };
                    
                    return alert;
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error analyzing workload {workload.WorkloadId}: {ex.Message}");
            }
            
            return null;
        }

        /// <summary>
        /// Analyze Lambda function for security issues
        /// </summary>
        private static double AnalyzeLambdaWorkload(WorkloadInfo workload, List<string> issues)
        {
            var riskScore = 0.0;
            
            try
            {
                // Check for suspicious environment variables
                if (workload.Configuration.ContainsKey("EnvironmentVariables"))
                {
                    var envVars = workload.Configuration["EnvironmentVariables"] as Dictionary<string, string>;
                    if (envVars != null)
                    {
                        foreach (var envVar in envVars)
                        {
                            if (SuspiciousLambdaPatterns.Any(pattern => 
                                envVar.Value.ToLower().Contains(pattern.ToLower())))
                            {
                                issues.Add($"Suspicious environment variable: {envVar.Key}");
                                riskScore += 0.3;
                            }
                        }
                    }
                }
                
                // Check for excessive permissions
                if (workload.Configuration.ContainsKey("RoleArn"))
                {
                    var roleArn = workload.Configuration["RoleArn"] as string;
                    if (roleArn?.Contains("AdministratorAccess") == true)
                    {
                        issues.Add("Lambda function has administrator access");
                        riskScore += 0.5;
                    }
                }
                
                // Check for high error rates
                if (workload.Metrics.ContainsKey("Errors") && workload.Metrics.ContainsKey("Invocations"))
                {
                    var errors = Convert.ToInt32(workload.Metrics["Errors"]);
                    var invocations = Convert.ToInt32(workload.Metrics["Invocations"]);
                    if (invocations > 0 && (double)errors / invocations > 0.1)
                    {
                        issues.Add($"High error rate: {(double)errors / invocations:P1}");
                        riskScore += 0.2;
                    }
                }
                
                // Check for long execution times
                if (workload.Metrics.ContainsKey("Duration"))
                {
                    var duration = Convert.ToInt32(workload.Metrics["Duration"]);
                    if (duration > 25000) // 25 seconds
                    {
                        issues.Add($"Long execution time: {duration}ms");
                        riskScore += 0.1;
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error analyzing Lambda workload: {ex.Message}");
            }
            
            return riskScore;
        }

        /// <summary>
        /// Analyze ECS service for security issues
        /// </summary>
        private static double AnalyzeECSWorkload(WorkloadInfo workload, List<string> issues)
        {
            var riskScore = 0.0;
            
            try
            {
                // Check for privileged containers
                if (workload.Configuration.ContainsKey("TaskDefinition"))
                {
                    // In a real implementation, you would fetch the task definition
                    // For now, we'll simulate the check
                    if (workload.Configuration.ContainsKey("Privileged") && 
                        Convert.ToBoolean(workload.Configuration["Privileged"]))
                    {
                        issues.Add("ECS task is running in privileged mode");
                        riskScore += 0.4;
                    }
                }
                
                // Check for exposed ports
                if (workload.Configuration.ContainsKey("PortMappings"))
                {
                    var portMappings = workload.Configuration["PortMappings"] as List<object>;
                    if (portMappings != null)
                    {
                        foreach (var mapping in portMappings)
                        {
                            if (mapping is Dictionary<string, object> portMap)
                            {
                                if (portMap.ContainsKey("HostPort") && 
                                    HighRiskPorts.Contains(portMap["HostPort"].ToString()))
                                {
                                    issues.Add($"Exposed high-risk port: {portMap["HostPort"]}");
                                    riskScore += 0.2;
                                }
                            }
                        }
                    }
                }
                
                // Check for resource utilization
                if (workload.Metrics.ContainsKey("CPUUtilization"))
                {
                    var cpuUtil = Convert.ToDouble(workload.Metrics["CPUUtilization"]);
                    if (cpuUtil > 80)
                    {
                        issues.Add($"High CPU utilization: {cpuUtil:F1}%");
                        riskScore += 0.1;
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error analyzing ECS workload: {ex.Message}");
            }
            
            return riskScore;
        }

        /// <summary>
        /// Analyze EKS pod for security issues
        /// </summary>
        private static double AnalyzeEKSWorkload(WorkloadInfo workload, List<string> issues)
        {
            var riskScore = 0.0;
            
            try
            {
                // Check security context
                if (workload.Configuration.ContainsKey("SecurityContext"))
                {
                    var securityContext = workload.Configuration["SecurityContext"] as Dictionary<string, object>;
                    if (securityContext != null)
                    {
                        if (securityContext.ContainsKey("RunAsUser") && 
                            Convert.ToInt32(securityContext["RunAsUser"]) == 0)
                        {
                            issues.Add("Pod is running as root user");
                            riskScore += 0.4;
                        }
                        
                        if (securityContext.ContainsKey("ReadOnlyRootFilesystem") && 
                            !Convert.ToBoolean(securityContext["ReadOnlyRootFilesystem"]))
                        {
                            issues.Add("Pod has writable root filesystem");
                            riskScore += 0.2;
                        }
                        
                        if (securityContext.ContainsKey("AllowPrivilegeEscalation") && 
                            Convert.ToBoolean(securityContext["AllowPrivilegeEscalation"]))
                        {
                            issues.Add("Pod allows privilege escalation");
                            riskScore += 0.3;
                        }
                    }
                }
                
                // Check for suspicious container images
                if (workload.Configuration.ContainsKey("Image"))
                {
                    var image = workload.Configuration["Image"] as string;
                    if (image?.Contains("latest") == true)
                    {
                        issues.Add("Container using 'latest' tag");
                        riskScore += 0.1;
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error analyzing EKS workload: {ex.Message}");
            }
            
            return riskScore;
        }

        /// <summary>
        /// Check for common security issues across all workload types
        /// </summary>
        private static double CheckCommonSecurityIssues(WorkloadInfo workload, List<string> issues)
        {
            var riskScore = 0.0;
            
            // Check for inactive workloads
            if (workload.Status == WorkloadStatus.Inactive || workload.Status == WorkloadStatus.Stopped)
            {
                issues.Add($"Workload is {workload.Status.ToString().ToLower()}");
                riskScore += 0.1;
            }
            
            // Check for old workloads
            if (workload.LastModified < DateTime.UtcNow.AddDays(-90))
            {
                issues.Add("Workload hasn't been updated in over 90 days");
                riskScore += 0.1;
            }
            
            return riskScore;
        }

        /// <summary>
        /// Check for suspicious metrics
        /// </summary>
        private static double CheckSuspiciousMetrics(WorkloadInfo workload, List<string> issues)
        {
            var riskScore = 0.0;
            
            // Check for unusual network activity
            if (workload.Metrics.ContainsKey("NetworkRxBytes") && workload.Metrics.ContainsKey("NetworkTxBytes"))
            {
                var rxBytes = Convert.ToInt64(workload.Metrics["NetworkRxBytes"]);
                var txBytes = Convert.ToInt64(workload.Metrics["NetworkTxBytes"]);
                
                if (txBytes > rxBytes * 10) // Unusual outbound traffic
                {
                    issues.Add("Unusual outbound network traffic detected");
                    riskScore += 0.3;
                }
            }
            
            return riskScore;
        }

        /// <summary>
        /// Send workload analysis to cloud for additional processing
        /// </summary>
        private static async Task SendWorkloadAnalysisToCloudAsync(WorkloadAnalysisResult result)
        {
            try
            {
                var telemetryData = new
                {
                    scan_timestamp = DateTime.UtcNow,
                    total_workloads = result.TotalWorkloads,
                    total_alerts = result.Alerts.Count,
                    critical_issues = result.CriticalIssues,
                    high_issues = result.HighIssues,
                    medium_issues = result.MediumIssues,
                    overall_risk_score = result.OverallRiskScore,
                    alerts_summary = result.Alerts.Select(a => new
                    {
                        workload_type = a.WorkloadType,
                        alert_type = a.AlertType,
                        severity = a.Severity.ToString(),
                        risk_score = a.RiskScore
                    }).ToList()
                };
                
                await CloudIntegration.SendTelemetryAsync("ServerlessContainerMonitor", "workload_analysis", telemetryData, 
                    result.OverallRiskScore >= criticalRiskThreshold ? ThreatLevel.Critical :
                    result.OverallRiskScore >= highRiskThreshold ? ThreatLevel.High : ThreatLevel.Medium);
                
                // Get cloud analysis results
                var cloudAnalysis = await CloudIntegration.GetCloudAnalysisAsync("ServerlessContainerMonitor", telemetryData);
                if (cloudAnalysis.Success)
                {
                    EnhancedLogger.LogInfo($"Cloud workload analysis: {cloudAnalysis.Analysis}");
                    
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
                EnhancedLogger.LogWarning($"Failed to send workload analysis to cloud: {ex.Message}");
            }
        }

        /// <summary>
        /// Generate remediation guidance for workload issues
        /// </summary>
        private static string GenerateWorkloadRemediationGuidance(List<string> issues, string workloadType)
        {
            var guidance = new List<string>();
            
            foreach (var issue in issues)
            {
                if (issue.Contains("privileged"))
                {
                    guidance.Add("Remove privileged mode and use least privilege access");
                }
                else if (issue.Contains("root"))
                {
                    guidance.Add("Run containers as non-root user");
                }
                else if (issue.Contains("latest"))
                {
                    guidance.Add("Use specific image tags instead of 'latest'");
                }
                else if (issue.Contains("administrator"))
                {
                    guidance.Add("Implement least privilege IAM roles");
                }
                else if (issue.Contains("error rate"))
                {
                    guidance.Add("Investigate and fix function errors");
                }
                else if (issue.Contains("network"))
                {
                    guidance.Add("Review network traffic patterns and security groups");
                }
            }
            
            return string.Join("; ", guidance.Distinct());
        }

        /// <summary>
        /// Generate security recommendations based on analysis results
        /// </summary>
        private static List<string> GenerateWorkloadRecommendations(List<WorkloadAlert> alerts)
        {
            var recommendations = new List<string>();
            
            if (alerts.Any(a => a.Severity == ThreatLevel.Critical))
            {
                recommendations.Add("Immediately address critical workload security issues");
            }
            
            if (alerts.Any(a => a.Description.Contains("privileged")))
            {
                recommendations.Add("Implement least privilege access for all workloads");
            }
            
            if (alerts.Any(a => a.Description.Contains("root")))
            {
                recommendations.Add("Ensure all containers run as non-root users");
            }
            
            if (alerts.Any(a => a.Description.Contains("latest")))
            {
                recommendations.Add("Use specific image tags and implement image scanning");
            }
            
            recommendations.Add("Enable AWS Security Hub for workload compliance monitoring");
            recommendations.Add("Implement automated security scanning in CI/CD pipeline");
            recommendations.Add("Regularly review and update workload security configurations");
            
            return recommendations;
        }

        /// <summary>
        /// Log workload analysis results
        /// </summary>
        private static void LogWorkloadAnalysisResults(WorkloadAnalysisResult result)
        {
            if (result.CriticalIssues > 0)
            {
                EnhancedLogger.LogCritical($"Workload Scan: {result.CriticalIssues} critical issues found");
            }
            
            if (result.HighIssues > 0)
            {
                EnhancedLogger.LogWarning($"Workload Scan: {result.HighIssues} high-risk issues found");
            }
            
            if (result.MediumIssues > 0)
            {
                EnhancedLogger.LogInfo($"Workload Scan: {result.MediumIssues} medium-risk issues found");
            }
            
            EnhancedLogger.LogInfo($"Workload Scan Summary: {result.TotalWorkloads} workloads scanned, " +
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
                monitoringIntervalSeconds = config.GetModulePerformanceSettings("ServerlessContainerMonitor").ScanInterval;
                criticalRiskThreshold = 0.8;
                highRiskThreshold = 0.6;
                mediumRiskThreshold = 0.4;
                
                EnhancedLogger.LogInfo($"Serverless Container Monitor configuration loaded: monitoring interval = {monitoringIntervalSeconds} seconds");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to load Serverless Container Monitor configuration: {ex.Message}");
            }
        }

        /// <summary>
        /// Initialize workload tracking
        /// </summary>
        private static void InitializeWorkloadTracking()
        {
            monitoredWorkloads.Clear();
            activeAlerts.Clear();
        }

        /// <summary>
        /// Start monitoring
        /// </summary>
        private static void StartMonitoring()
        {
            monitoringTimer = new Timer(async _ => await PerformComprehensiveWorkloadScanAsync(), null, 
                TimeSpan.Zero, TimeSpan.FromSeconds(monitoringIntervalSeconds));
        }

        /// <summary>
        /// Start continuous workload monitoring
        /// </summary>
        private static async Task StartContinuousWorkloadMonitoringAsync()
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
        public static List<WorkloadAlert> GetActiveAlerts() => new List<WorkloadAlert>(activeAlerts);

        /// <summary>
        /// Acknowledge an alert
        /// </summary>
        public static void AcknowledgeAlert(string alertId)
        {
            var alert = activeAlerts.FirstOrDefault(a => a.AlertId == alertId);
            if (alert != null)
            {
                alert.IsAcknowledged = true;
                EnhancedLogger.LogInfo($"Workload alert {alertId} acknowledged");
            }
        }
    }
} 
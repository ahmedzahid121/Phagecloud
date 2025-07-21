using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Threading;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using PhageVirus.Modules.CloudSecurity;

namespace PhageVirus.Modules.CloudSecurity
{
    /// <summary>
    /// Comprehensive Infrastructure-as-Code Security Scanner
    /// Scans CloudFormation, Terraform, and other IaC files for security misconfigurations
    /// Integrates with CI/CD pipelines for automated security validation
    /// Offloads complex analysis to AWS Lambda for scalable processing
    /// </summary>
    public class IaCScanner
    {
        private static readonly object scannerLock = new object();
        private static bool isActive = false;
        private static Timer? scanTimer;
        private static readonly ConcurrentDictionary<string, IaCFile> scannedFiles = new();
        private static readonly List<IaCAlert> activeAlerts = new();
        
        // Configuration
        private static int scanIntervalMinutes = 60;
        private static double criticalRiskThreshold = 0.8;
        private static double highRiskThreshold = 0.6;
        private static double mediumRiskThreshold = 0.4;
        private static string[] scanDirectories = { ".", "infrastructure", "terraform", "cloudformation" };
        private static string[] supportedExtensions = { ".yaml", ".yml", ".json", ".tf", ".tfvars", ".hcl" };
        
        // Security patterns for detection
        private static readonly Dictionary<string, string[]> SecurityPatterns = new()
        {
            ["CloudFormation"] = {
                @"SecurityGroup.*0\.0\.0\.0/0", // Open security groups
                @"CidrIp.*0\.0\.0\.0/0", // Open CIDR blocks
                @"PublicReadAcl.*true", // Public read access
                @"PublicReadWriteAcl.*true", // Public write access
                @"Encryption.*false", // Disabled encryption
                @"VersioningConfiguration.*Status.*Suspended", // Suspended versioning
                @"AccessControl.*PublicRead", // Public access
                @"BlockPublicAcls.*false", // Public ACLs allowed
                @"IgnorePublicAcls.*false", // Public ACLs not ignored
                @"BlockPublicPolicy.*false", // Public policies allowed
                @"RestrictPublicBuckets.*false" // Public buckets allowed
            },
            ["Terraform"] = {
                @"cidr_blocks.*\[.*0\.0\.0\.0/0.*\]", // Open CIDR blocks
                @"from_port.*0", // Open ports
                @"to_port.*65535", // All ports
                @"encrypted.*false", // Disabled encryption
                @"publicly_accessible.*true", // Publicly accessible
                @"force_destroy.*true", // Force destroy enabled
                @"versioning.*Disabled", // Versioning disabled
                @"acl.*public-read", // Public read ACL
                @"acl.*public-read-write", // Public write ACL
                @"block_public_acls.*false", // Public ACLs allowed
                @"block_public_policy.*false", // Public policies allowed
                @"ignore_public_acls.*false", // Public ACLs not ignored
                @"restrict_public_buckets.*false" // Public buckets allowed
            },
            ["General"] = {
                @"password.*=.*[a-zA-Z0-9]{8,}", // Hardcoded passwords
                @"secret.*=.*[a-zA-Z0-9]{8,}", // Hardcoded secrets
                @"key.*=.*[a-zA-Z0-9]{20,}", // Hardcoded keys
                @"token.*=.*[a-zA-Z0-9]{20,}", // Hardcoded tokens
                @"admin.*=.*true", // Admin access
                @"root.*=.*true", // Root access
                @"privileged.*=.*true", // Privileged mode
                @"debug.*=.*true", // Debug mode enabled
                @"verbose.*=.*true" // Verbose logging
            }
        };

        public class IaCFile
        {
            public string FilePath { get; set; } = "";
            public string FileName { get; set; } = "";
            public string FileType { get; set; } = ""; // CloudFormation, Terraform, etc.
            public string Content { get; set; } = "";
            public DateTime LastModified { get; set; }
            public long FileSize { get; set; }
            public List<string> SecurityIssues { get; set; } = new();
            public double RiskScore { get; set; } = 0.0;
            public Dictionary<string, object> Metadata { get; set; } = new();
            public bool IsScanned { get; set; } = false;
        }

        public class IaCAlert
        {
            public string AlertId { get; set; } = Guid.NewGuid().ToString();
            public string FilePath { get; set; } = "";
            public string FileType { get; set; } = "";
            public string IssueType { get; set; } = "";
            public string Description { get; set; } = "";
            public ThreatLevel Severity { get; set; } = ThreatLevel.Medium;
            public double RiskScore { get; set; } = 0.0;
            public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
            public bool IsAcknowledged { get; set; } = false;
            public string? RemediationGuidance { get; set; }
            public Dictionary<string, object> Context { get; set; } = new();
        }

        public class IaCAnalysisResult
        {
            public bool Success { get; set; }
            public string Message { get; set; } = "";
            public List<IaCAlert> Alerts { get; set; } = new();
            public double OverallRiskScore { get; set; } = 0.0;
            public int TotalFiles { get; set; } = 0;
            public int CriticalIssues { get; set; } = 0;
            public int HighIssues { get; set; } = 0;
            public int MediumIssues { get; set; } = 0;
            public List<string> Recommendations { get; set; } = new();
            public Dictionary<string, object> Metrics { get; set; } = new();
        }

        /// <summary>
        /// Initialize the IaC Scanner
        /// </summary>
        public static async Task InitializeAsync()
        {
            if (isActive) return;

            lock (scannerLock)
            {
                if (isActive) return;

                try
                {
                    EnhancedLogger.LogInfo("Initializing IaC Security Scanner...");
                    
                    // Load configuration
                    LoadConfiguration();
                    
                    // Initialize file tracking
                    InitializeFileTracking();
                    
                    // Start periodic scanning
                    StartPeriodicScanning();
                    
                    isActive = true;
                    EnhancedLogger.LogSuccess("IaC Security Scanner initialized successfully");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to initialize IaC Security Scanner: {ex.Message}");
                    throw;
                }
            }
        }

        /// <summary>
        /// Start scanning Infrastructure-as-Code files
        /// </summary>
        public static async Task ScanIaCAsync()
        {
            if (!isActive)
            {
                await InitializeAsync();
            }

            try
            {
                EnhancedLogger.LogInfo("Starting IaC security scanning...");
                
                // Perform comprehensive scan
                await PerformComprehensiveIaCScanAsync();
                
                // Start continuous monitoring
                await StartContinuousIaCMonitoringAsync();
                
                EnhancedLogger.LogSuccess("IaC security scanning started successfully");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start IaC scanning: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Stop the IaC scanner
        /// </summary>
        public static void StopScanning()
        {
            lock (scannerLock)
            {
                if (!isActive) return;

                try
                {
                    scanTimer?.Dispose();
                    scanTimer = null;
                    isActive = false;
                    
                    EnhancedLogger.LogInfo("IaC Security Scanner stopped");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Error stopping IaC Security Scanner: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Perform comprehensive IaC security scan
        /// </summary>
        public static async Task<IaCAnalysisResult> PerformComprehensiveIaCScanAsync()
        {
            var result = new IaCAnalysisResult();
            
            try
            {
                EnhancedLogger.LogInfo("Starting comprehensive IaC security scan...");
                
                // Discover IaC files
                var iacFiles = await DiscoverIaCFilesAsync();
                
                // Scan each file for security issues
                var scanTasks = iacFiles.Select(file => ScanIaCFileAsync(file));
                var scanResults = await Task.WhenAll(scanTasks);
                
                // Aggregate results
                foreach (var scanResult in scanResults)
                {
                    if (scanResult != null)
                    {
                        result.Alerts.AddRange(scanResult.Alerts);
                        result.TotalFiles++;
                        
                        if (scanResult.RiskScore >= criticalRiskThreshold)
                            result.CriticalIssues++;
                        else if (scanResult.RiskScore >= highRiskThreshold)
                            result.HighIssues++;
                        else if (scanResult.RiskScore >= mediumRiskThreshold)
                            result.MediumIssues++;
                    }
                }
                
                // Calculate overall risk score
                result.OverallRiskScore = result.Alerts.Any() ? 
                    result.Alerts.Average(a => a.RiskScore) : 0.0;
                
                // Generate recommendations
                result.Recommendations = GenerateIaCRecommendations(result.Alerts);
                
                // Send analysis to cloud for additional processing
                await SendIaCAnalysisToCloudAsync(result);
                
                // Log results
                LogIaCAnalysisResults(result);
                
                result.Success = true;
                result.Message = "Comprehensive IaC scan completed successfully";
                
                EnhancedLogger.LogSuccess($"IaC scan completed: {result.TotalFiles} files, {result.Alerts.Count} issues found");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"IaC scan failed: {ex.Message}";
                EnhancedLogger.LogError($"Comprehensive IaC scan failed: {ex.Message}");
            }
            
            return result;
        }

        /// <summary>
        /// Discover IaC files in the specified directories
        /// </summary>
        private static async Task<List<IaCFile>> DiscoverIaCFilesAsync()
        {
            var iacFiles = new List<IaCFile>();
            
            try
            {
                foreach (var directory in scanDirectories)
                {
                    if (Directory.Exists(directory))
                    {
                        var files = Directory.GetFiles(directory, "*.*", SearchOption.AllDirectories)
                            .Where(file => supportedExtensions.Contains(Path.GetExtension(file).ToLower()))
                            .ToList();
                        
                        foreach (var filePath in files)
                        {
                            try
                            {
                                var fileInfo = new FileInfo(filePath);
                                var content = await File.ReadAllTextAsync(filePath);
                                
                                var iacFile = new IaCFile
                                {
                                    FilePath = filePath,
                                    FileName = Path.GetFileName(filePath),
                                    FileType = DetermineFileType(filePath, content),
                                    Content = content,
                                    LastModified = fileInfo.LastWriteTime,
                                    FileSize = fileInfo.Length,
                                    Metadata = new Dictionary<string, object>
                                    {
                                        { "Directory", Path.GetDirectoryName(filePath) },
                                        { "Extension", Path.GetExtension(filePath) },
                                        { "Lines", content.Split('\n').Length }
                                    }
                                };
                                
                                iacFiles.Add(iacFile);
                            }
                            catch (Exception ex)
                            {
                                EnhancedLogger.LogWarning($"Failed to read file {filePath}: {ex.Message}");
                            }
                        }
                    }
                }
                
                EnhancedLogger.LogInfo($"Discovered {iacFiles.Count} IaC files for scanning");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error discovering IaC files: {ex.Message}");
            }
            
            return iacFiles;
        }

        /// <summary>
        /// Determine the type of IaC file based on content and extension
        /// </summary>
        private static string DetermineFileType(string filePath, string content)
        {
            var extension = Path.GetExtension(filePath).ToLower();
            var fileName = Path.GetFileName(filePath).ToLower();
            
            if (fileName.Contains("cloudformation") || fileName.Contains("cfn") || 
                (extension == ".yaml" || extension == ".yml") && content.Contains("AWSTemplateFormatVersion"))
            {
                return "CloudFormation";
            }
            else if (fileName.Contains("terraform") || extension == ".tf" || extension == ".tfvars" || extension == ".hcl")
            {
                return "Terraform";
            }
            else if (extension == ".json" && (content.Contains("Resources") || content.Contains("Parameters")))
            {
                return "CloudFormation";
            }
            else
            {
                return "Unknown";
            }
        }

        /// <summary>
        /// Scan a single IaC file for security issues
        /// </summary>
        private static async Task<IaCAlert?> ScanIaCFileAsync(IaCFile iacFile)
        {
            try
            {
                var securityIssues = new List<string>();
                var riskScore = 0.0;
                
                // Scan for security patterns based on file type
                if (SecurityPatterns.ContainsKey(iacFile.FileType))
                {
                    foreach (var pattern in SecurityPatterns[iacFile.FileType])
                    {
                        var matches = Regex.Matches(iacFile.Content, pattern, RegexOptions.IgnoreCase);
                        if (matches.Count > 0)
                        {
                            var issueDescription = GetIssueDescription(pattern, iacFile.FileType);
                            securityIssues.Add($"{issueDescription} (found {matches.Count} instances)");
                            riskScore += CalculatePatternRisk(pattern, matches.Count);
                        }
                    }
                }
                
                // Scan for general security patterns
                foreach (var pattern in SecurityPatterns["General"])
                {
                    var matches = Regex.Matches(iacFile.Content, pattern, RegexOptions.IgnoreCase);
                    if (matches.Count > 0)
                    {
                        var issueDescription = GetIssueDescription(pattern, "General");
                        securityIssues.Add($"{issueDescription} (found {matches.Count} instances)");
                        riskScore += CalculatePatternRisk(pattern, matches.Count);
                    }
                }
                
                // Check for hardcoded secrets
                var secretIssues = DetectHardcodedSecrets(iacFile.Content);
                if (secretIssues.Any())
                {
                    securityIssues.AddRange(secretIssues);
                    riskScore += secretIssues.Count * 0.3;
                }
                
                // Check for overly permissive configurations
                var permissionIssues = DetectOverlyPermissiveConfigs(iacFile.Content, iacFile.FileType);
                if (permissionIssues.Any())
                {
                    securityIssues.AddRange(permissionIssues);
                    riskScore += permissionIssues.Count * 0.4;
                }
                
                if (securityIssues.Any())
                {
                    var alert = new IaCAlert
                    {
                        FilePath = iacFile.FilePath,
                        FileType = iacFile.FileType,
                        IssueType = "IAC_SECURITY_ISSUE",
                        Description = string.Join("; ", securityIssues),
                        RiskScore = Math.Min(riskScore, 1.0),
                        Severity = riskScore >= criticalRiskThreshold ? ThreatLevel.Critical :
                                  riskScore >= highRiskThreshold ? ThreatLevel.High :
                                  ThreatLevel.Medium,
                        RemediationGuidance = GenerateIaCRemediationGuidance(securityIssues, iacFile.FileType),
                        Context = new Dictionary<string, object>
                        {
                            { "FileName", iacFile.FileName },
                            { "FileSize", iacFile.FileSize },
                            { "LastModified", iacFile.LastModified },
                            { "Lines", iacFile.Content.Split('\n').Length },
                            { "Issues", securityIssues }
                        }
                    };
                    
                    return alert;
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error scanning IaC file {iacFile.FilePath}: {ex.Message}");
            }
            
            return null;
        }

        /// <summary>
        /// Get description for a security pattern
        /// </summary>
        private static string GetIssueDescription(string pattern, string fileType)
        {
            if (pattern.Contains("0.0.0.0/0"))
                return "Open security group or CIDR block detected";
            else if (pattern.Contains("PublicRead"))
                return "Public read access enabled";
            else if (pattern.Contains("PublicWrite"))
                return "Public write access enabled";
            else if (pattern.Contains("encrypted.*false"))
                return "Encryption disabled";
            else if (pattern.Contains("password.*="))
                return "Hardcoded password detected";
            else if (pattern.Contains("secret.*="))
                return "Hardcoded secret detected";
            else if (pattern.Contains("admin.*=.*true"))
                return "Admin access enabled";
            else if (pattern.Contains("privileged.*=.*true"))
                return "Privileged mode enabled";
            else
                return "Security misconfiguration detected";
        }

        /// <summary>
        /// Calculate risk score for a pattern match
        /// </summary>
        private static double CalculatePatternRisk(string pattern, int matchCount)
        {
            var baseRisk = 0.1;
            
            if (pattern.Contains("0.0.0.0/0"))
                baseRisk = 0.4;
            else if (pattern.Contains("password") || pattern.Contains("secret"))
                baseRisk = 0.5;
            else if (pattern.Contains("admin") || pattern.Contains("privileged"))
                baseRisk = 0.3;
            else if (pattern.Contains("encrypted.*false"))
                baseRisk = 0.2;
            
            return baseRisk * Math.Min(matchCount, 5); // Cap at 5 instances
        }

        /// <summary>
        /// Detect hardcoded secrets in IaC files
        /// </summary>
        private static List<string> DetectHardcodedSecrets(string content)
        {
            var issues = new List<string>();
            
            // Common secret patterns
            var secretPatterns = new[]
            {
                @"password\s*=\s*['""][^'""]{8,}['""]",
                @"secret\s*=\s*['""][^'""]{8,}['""]",
                @"key\s*=\s*['""][^'""]{20,}['""]",
                @"token\s*=\s*['""][^'""]{20,}['""]",
                @"api_key\s*=\s*['""][^'""]{20,}['""]",
                @"access_key\s*=\s*['""][^'""]{20,}['""]",
                @"private_key\s*=\s*['""][^'""]{20,}['""]"
            };
            
            foreach (var pattern in secretPatterns)
            {
                var matches = Regex.Matches(content, pattern, RegexOptions.IgnoreCase);
                if (matches.Count > 0)
                {
                    issues.Add($"Hardcoded secret detected: {matches.Count} instances");
                }
            }
            
            return issues;
        }

        /// <summary>
        /// Detect overly permissive configurations
        /// </summary>
        private static List<string> DetectOverlyPermissiveConfigs(string content, string fileType)
        {
            var issues = new List<string>();
            
            if (fileType == "CloudFormation")
            {
                if (content.Contains("Principal: '*'"))
                {
                    issues.Add("Overly permissive IAM principal (wildcard)");
                }
                if (content.Contains("Action: '*'"))
                {
                    issues.Add("Overly permissive IAM action (wildcard)");
                }
                if (content.Contains("Resource: '*'"))
                {
                    issues.Add("Overly permissive IAM resource (wildcard)");
                }
            }
            else if (fileType == "Terraform")
            {
                if (content.Contains("principal = \"*\""))
                {
                    issues.Add("Overly permissive IAM principal (wildcard)");
                }
                if (content.Contains("actions = [\"*\"]"))
                {
                    issues.Add("Overly permissive IAM action (wildcard)");
                }
                if (content.Contains("resources = [\"*\"]"))
                {
                    issues.Add("Overly permissive IAM resource (wildcard)");
                }
            }
            
            return issues;
        }

        /// <summary>
        /// Send IaC analysis to cloud for additional processing
        /// </summary>
        private static async Task SendIaCAnalysisToCloudAsync(IaCAnalysisResult result)
        {
            try
            {
                var telemetryData = new
                {
                    scan_timestamp = DateTime.UtcNow,
                    total_files = result.TotalFiles,
                    total_alerts = result.Alerts.Count,
                    critical_issues = result.CriticalIssues,
                    high_issues = result.HighIssues,
                    medium_issues = result.MediumIssues,
                    overall_risk_score = result.OverallRiskScore,
                    alerts_summary = result.Alerts.Select(a => new
                    {
                        file_type = a.FileType,
                        issue_type = a.IssueType,
                        severity = a.Severity.ToString(),
                        risk_score = a.RiskScore
                    }).ToList()
                };
                
                await CloudIntegration.SendTelemetryAsync("IaCScanner", "iac_analysis", telemetryData, 
                    result.OverallRiskScore >= criticalRiskThreshold ? ThreatLevel.Critical :
                    result.OverallRiskScore >= highRiskThreshold ? ThreatLevel.High : ThreatLevel.Medium);
                
                // Get cloud analysis results
                var cloudAnalysis = await CloudIntegration.GetCloudAnalysisAsync("IaCScanner", telemetryData);
                if (cloudAnalysis.Success)
                {
                    EnhancedLogger.LogInfo($"Cloud IaC analysis: {cloudAnalysis.Analysis}");
                    
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
                EnhancedLogger.LogWarning($"Failed to send IaC analysis to cloud: {ex.Message}");
            }
        }

        /// <summary>
        /// Generate remediation guidance for IaC issues
        /// </summary>
        private static string GenerateIaCRemediationGuidance(List<string> issues, string fileType)
        {
            var guidance = new List<string>();
            
            foreach (var issue in issues)
            {
                if (issue.Contains("Open security group"))
                {
                    guidance.Add("Restrict security group rules to specific CIDR blocks");
                }
                else if (issue.Contains("Public read access"))
                {
                    guidance.Add("Disable public read access and use private resources");
                }
                else if (issue.Contains("Public write access"))
                {
                    guidance.Add("Disable public write access and use private resources");
                }
                else if (issue.Contains("Encryption disabled"))
                {
                    guidance.Add("Enable encryption for all storage resources");
                }
                else if (issue.Contains("Hardcoded secret"))
                {
                    guidance.Add("Use parameter stores or secrets managers instead of hardcoded values");
                }
                else if (issue.Contains("Admin access"))
                {
                    guidance.Add("Implement least privilege access instead of admin permissions");
                }
                else if (issue.Contains("Privileged mode"))
                {
                    guidance.Add("Disable privileged mode and use minimal required permissions");
                }
                else if (issue.Contains("wildcard"))
                {
                    guidance.Add("Replace wildcard permissions with specific resources and actions");
                }
            }
            
            return string.Join("; ", guidance.Distinct());
        }

        /// <summary>
        /// Generate security recommendations based on analysis results
        /// </summary>
        private static List<string> GenerateIaCRecommendations(List<IaCAlert> alerts)
        {
            var recommendations = new List<string>();
            
            if (alerts.Any(a => a.Severity == ThreatLevel.Critical))
            {
                recommendations.Add("Immediately address critical IaC security issues");
            }
            
            if (alerts.Any(a => a.Description.Contains("Hardcoded secret")))
            {
                recommendations.Add("Implement secrets management for all sensitive values");
            }
            
            if (alerts.Any(a => a.Description.Contains("Open security group")))
            {
                recommendations.Add("Implement network security best practices");
            }
            
            if (alerts.Any(a => a.Description.Contains("Public access")))
            {
                recommendations.Add("Disable public access for all resources");
            }
            
            recommendations.Add("Integrate IaC scanning into CI/CD pipeline");
            recommendations.Add("Use AWS Config rules for compliance monitoring");
            recommendations.Add("Implement automated IaC validation and testing");
            recommendations.Add("Regularly review and update IaC security policies");
            
            return recommendations;
        }

        /// <summary>
        /// Log IaC analysis results
        /// </summary>
        private static void LogIaCAnalysisResults(IaCAnalysisResult result)
        {
            if (result.CriticalIssues > 0)
            {
                EnhancedLogger.LogCritical($"IaC Scan: {result.CriticalIssues} critical issues found");
            }
            
            if (result.HighIssues > 0)
            {
                EnhancedLogger.LogWarning($"IaC Scan: {result.HighIssues} high-risk issues found");
            }
            
            if (result.MediumIssues > 0)
            {
                EnhancedLogger.LogInfo($"IaC Scan: {result.MediumIssues} medium-risk issues found");
            }
            
            EnhancedLogger.LogInfo($"IaC Scan Summary: {result.TotalFiles} files scanned, " +
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
                scanIntervalMinutes = config.GetModulePerformanceSettings("IaCScanner").ScanInterval / 60;
                criticalRiskThreshold = 0.8;
                highRiskThreshold = 0.6;
                mediumRiskThreshold = 0.4;
                
                EnhancedLogger.LogInfo($"IaC Scanner configuration loaded: scan interval = {scanIntervalMinutes} minutes");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to load IaC Scanner configuration: {ex.Message}");
            }
        }

        /// <summary>
        /// Initialize file tracking
        /// </summary>
        private static void InitializeFileTracking()
        {
            scannedFiles.Clear();
            activeAlerts.Clear();
        }

        /// <summary>
        /// Start periodic scanning
        /// </summary>
        private static void StartPeriodicScanning()
        {
            scanTimer = new Timer(async _ => await PerformComprehensiveIaCScanAsync(), null, 
                TimeSpan.Zero, TimeSpan.FromMinutes(scanIntervalMinutes));
        }

        /// <summary>
        /// Start continuous IaC monitoring
        /// </summary>
        private static async Task StartContinuousIaCMonitoringAsync()
        {
            // In a real implementation, this would set up file system watchers
            // For now, we rely on periodic scanning
            await Task.CompletedTask;
        }

        /// <summary>
        /// Get current status of the scanner
        /// </summary>
        public static bool IsActive => isActive;

        /// <summary>
        /// Get active alerts
        /// </summary>
        public static List<IaCAlert> GetActiveAlerts() => new List<IaCAlert>(activeAlerts);

        /// <summary>
        /// Acknowledge an alert
        /// </summary>
        public static void AcknowledgeAlert(string alertId)
        {
            var alert = activeAlerts.FirstOrDefault(a => a.AlertId == alertId);
            if (alert != null)
            {
                alert.IsAcknowledged = true;
                EnhancedLogger.LogInfo($"IaC alert {alertId} acknowledged");
            }
        }
    }
} 
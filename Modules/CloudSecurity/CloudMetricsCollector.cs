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
    /// Comprehensive Cloud Security Metrics Collection and Analysis Module
    /// Collects real-time metrics from AWS services for security monitoring
    /// Provides dashboard-ready metrics for security operations
    /// Offloads heavy analysis to AWS Lambda for scalable processing
    /// </summary>
    public class CloudMetricsCollector
    {
        private static readonly object collectorLock = new object();
        private static bool isActive = false;
        private static Timer? collectionTimer;
        private static readonly ConcurrentDictionary<string, MetricData> collectedMetrics = new();
        private static readonly List<MetricAlert> activeAlerts = new();
        
        // Configuration
        private static int collectionIntervalSeconds = 30;
        private static double criticalThreshold = 0.8;
        private static double highThreshold = 0.6;
        private static double mediumThreshold = 0.4;
        
        // Metric categories
        private static readonly string[] MetricCategories = {
            "Security", "Compliance", "Performance", "Availability", "Cost"
        };

        public class MetricData
        {
            public string MetricId { get; set; } = "";
            public string MetricName { get; set; } = "";
            public string MetricCategory { get; set; } = "";
            public string Service { get; set; } = ""; // AWS service name
            public string Region { get; set; } = "";
            public double Value { get; set; } = 0.0;
            public string Unit { get; set; } = "";
            public DateTime Timestamp { get; set; } = DateTime.UtcNow;
            public Dictionary<string, object> Dimensions { get; set; } = new();
            public double Threshold { get; set; } = 0.0;
            public bool IsAlerting { get; set; } = false;
            public ThreatLevel Severity { get; set; } = ThreatLevel.Normal;
        }

        public class MetricAlert
        {
            public string AlertId { get; set; } = Guid.NewGuid().ToString();
            public string MetricId { get; set; } = "";
            public string MetricName { get; set; } = "";
            public string AlertType { get; set; } = "";
            public string Description { get; set; } = "";
            public ThreatLevel Severity { get; set; } = ThreatLevel.Medium;
            public double CurrentValue { get; set; } = 0.0;
            public double Threshold { get; set; } = 0.0;
            public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
            public bool IsAcknowledged { get; set; } = false;
            public string? RemediationGuidance { get; set; }
            public Dictionary<string, object> Context { get; set; } = new();
        }

        public class MetricsAnalysisResult
        {
            public bool Success { get; set; }
            public string Message { get; set; } = "";
            public List<MetricAlert> Alerts { get; set; } = new();
            public double OverallHealthScore { get; set; } = 0.0;
            public int TotalMetrics { get; set; } = 0;
            public int CriticalAlerts { get; set; } = 0;
            public int HighAlerts { get; set; } = 0;
            public int MediumAlerts { get; set; } = 0;
            public List<string> Recommendations { get; set; } = new();
            public Dictionary<string, object> DashboardMetrics { get; set; } = new();
        }

        /// <summary>
        /// Initialize the Cloud Metrics Collector
        /// </summary>
        public static async Task InitializeAsync()
        {
            if (isActive) return;

            lock (collectorLock)
            {
                if (isActive) return;

                try
                {
                    EnhancedLogger.LogInfo("Initializing Cloud Metrics Collector...");
                    
                    // Load configuration
                    LoadConfiguration();
                    
                    // Initialize metrics tracking
                    InitializeMetricsTracking();
                    
                    // Start collection
                    StartCollection();
                    
                    isActive = true;
                    EnhancedLogger.LogSuccess("Cloud Metrics Collector initialized successfully");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to initialize Cloud Metrics Collector: {ex.Message}");
                    throw;
                }
            }
        }

        /// <summary>
        /// Start collecting cloud security metrics
        /// </summary>
        public static async Task CollectMetricsAsync()
        {
            if (!isActive)
            {
                await InitializeAsync();
            }

            try
            {
                EnhancedLogger.LogInfo("Starting cloud security metrics collection...");
                
                // Perform initial comprehensive collection
                await PerformComprehensiveMetricsCollectionAsync();
                
                // Start continuous collection
                await StartContinuousMetricsCollectionAsync();
                
                EnhancedLogger.LogSuccess("Cloud security metrics collection started successfully");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start metrics collection: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Stop the metrics collector
        /// </summary>
        public static void StopCollection()
        {
            lock (collectorLock)
            {
                if (!isActive) return;

                try
                {
                    collectionTimer?.Dispose();
                    collectionTimer = null;
                    isActive = false;
                    
                    EnhancedLogger.LogInfo("Cloud Metrics Collector stopped");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Error stopping Cloud Metrics Collector: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Perform comprehensive metrics collection and analysis
        /// </summary>
        public static async Task<MetricsAnalysisResult> PerformComprehensiveMetricsCollectionAsync()
        {
            var result = new MetricsAnalysisResult();
            
            try
            {
                EnhancedLogger.LogInfo("Starting comprehensive cloud metrics collection...");
                
                // Collect metrics from various AWS services
                var securityMetrics = await CollectSecurityMetricsAsync();
                var complianceMetrics = await CollectComplianceMetricsAsync();
                var performanceMetrics = await CollectPerformanceMetricsAsync();
                var availabilityMetrics = await CollectAvailabilityMetricsAsync();
                var costMetrics = await CollectCostMetricsAsync();
                
                // Combine all metrics
                var allMetrics = new List<MetricData>();
                allMetrics.AddRange(securityMetrics);
                allMetrics.AddRange(complianceMetrics);
                allMetrics.AddRange(performanceMetrics);
                allMetrics.AddRange(availabilityMetrics);
                allMetrics.AddRange(costMetrics);
                
                // Analyze metrics for alerts
                var analysisTasks = allMetrics.Select(metric => AnalyzeMetricAsync(metric));
                var analysisResults = await Task.WhenAll(analysisTasks);
                
                // Aggregate results
                foreach (var analysis in analysisResults)
                {
                    if (analysis != null)
                    {
                        result.Alerts.Add(analysis);
                        result.TotalMetrics++;
                        
                        if (analysis.Severity == ThreatLevel.Critical)
                            result.CriticalAlerts++;
                        else if (analysis.Severity == ThreatLevel.High)
                            result.HighAlerts++;
                        else if (analysis.Severity == ThreatLevel.Medium)
                            result.MediumAlerts++;
                    }
                }
                
                // Calculate overall health score
                result.OverallHealthScore = CalculateOverallHealthScore(allMetrics);
                
                // Generate dashboard metrics
                result.DashboardMetrics = GenerateDashboardMetrics(allMetrics);
                
                // Generate recommendations
                result.Recommendations = GenerateMetricsRecommendations(result.Alerts);
                
                // Send analysis to cloud for additional processing
                await SendMetricsAnalysisToCloudAsync(result);
                
                // Log results
                LogMetricsAnalysisResults(result);
                
                result.Success = true;
                result.Message = "Comprehensive metrics collection completed successfully";
                
                EnhancedLogger.LogSuccess($"Metrics collection completed: {result.TotalMetrics} metrics, {result.Alerts.Count} alerts found");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"Metrics collection failed: {ex.Message}";
                EnhancedLogger.LogError($"Comprehensive metrics collection failed: {ex.Message}");
            }
            
            return result;
        }

        /// <summary>
        /// Collect security-related metrics
        /// </summary>
        private static async Task<List<MetricData>> CollectSecurityMetricsAsync()
        {
            var metrics = new List<MetricData>();
            
            try
            {
                // Simulate collecting security metrics from AWS services
                
                // IAM metrics
                metrics.Add(new MetricData
                {
                    MetricId = "iam-users-count",
                    MetricName = "IAM Users Count",
                    MetricCategory = "Security",
                    Service = "IAM",
                    Region = "us-east-1",
                    Value = 25,
                    Unit = "Count",
                    Threshold = 50,
                    Dimensions = new Dictionary<string, object>
                    {
                        { "AccountId", "123456789012" },
                        { "Service", "IAM" }
                    }
                });
                
                metrics.Add(new MetricData
                {
                    MetricId = "iam-root-usage",
                    MetricName = "Root Account Usage",
                    MetricCategory = "Security",
                    Service = "IAM",
                    Region = "us-east-1",
                    Value = 0,
                    Unit = "Count",
                    Threshold = 0,
                    Dimensions = new Dictionary<string, object>
                    {
                        { "AccountId", "123456789012" },
                        { "Service", "IAM" }
                    }
                });
                
                // Security Hub metrics
                metrics.Add(new MetricData
                {
                    MetricId = "security-hub-findings",
                    MetricName = "Security Hub Findings",
                    MetricCategory = "Security",
                    Service = "SecurityHub",
                    Region = "us-east-1",
                    Value = 15,
                    Unit = "Count",
                    Threshold = 10,
                    Dimensions = new Dictionary<string, object>
                    {
                        { "AccountId", "123456789012" },
                        { "Service", "SecurityHub" }
                    }
                });
                
                // GuardDuty metrics
                metrics.Add(new MetricData
                {
                    MetricId = "guardduty-findings",
                    MetricName = "GuardDuty Findings",
                    MetricCategory = "Security",
                    Service = "GuardDuty",
                    Region = "us-east-1",
                    Value = 3,
                    Unit = "Count",
                    Threshold = 5,
                    Dimensions = new Dictionary<string, object>
                    {
                        { "AccountId", "123456789012" },
                        { "Service", "GuardDuty" }
                    }
                });
                
                // CloudTrail metrics
                metrics.Add(new MetricData
                {
                    MetricId = "cloudtrail-api-calls",
                    MetricName = "CloudTrail API Calls",
                    MetricCategory = "Security",
                    Service = "CloudTrail",
                    Region = "us-east-1",
                    Value = 15000,
                    Unit = "Count",
                    Threshold = 10000,
                    Dimensions = new Dictionary<string, object>
                    {
                        { "AccountId", "123456789012" },
                        { "Service", "CloudTrail" }
                    }
                });
                
                await Task.Delay(100); // Simulate API call delay
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error collecting security metrics: {ex.Message}");
            }
            
            return metrics;
        }

        /// <summary>
        /// Collect compliance-related metrics
        /// </summary>
        private static async Task<List<MetricData>> CollectComplianceMetricsAsync()
        {
            var metrics = new List<MetricData>();
            
            try
            {
                // Config compliance metrics
                metrics.Add(new MetricData
                {
                    MetricId = "config-compliance-score",
                    MetricName = "Config Compliance Score",
                    MetricCategory = "Compliance",
                    Service = "Config",
                    Region = "us-east-1",
                    Value = 85.5,
                    Unit = "Percent",
                    Threshold = 90.0,
                    Dimensions = new Dictionary<string, object>
                    {
                        { "AccountId", "123456789012" },
                        { "Service", "Config" }
                    }
                });
                
                // Security Hub compliance
                metrics.Add(new MetricData
                {
                    MetricId = "security-hub-compliance",
                    MetricName = "Security Hub Compliance",
                    MetricCategory = "Compliance",
                    Service = "SecurityHub",
                    Region = "us-east-1",
                    Value = 92.0,
                    Unit = "Percent",
                    Threshold = 95.0,
                    Dimensions = new Dictionary<string, object>
                    {
                        { "AccountId", "123456789012" },
                        { "Service", "SecurityHub" }
                    }
                });
                
                await Task.Delay(50); // Simulate API call delay
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error collecting compliance metrics: {ex.Message}");
            }
            
            return metrics;
        }

        /// <summary>
        /// Collect performance-related metrics
        /// </summary>
        private static async Task<List<MetricData>> CollectPerformanceMetricsAsync()
        {
            var metrics = new List<MetricData>();
            
            try
            {
                // Lambda performance metrics
                metrics.Add(new MetricData
                {
                    MetricId = "lambda-duration",
                    MetricName = "Lambda Average Duration",
                    MetricCategory = "Performance",
                    Service = "Lambda",
                    Region = "us-east-1",
                    Value = 250,
                    Unit = "Milliseconds",
                    Threshold = 1000,
                    Dimensions = new Dictionary<string, object>
                    {
                        { "FunctionName", "phagevirus-telemetry-processor" },
                        { "Service", "Lambda" }
                    }
                });
                
                metrics.Add(new MetricData
                {
                    MetricId = "lambda-errors",
                    MetricName = "Lambda Error Rate",
                    MetricCategory = "Performance",
                    Service = "Lambda",
                    Region = "us-east-1",
                    Value = 0.5,
                    Unit = "Percent",
                    Threshold = 1.0,
                    Dimensions = new Dictionary<string, object>
                    {
                        { "FunctionName", "phagevirus-telemetry-processor" },
                        { "Service", "Lambda" }
                    }
                });
                
                await Task.Delay(50); // Simulate API call delay
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error collecting performance metrics: {ex.Message}");
            }
            
            return metrics;
        }

        /// <summary>
        /// Collect availability-related metrics
        /// </summary>
        private static async Task<List<MetricData>> CollectAvailabilityMetricsAsync()
        {
            var metrics = new List<MetricData>();
            
            try
            {
                // Service availability metrics
                metrics.Add(new MetricData
                {
                    MetricId = "service-availability",
                    MetricName = "Service Availability",
                    MetricCategory = "Availability",
                    Service = "Global",
                    Region = "us-east-1",
                    Value = 99.95,
                    Unit = "Percent",
                    Threshold = 99.9,
                    Dimensions = new Dictionary<string, object>
                    {
                        { "AccountId", "123456789012" },
                        { "Service", "Global" }
                    }
                });
                
                await Task.Delay(50); // Simulate API call delay
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error collecting availability metrics: {ex.Message}");
            }
            
            return metrics;
        }

        /// <summary>
        /// Collect cost-related metrics
        /// </summary>
        private static async Task<List<MetricData>> CollectCostMetricsAsync()
        {
            var metrics = new List<MetricData>();
            
            try
            {
                // Cost metrics
                metrics.Add(new MetricData
                {
                    MetricId = "monthly-cost",
                    MetricName = "Monthly Cost",
                    MetricCategory = "Cost",
                    Service = "CostExplorer",
                    Region = "us-east-1",
                    Value = 1250.75,
                    Unit = "USD",
                    Threshold = 2000.0,
                    Dimensions = new Dictionary<string, object>
                    {
                        { "AccountId", "123456789012" },
                        { "Service", "CostExplorer" }
                    }
                });
                
                await Task.Delay(50); // Simulate API call delay
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error collecting cost metrics: {ex.Message}");
            }
            
            return metrics;
        }

        /// <summary>
        /// Analyze a single metric for alerts
        /// </summary>
        private static async Task<MetricAlert?> AnalyzeMetricAsync(MetricData metric)
        {
            try
            {
                var isAlerting = false;
                var severity = ThreatLevel.Normal;
                var description = "";
                
                // Check if metric exceeds threshold
                if (metric.Value > metric.Threshold)
                {
                    isAlerting = true;
                    
                    // Determine severity based on how much it exceeds threshold
                    var ratio = metric.Value / metric.Threshold;
                    
                    if (ratio >= 2.0)
                    {
                        severity = ThreatLevel.Critical;
                        description = $"Critical: {metric.MetricName} is {ratio:F1}x above threshold";
                    }
                    else if (ratio >= 1.5)
                    {
                        severity = ThreatLevel.High;
                        description = $"High: {metric.MetricName} is {ratio:F1}x above threshold";
                    }
                    else
                    {
                        severity = ThreatLevel.Medium;
                        description = $"Medium: {metric.MetricName} is {ratio:F1}x above threshold";
                    }
                }
                else if (metric.Value < metric.Threshold * 0.5 && metric.Threshold > 0)
                {
                    // Check for unusually low values (might indicate issues)
                    isAlerting = true;
                    severity = ThreatLevel.Medium;
                    description = $"Medium: {metric.MetricName} is unusually low";
                }
                
                if (isAlerting)
                {
                    var alert = new MetricAlert
                    {
                        MetricId = metric.MetricId,
                        MetricName = metric.MetricName,
                        AlertType = "METRIC_THRESHOLD_EXCEEDED",
                        Description = description,
                        Severity = severity,
                        CurrentValue = metric.Value,
                        Threshold = metric.Threshold,
                        RemediationGuidance = GenerateMetricRemediationGuidance(metric),
                        Context = new Dictionary<string, object>
                        {
                            { "Service", metric.Service },
                            { "Region", metric.Region },
                            { "Category", metric.MetricCategory },
                            { "Unit", metric.Unit },
                            { "Dimensions", metric.Dimensions }
                        }
                    };
                    
                    return alert;
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error analyzing metric {metric.MetricId}: {ex.Message}");
            }
            
            return null;
        }

        /// <summary>
        /// Calculate overall health score
        /// </summary>
        private static double CalculateOverallHealthScore(List<MetricData> metrics)
        {
            if (!metrics.Any()) return 100.0;
            
            var totalScore = 0.0;
            var totalMetrics = 0;
            
            foreach (var metric in metrics)
            {
                if (metric.Threshold > 0)
                {
                    var ratio = metric.Value / metric.Threshold;
                    var score = ratio <= 1.0 ? 100.0 : Math.Max(0, 100 - (ratio - 1.0) * 50);
                    totalScore += score;
                    totalMetrics++;
                }
            }
            
            return totalMetrics > 0 ? totalScore / totalMetrics : 100.0;
        }

        /// <summary>
        /// Generate dashboard metrics
        /// </summary>
        private static Dictionary<string, object> GenerateDashboardMetrics(List<MetricData> metrics)
        {
            var dashboardMetrics = new Dictionary<string, object>();
            
            try
            {
                // Group metrics by category
                var securityMetrics = metrics.Where(m => m.MetricCategory == "Security").ToList();
                var complianceMetrics = metrics.Where(m => m.MetricCategory == "Compliance").ToList();
                var performanceMetrics = metrics.Where(m => m.MetricCategory == "Performance").ToList();
                var availabilityMetrics = metrics.Where(m => m.MetricCategory == "Availability").ToList();
                var costMetrics = metrics.Where(m => m.MetricCategory == "Cost").ToList();
                
                // Calculate summary statistics
                dashboardMetrics["Security"] = new
                {
                    TotalMetrics = securityMetrics.Count,
                    AlertingMetrics = securityMetrics.Count(m => m.IsAlerting),
                    AverageValue = securityMetrics.Any() ? securityMetrics.Average(m => m.Value) : 0.0
                };
                
                dashboardMetrics["Compliance"] = new
                {
                    TotalMetrics = complianceMetrics.Count,
                    AlertingMetrics = complianceMetrics.Count(m => m.IsAlerting),
                    AverageValue = complianceMetrics.Any() ? complianceMetrics.Average(m => m.Value) : 0.0
                };
                
                dashboardMetrics["Performance"] = new
                {
                    TotalMetrics = performanceMetrics.Count,
                    AlertingMetrics = performanceMetrics.Count(m => m.IsAlerting),
                    AverageValue = performanceMetrics.Any() ? performanceMetrics.Average(m => m.Value) : 0.0
                };
                
                dashboardMetrics["Availability"] = new
                {
                    TotalMetrics = availabilityMetrics.Count,
                    AlertingMetrics = availabilityMetrics.Count(m => m.IsAlerting),
                    AverageValue = availabilityMetrics.Any() ? availabilityMetrics.Average(m => m.Value) : 0.0
                };
                
                dashboardMetrics["Cost"] = new
                {
                    TotalMetrics = costMetrics.Count,
                    AlertingMetrics = costMetrics.Count(m => m.IsAlerting),
                    AverageValue = costMetrics.Any() ? costMetrics.Average(m => m.Value) : 0.0
                };
                
                // Overall statistics
                dashboardMetrics["Overall"] = new
                {
                    TotalMetrics = metrics.Count,
                    AlertingMetrics = metrics.Count(m => m.IsAlerting),
                    HealthScore = CalculateOverallHealthScore(metrics),
                    LastUpdated = DateTime.UtcNow
                };
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error generating dashboard metrics: {ex.Message}");
            }
            
            return dashboardMetrics;
        }

        /// <summary>
        /// Send metrics analysis to cloud for additional processing
        /// </summary>
        private static async Task SendMetricsAnalysisToCloudAsync(MetricsAnalysisResult result)
        {
            try
            {
                var telemetryData = new
                {
                    collection_timestamp = DateTime.UtcNow,
                    total_metrics = result.TotalMetrics,
                    total_alerts = result.Alerts.Count,
                    critical_alerts = result.CriticalAlerts,
                    high_alerts = result.HighAlerts,
                    medium_alerts = result.MediumAlerts,
                    overall_health_score = result.OverallHealthScore,
                    dashboard_metrics = result.DashboardMetrics
                };
                
                await CloudIntegration.SendTelemetryAsync("CloudMetricsCollector", "metrics_analysis", telemetryData, 
                    result.OverallHealthScore < 80 ? ThreatLevel.High : ThreatLevel.Normal);
                
                // Get cloud analysis results
                var cloudAnalysis = await CloudIntegration.GetCloudAnalysisAsync("CloudMetricsCollector", telemetryData);
                if (cloudAnalysis.Success)
                {
                    EnhancedLogger.LogInfo($"Cloud metrics analysis: {cloudAnalysis.Analysis}");
                    
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
                EnhancedLogger.LogWarning($"Failed to send metrics analysis to cloud: {ex.Message}");
            }
        }

        /// <summary>
        /// Generate remediation guidance for metric alerts
        /// </summary>
        private static string GenerateMetricRemediationGuidance(MetricData metric)
        {
            switch (metric.MetricName)
            {
                case "IAM Users Count":
                    return "Review and remove unnecessary IAM users";
                case "Root Account Usage":
                    return "Disable root account access and use IAM users";
                case "Security Hub Findings":
                    return "Address security findings in Security Hub console";
                case "GuardDuty Findings":
                    return "Investigate and remediate GuardDuty findings";
                case "Config Compliance Score":
                    return "Fix non-compliant resources in AWS Config";
                case "Lambda Error Rate":
                    return "Investigate and fix Lambda function errors";
                case "Monthly Cost":
                    return "Review and optimize AWS resource usage";
                default:
                    return "Review metric configuration and thresholds";
            }
        }

        /// <summary>
        /// Generate recommendations based on analysis results
        /// </summary>
        private static List<string> GenerateMetricsRecommendations(List<MetricAlert> alerts)
        {
            var recommendations = new List<string>();
            
            if (alerts.Any(a => a.Severity == ThreatLevel.Critical))
            {
                recommendations.Add("Immediately address critical metric alerts");
            }
            
            if (alerts.Any(a => a.MetricName.Contains("IAM")))
            {
                recommendations.Add("Review and optimize IAM configurations");
            }
            
            if (alerts.Any(a => a.MetricName.Contains("Security")))
            {
                recommendations.Add("Address security findings and improve compliance");
            }
            
            if (alerts.Any(a => a.MetricName.Contains("Lambda")))
            {
                recommendations.Add("Optimize Lambda functions for better performance");
            }
            
            recommendations.Add("Set up automated alerting for critical metrics");
            recommendations.Add("Implement metric-based dashboards for monitoring");
            recommendations.Add("Regularly review and adjust metric thresholds");
            
            return recommendations;
        }

        /// <summary>
        /// Log metrics analysis results
        /// </summary>
        private static void LogMetricsAnalysisResults(MetricsAnalysisResult result)
        {
            if (result.CriticalAlerts > 0)
            {
                EnhancedLogger.LogCritical($"Metrics Collection: {result.CriticalAlerts} critical alerts found");
            }
            
            if (result.HighAlerts > 0)
            {
                EnhancedLogger.LogWarning($"Metrics Collection: {result.HighAlerts} high-risk alerts found");
            }
            
            if (result.MediumAlerts > 0)
            {
                EnhancedLogger.LogInfo($"Metrics Collection: {result.MediumAlerts} medium-risk alerts found");
            }
            
            EnhancedLogger.LogInfo($"Metrics Collection Summary: {result.TotalMetrics} metrics collected, " +
                                 $"Health score: {result.OverallHealthScore:F1}%");
        }

        /// <summary>
        /// Load configuration from UnifiedConfig
        /// </summary>
        private static void LoadConfiguration()
        {
            try
            {
                var config = UnifiedConfig.Instance;
                collectionIntervalSeconds = config.GetModulePerformanceSettings("CloudMetricsCollector").ScanInterval;
                criticalThreshold = 0.8;
                highThreshold = 0.6;
                mediumThreshold = 0.4;
                
                EnhancedLogger.LogInfo($"Cloud Metrics Collector configuration loaded: collection interval = {collectionIntervalSeconds} seconds");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to load Cloud Metrics Collector configuration: {ex.Message}");
            }
        }

        /// <summary>
        /// Initialize metrics tracking
        /// </summary>
        private static void InitializeMetricsTracking()
        {
            collectedMetrics.Clear();
            activeAlerts.Clear();
        }

        /// <summary>
        /// Start collection
        /// </summary>
        private static void StartCollection()
        {
            collectionTimer = new Timer(async _ => await PerformComprehensiveMetricsCollectionAsync(), null, 
                TimeSpan.Zero, TimeSpan.FromSeconds(collectionIntervalSeconds));
        }

        /// <summary>
        /// Start continuous metrics collection
        /// </summary>
        private static async Task StartContinuousMetricsCollectionAsync()
        {
            // In a real implementation, this would set up continuous monitoring
            // For now, we rely on periodic collection
            await Task.CompletedTask;
        }

        /// <summary>
        /// Get current status of the collector
        /// </summary>
        public static bool IsActive => isActive;

        /// <summary>
        /// Get active alerts
        /// </summary>
        public static List<MetricAlert> GetActiveAlerts() => new List<MetricAlert>(activeAlerts);

        /// <summary>
        /// Get dashboard metrics
        /// </summary>
        public static Dictionary<string, object> GetDashboardMetrics()
        {
            var metrics = collectedMetrics.Values.ToList();
            return GenerateDashboardMetrics(metrics);
        }

        /// <summary>
        /// Acknowledge an alert
        /// </summary>
        public static void AcknowledgeAlert(string alertId)
        {
            var alert = activeAlerts.FirstOrDefault(a => a.AlertId == alertId);
            if (alert != null)
            {
                alert.IsAcknowledged = true;
                EnhancedLogger.LogInfo($"Metric alert {alertId} acknowledged");
            }
        }
    }
} 
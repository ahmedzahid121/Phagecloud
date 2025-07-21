using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using PhageVirus.Agent.Shared;

namespace PhageVirus.Agent.Security
{
    /// <summary>
    /// Advanced threat detection engine with behavioral AI models and real-time monitoring
    /// </summary>
    public class ThreatDetectionEngine
    {
        private readonly ILogger<ThreatDetectionEngine> _logger;
        private readonly IConfiguration _configuration;
        private readonly SecurityManager _securityManager;
        private readonly Dictionary<string, FileIntegrityInfo> _fileIntegrityCache;
        private readonly List<BehavioralRule> _behavioralRules;
        private readonly List<KqlQuery> _kqlQueries;
        private readonly Dictionary<string, ThreatScore> _threatScores;
        
        private bool _isInitialized = false;
        private readonly object _detectionLock = new object();

        public ThreatDetectionEngine(IConfiguration configuration, ILogger<ThreatDetectionEngine> logger, SecurityManager securityManager)
        {
            _configuration = configuration;
            _logger = logger;
            _securityManager = securityManager;
            _fileIntegrityCache = new Dictionary<string, FileIntegrityInfo>();
            _behavioralRules = LoadBehavioralRules();
            _kqlQueries = LoadKqlQueries();
            _threatScores = new Dictionary<string, ThreatScore>();
        }

        public async Task InitializeAsync()
        {
            if (_isInitialized)
                return;

            lock (_detectionLock)
            {
                if (_isInitialized)
                    return;

                try
                {
                    _logger.LogInformation("Initializing advanced threat detection engine");

                    // Initialize file integrity monitoring
                    InitializeFileIntegrityMonitoring();

                    // Initialize behavioral AI models
                    InitializeBehavioralModels();

                    // Initialize KQL query engine
                    InitializeKqlEngine();

                    // Initialize threat scoring
                    InitializeThreatScoring();

                    _isInitialized = true;
                    _logger.LogInformation("Threat detection engine initialized successfully");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to initialize threat detection engine");
                    throw;
                }
            }
        }

        public async Task<ThreatDetectionResult> AnalyzeThreatAsync(ThreatData threatData)
        {
            try
            {
                _logger.LogDebug("Analyzing threat with advanced detection engine");

                var result = new ThreatDetectionResult
                {
                    ThreatId = Guid.NewGuid().ToString(),
                    Timestamp = DateTime.UtcNow,
                    OriginalThreat = threatData,
                    DetectionMethods = new List<string>(),
                    BehavioralAnalysis = new BehavioralAnalysisResult(),
                    FileIntegrityChecks = new List<FileIntegrityResult>(),
                    KqlAnalysis = new List<KqlAnalysisResult>(),
                    ThreatScore = new ThreatScore(),
                    Recommendations = new List<string>()
                };

                // Perform behavioral analysis
                result.BehavioralAnalysis = await PerformBehavioralAnalysisAsync(threatData);

                // Perform file integrity checks
                result.FileIntegrityChecks = await PerformFileIntegrityChecksAsync(threatData);

                // Perform KQL analysis
                result.KqlAnalysis = await PerformKqlAnalysisAsync(threatData);

                // Calculate overall threat score
                result.ThreatScore = CalculateOverallThreatScore(result);

                // Generate recommendations
                result.Recommendations = GenerateRecommendations(result);

                // Log detection results
                LogDetectionResults(result);

                _logger.LogInformation($"Threat analysis completed: Score {result.ThreatScore.OverallScore:F2}");
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing threat");
                throw;
            }
        }

        public async Task<bool> DetectAnomalousBehaviorAsync(ProcessInfo process)
        {
            try
            {
                _logger.LogDebug($"Detecting anomalous behavior for process: {process.ProcessName}");

                // Check against behavioral rules
                foreach (var rule in _behavioralRules)
                {
                    if (await EvaluateBehavioralRuleAsync(rule, process))
                    {
                        _logger.LogWarning($"Anomalous behavior detected: {rule.Name} for process {process.ProcessName}");
                        return true;
                    }
                }

                // Check against AI models
                if (await EvaluateAIModelAsync(process))
                {
                    _logger.LogWarning($"AI model detected anomalous behavior for process {process.ProcessName}");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error detecting anomalous behavior");
                return false;
            }
        }

        public async Task<FileIntegrityResult> CheckFileIntegrityAsync(string filePath)
        {
            try
            {
                _logger.LogDebug($"Checking file integrity: {filePath}");

                if (!File.Exists(filePath))
                {
                    return new FileIntegrityResult
                    {
                        FilePath = filePath,
                        IsValid = false,
                        Reason = "File does not exist"
                    };
                }

                var fileInfo = new FileInfo(filePath);
                var currentHash = await CalculateFileHashAsync(filePath);
                var lastModified = fileInfo.LastWriteTimeUtc;

                // Check cache
                if (_fileIntegrityCache.TryGetValue(filePath, out var cachedInfo))
                {
                    if (cachedInfo.Hash == currentHash && cachedInfo.LastModified == lastModified)
                    {
                        return new FileIntegrityResult
                        {
                            FilePath = filePath,
                            IsValid = true,
                            Hash = currentHash,
                            LastModified = lastModified
                        };
                    }
                    else
                    {
                        // File has changed
                        _logger.LogWarning($"File integrity violation detected: {filePath}");
                        return new FileIntegrityResult
                        {
                            FilePath = filePath,
                            IsValid = false,
                            Reason = "File content or modification time changed",
                            PreviousHash = cachedInfo.Hash,
                            CurrentHash = currentHash,
                            PreviousModified = cachedInfo.LastModified,
                            LastModified = lastModified
                        };
                    }
                }

                // Add to cache
                _fileIntegrityCache[filePath] = new FileIntegrityInfo
                {
                    Hash = currentHash,
                    LastModified = lastModified,
                    FirstSeen = DateTime.UtcNow
                };

                return new FileIntegrityResult
                {
                    FilePath = filePath,
                    IsValid = true,
                    Hash = currentHash,
                    LastModified = lastModified
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error checking file integrity: {filePath}");
                return new FileIntegrityResult
                {
                    FilePath = filePath,
                    IsValid = false,
                    Reason = $"Error: {ex.Message}"
                };
            }
        }

        public async Task<List<KqlAnalysisResult>> ExecuteKqlQueriesAsync(string data)
        {
            try
            {
                _logger.LogDebug("Executing KQL queries");

                var results = new List<KqlAnalysisResult>();

                foreach (var query in _kqlQueries)
                {
                    var result = await ExecuteKqlQueryAsync(query, data);
                    if (result != null)
                    {
                        results.Add(result);
                    }
                }

                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error executing KQL queries");
                return new List<KqlAnalysisResult>();
            }
        }

        #region Behavioral Analysis

        private async Task<BehavioralAnalysisResult> PerformBehavioralAnalysisAsync(ThreatData threatData)
        {
            try
            {
                var result = new BehavioralAnalysisResult
                {
                    Timestamp = DateTime.UtcNow,
                    RuleMatches = new List<BehavioralRuleMatch>(),
                    AnomalyScore = 0.0,
                    RiskLevel = RiskLevel.Low
                };

                // Analyze process behavior
                if (threatData.ProcessInfo != null)
                {
                    foreach (var rule in _behavioralRules)
                    {
                        if (await EvaluateBehavioralRuleAsync(rule, threatData.ProcessInfo))
                        {
                            result.RuleMatches.Add(new BehavioralRuleMatch
                            {
                                RuleName = rule.Name,
                                RuleDescription = rule.Description,
                                Severity = rule.Severity,
                                Confidence = rule.Confidence
                            });
                        }
                    }
                }

                // Calculate anomaly score
                result.AnomalyScore = CalculateAnomalyScore(result.RuleMatches);
                result.RiskLevel = DetermineRiskLevel(result.AnomalyScore);

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error performing behavioral analysis");
                return new BehavioralAnalysisResult
                {
                    Timestamp = DateTime.UtcNow,
                    AnomalyScore = 0.0,
                    RiskLevel = RiskLevel.Low
                };
            }
        }

        private async Task<bool> EvaluateBehavioralRuleAsync(BehavioralRule rule, ProcessInfo process)
        {
            try
            {
                switch (rule.Type)
                {
                    case RuleType.CommandLine:
                        return EvaluateCommandLineRule(rule, process);
                    case RuleType.MemoryUsage:
                        return EvaluateMemoryUsageRule(rule, process);
                    case RuleType.NetworkActivity:
                        return EvaluateNetworkActivityRule(rule, process);
                    case RuleType.FileAccess:
                        return EvaluateFileAccessRule(rule, process);
                    case RuleType.RegistryAccess:
                        return EvaluateRegistryAccessRule(rule, process);
                    default:
                        return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error evaluating behavioral rule: {rule.Name}");
                return false;
            }
        }

        private bool EvaluateCommandLineRule(BehavioralRule rule, ProcessInfo process)
        {
            try
            {
                if (string.IsNullOrEmpty(process.CommandLine))
                    return false;

                var commandLine = process.CommandLine.ToLower();
                return rule.Patterns.Any(pattern => Regex.IsMatch(commandLine, pattern, RegexOptions.IgnoreCase));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error evaluating command line rule");
                return false;
            }
        }

        private bool EvaluateMemoryUsageRule(BehavioralRule rule, ProcessInfo process)
        {
            try
            {
                var memoryUsageMB = process.MemoryUsage / (1024 * 1024);
                return memoryUsageMB > rule.Threshold;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error evaluating memory usage rule");
                return false;
            }
        }

        private bool EvaluateNetworkActivityRule(BehavioralRule rule, ProcessInfo process)
        {
            try
            {
                // This would check network connections for the process
                // Implementation depends on network monitoring capabilities
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error evaluating network activity rule");
                return false;
            }
        }

        private bool EvaluateFileAccessRule(BehavioralRule rule, ProcessInfo process)
        {
            try
            {
                // This would check file access patterns for the process
                // Implementation depends on file system monitoring capabilities
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error evaluating file access rule");
                return false;
            }
        }

        private bool EvaluateRegistryAccessRule(BehavioralRule rule, ProcessInfo process)
        {
            try
            {
                // This would check registry access patterns for the process
                // Implementation depends on registry monitoring capabilities
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error evaluating registry access rule");
                return false;
            }
        }

        private async Task<bool> EvaluateAIModelAsync(ProcessInfo process)
        {
            try
            {
                // This would use a trained AI model to detect anomalies
                // For now, return false (no AI model implemented)
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error evaluating AI model");
                return false;
            }
        }

        #endregion

        #region File Integrity Monitoring

        private void InitializeFileIntegrityMonitoring()
        {
            try
            {
                _logger.LogDebug("Initializing file integrity monitoring");

                // Monitor critical system files
                var criticalFiles = new[]
                {
                    Path.Combine(Environment.SystemDirectory, "kernel32.dll"),
                    Path.Combine(Environment.SystemDirectory, "ntdll.dll"),
                    Path.Combine(Environment.SystemDirectory, "user32.dll"),
                    Process.GetCurrentProcess().MainModule?.FileName ?? string.Empty
                };

                foreach (var file in criticalFiles)
                {
                    if (File.Exists(file))
                    {
                        _ = Task.Run(async () => await CheckFileIntegrityAsync(file));
                    }
                }

                // Start periodic integrity checks
                _ = Task.Run(async () =>
                {
                    while (_isInitialized)
                    {
                        await Task.Delay(TimeSpan.FromMinutes(5));
                        await PerformPeriodicIntegrityChecksAsync();
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error initializing file integrity monitoring");
            }
        }

        private async Task<List<FileIntegrityResult>> PerformFileIntegrityChecksAsync(ThreatData threatData)
        {
            try
            {
                var results = new List<FileIntegrityResult>();

                // Check files mentioned in threat data
                if (threatData.FilePaths != null)
                {
                    foreach (var filePath in threatData.FilePaths)
                    {
                        var result = await CheckFileIntegrityAsync(filePath);
                        results.Add(result);
                    }
                }

                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error performing file integrity checks");
                return new List<FileIntegrityResult>();
            }
        }

        private async Task PerformPeriodicIntegrityChecksAsync()
        {
            try
            {
                foreach (var kvp in _fileIntegrityCache.ToList())
                {
                    var result = await CheckFileIntegrityAsync(kvp.Key);
                    if (!result.IsValid)
                    {
                        _logger.LogWarning($"Periodic integrity check failed: {kvp.Key}");
                        // Handle integrity violation
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error performing periodic integrity checks");
            }
        }

        private async Task<string> CalculateFileHashAsync(string filePath)
        {
            try
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                var hash = await Task.Run(() => sha256.ComputeHash(stream));
                return Convert.ToBase64String(hash);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error calculating file hash: {filePath}");
                return string.Empty;
            }
        }

        #endregion

        #region KQL Analysis

        private void InitializeKqlEngine()
        {
            try
            {
                _logger.LogDebug("Initializing KQL query engine");
                // KQL engine initialization would go here
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error initializing KQL engine");
            }
        }

        private async Task<List<KqlAnalysisResult>> PerformKqlAnalysisAsync(ThreatData threatData)
        {
            try
            {
                var results = new List<KqlAnalysisResult>();

                // Convert threat data to KQL format
                var kqlData = ConvertThreatDataToKql(threatData);

                // Execute KQL queries
                foreach (var query in _kqlQueries)
                {
                    var result = await ExecuteKqlQueryAsync(query, kqlData);
                    if (result != null)
                    {
                        results.Add(result);
                    }
                }

                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error performing KQL analysis");
                return new List<KqlAnalysisResult>();
            }
        }

        private async Task<KqlAnalysisResult?> ExecuteKqlQueryAsync(KqlQuery query, string data)
        {
            try
            {
                // This would execute the actual KQL query
                // For now, simulate query execution
                var result = new KqlAnalysisResult
                {
                    QueryName = query.Name,
                    QueryDescription = query.Description,
                    Timestamp = DateTime.UtcNow,
                    Matches = new List<string>(),
                    Severity = query.Severity
                };

                // Simulate query matching
                if (data.Contains(query.SearchTerm))
                {
                    result.Matches.Add($"Found '{query.SearchTerm}' in data");
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error executing KQL query: {query.Name}");
                return null;
            }
        }

        private string ConvertThreatDataToKql(ThreatData threatData)
        {
            try
            {
                var kqlData = new
                {
                    threatData.ThreatType,
                    threatData.Severity,
                    threatData.Timestamp,
                    threatData.ProcessInfo?.ProcessName,
                    threatData.ProcessInfo?.CommandLine,
                    threatData.FilePaths,
                    threatData.NetworkConnections
                };

                return JsonSerializer.Serialize(kqlData);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error converting threat data to KQL");
                return string.Empty;
            }
        }

        #endregion

        #region Threat Scoring

        private void InitializeThreatScoring()
        {
            try
            {
                _logger.LogDebug("Initializing threat scoring system");
                // Threat scoring initialization would go here
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error initializing threat scoring");
            }
        }

        private ThreatScore CalculateOverallThreatScore(ThreatDetectionResult result)
        {
            try
            {
                var score = new ThreatScore
                {
                    Timestamp = DateTime.UtcNow,
                    BehavioralScore = CalculateBehavioralScore(result.BehavioralAnalysis),
                    IntegrityScore = CalculateIntegrityScore(result.FileIntegrityChecks),
                    KqlScore = CalculateKqlScore(result.KqlAnalysis),
                    OverallScore = 0.0
                };

                // Calculate weighted overall score
                score.OverallScore = (score.BehavioralScore * 0.4) + 
                                   (score.IntegrityScore * 0.3) + 
                                   (score.KqlScore * 0.3);

                return score;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calculating overall threat score");
                return new ThreatScore
                {
                    Timestamp = DateTime.UtcNow,
                    OverallScore = 0.0
                };
            }
        }

        private double CalculateBehavioralScore(BehavioralAnalysisResult analysis)
        {
            try
            {
                if (analysis.RuleMatches.Count == 0)
                    return 0.0;

                var totalScore = analysis.RuleMatches.Sum(match => 
                    (double)match.Severity * match.Confidence);
                
                return Math.Min(totalScore / analysis.RuleMatches.Count, 100.0);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calculating behavioral score");
                return 0.0;
            }
        }

        private double CalculateIntegrityScore(List<FileIntegrityResult> integrityChecks)
        {
            try
            {
                if (integrityChecks.Count == 0)
                    return 0.0;

                var violations = integrityChecks.Count(check => !check.IsValid);
                return (violations / (double)integrityChecks.Count) * 100.0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calculating integrity score");
                return 0.0;
            }
        }

        private double CalculateKqlScore(List<KqlAnalysisResult> kqlResults)
        {
            try
            {
                if (kqlResults.Count == 0)
                    return 0.0;

                var totalScore = kqlResults.Sum(result => (double)result.Severity);
                return Math.Min(totalScore / kqlResults.Count, 100.0);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calculating KQL score");
                return 0.0;
            }
        }

        #endregion

        #region Behavioral Models

        private void InitializeBehavioralModels()
        {
            try
            {
                _logger.LogDebug("Initializing behavioral AI models");
                // AI model initialization would go here
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error initializing behavioral models");
            }
        }

        private double CalculateAnomalyScore(List<BehavioralRuleMatch> ruleMatches)
        {
            try
            {
                if (ruleMatches.Count == 0)
                    return 0.0;

                var totalScore = ruleMatches.Sum(match => 
                    (double)match.Severity * match.Confidence);
                
                return Math.Min(totalScore / ruleMatches.Count, 100.0);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calculating anomaly score");
                return 0.0;
            }
        }

        private RiskLevel DetermineRiskLevel(double anomalyScore)
        {
            return anomalyScore switch
            {
                < 25 => RiskLevel.Low,
                < 50 => RiskLevel.Medium,
                < 75 => RiskLevel.High,
                _ => RiskLevel.Critical
            };
        }

        #endregion

        #region Configuration Loading

        private List<BehavioralRule> LoadBehavioralRules()
        {
            try
            {
                return new List<BehavioralRule>
                {
                    new BehavioralRule
                    {
                        Name = "Suspicious PowerShell",
                        Description = "Detects suspicious PowerShell command patterns",
                        Type = RuleType.CommandLine,
                        Patterns = new[] { @"powershell.*-enc", @"powershell.*-e", @"iex.*http" },
                        Severity = ThreatSeverity.High,
                        Confidence = 0.8,
                        Threshold = 0
                    },
                    new BehavioralRule
                    {
                        Name = "High Memory Usage",
                        Description = "Detects processes with unusually high memory usage",
                        Type = RuleType.MemoryUsage,
                        Patterns = new string[0],
                        Severity = ThreatSeverity.Medium,
                        Confidence = 0.6,
                        Threshold = 500 // MB
                    },
                    new BehavioralRule
                    {
                        Name = "Suspicious Network Activity",
                        Description = "Detects suspicious network connection patterns",
                        Type = RuleType.NetworkActivity,
                        Patterns = new[] { @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+" },
                        Severity = ThreatSeverity.High,
                        Confidence = 0.7,
                        Threshold = 0
                    }
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading behavioral rules");
                return new List<BehavioralRule>();
            }
        }

        private List<KqlQuery> LoadKqlQueries()
        {
            try
            {
                return new List<KqlQuery>
                {
                    new KqlQuery
                    {
                        Name = "Suspicious Process Creation",
                        Description = "Detects suspicious process creation patterns",
                        Query = "ProcessCreation | where ProcessName contains 'powershell' and CommandLine contains '-enc'",
                        SearchTerm = "powershell",
                        Severity = ThreatSeverity.High
                    },
                    new KqlQuery
                    {
                        Name = "File System Anomalies",
                        Description = "Detects unusual file system activity",
                        Query = "FileSystemActivity | where FileName endswith '.exe' and FilePath contains 'temp'",
                        SearchTerm = ".exe",
                        Severity = ThreatSeverity.Medium
                    },
                    new KqlQuery
                    {
                        Name = "Registry Modifications",
                        Description = "Detects suspicious registry modifications",
                        Query = "RegistryActivity | where RegistryKey contains 'Run' and RegistryValue contains 'http'",
                        SearchTerm = "registry",
                        Severity = ThreatSeverity.High
                    }
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading KQL queries");
                return new List<KqlQuery>();
            }
        }

        #endregion

        #region Recommendations

        private List<string> GenerateRecommendations(ThreatDetectionResult result)
        {
            try
            {
                var recommendations = new List<string>();

                if (result.ThreatScore.OverallScore > 75)
                {
                    recommendations.Add("Immediate isolation recommended - high threat score detected");
                    recommendations.Add("Enable enhanced monitoring and logging");
                }

                if (result.BehavioralAnalysis.RiskLevel >= RiskLevel.High)
                {
                    recommendations.Add("Terminate suspicious processes immediately");
                    recommendations.Add("Review and update behavioral rules");
                }

                if (result.FileIntegrityChecks.Any(check => !check.IsValid))
                {
                    recommendations.Add("File integrity violations detected - system compromise possible");
                    recommendations.Add("Perform full system scan and restore from backup");
                }

                if (result.KqlAnalysis.Any(analysis => analysis.Severity >= ThreatSeverity.High))
                {
                    recommendations.Add("KQL analysis indicates advanced threats");
                    recommendations.Add("Enable real-time threat hunting");
                }

                return recommendations;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating recommendations");
                return new List<string>();
            }
        }

        #endregion

        #region Logging

        private void LogDetectionResults(ThreatDetectionResult result)
        {
            try
            {
                var logEntry = new
                {
                    result.ThreatId,
                    result.Timestamp,
                    result.ThreatScore.OverallScore,
                    result.BehavioralAnalysis.RiskLevel,
                    FileIntegrityViolations = result.FileIntegrityChecks.Count(check => !check.IsValid),
                    KqlMatches = result.KqlAnalysis.Count,
                    result.Recommendations
                };

                _logger.LogInformation($"Threat detection results: {JsonSerializer.Serialize(logEntry)}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging detection results");
            }
        }

        #endregion

        #region Data Classes

        public class ThreatDetectionResult
        {
            public string ThreatId { get; set; } = string.Empty;
            public DateTime Timestamp { get; set; }
            public ThreatData? OriginalThreat { get; set; }
            public List<string> DetectionMethods { get; set; } = new();
            public BehavioralAnalysisResult BehavioralAnalysis { get; set; } = new();
            public List<FileIntegrityResult> FileIntegrityChecks { get; set; } = new();
            public List<KqlAnalysisResult> KqlAnalysis { get; set; } = new();
            public ThreatScore ThreatScore { get; set; } = new();
            public List<string> Recommendations { get; set; } = new();
        }

        public class BehavioralAnalysisResult
        {
            public DateTime Timestamp { get; set; }
            public List<BehavioralRuleMatch> RuleMatches { get; set; } = new();
            public double AnomalyScore { get; set; }
            public RiskLevel RiskLevel { get; set; }
        }

        public class BehavioralRuleMatch
        {
            public string RuleName { get; set; } = string.Empty;
            public string RuleDescription { get; set; } = string.Empty;
            public ThreatSeverity Severity { get; set; }
            public double Confidence { get; set; }
        }

        public class FileIntegrityResult
        {
            public string FilePath { get; set; } = string.Empty;
            public bool IsValid { get; set; }
            public string? Reason { get; set; }
            public string? Hash { get; set; }
            public DateTime? LastModified { get; set; }
            public string? PreviousHash { get; set; }
            public DateTime? PreviousModified { get; set; }
        }

        public class KqlAnalysisResult
        {
            public string QueryName { get; set; } = string.Empty;
            public string QueryDescription { get; set; } = string.Empty;
            public DateTime Timestamp { get; set; }
            public List<string> Matches { get; set; } = new();
            public ThreatSeverity Severity { get; set; }
        }

        public class ThreatScore
        {
            public DateTime Timestamp { get; set; }
            public double BehavioralScore { get; set; }
            public double IntegrityScore { get; set; }
            public double KqlScore { get; set; }
            public double OverallScore { get; set; }
        }

        public class BehavioralRule
        {
            public string Name { get; set; } = string.Empty;
            public string Description { get; set; } = string.Empty;
            public RuleType Type { get; set; }
            public string[] Patterns { get; set; } = Array.Empty<string>();
            public ThreatSeverity Severity { get; set; }
            public double Confidence { get; set; }
            public double Threshold { get; set; }
        }

        public class KqlQuery
        {
            public string Name { get; set; } = string.Empty;
            public string Description { get; set; } = string.Empty;
            public string Query { get; set; } = string.Empty;
            public string SearchTerm { get; set; } = string.Empty;
            public ThreatSeverity Severity { get; set; }
        }

        public class FileIntegrityInfo
        {
            public string Hash { get; set; } = string.Empty;
            public DateTime LastModified { get; set; }
            public DateTime FirstSeen { get; set; }
        }

        public enum RuleType
        {
            CommandLine,
            MemoryUsage,
            NetworkActivity,
            FileAccess,
            RegistryAccess
        }

        public enum RiskLevel
        {
            Low,
            Medium,
            High,
            Critical
        }

        #endregion

        #region Public Properties

        public bool IsInitialized => _isInitialized;
        public int FileIntegrityCacheCount => _fileIntegrityCache.Count;
        public int BehavioralRulesCount => _behavioralRules.Count;
        public int KqlQueriesCount => _kqlQueries.Count;

        #endregion
    }
} 
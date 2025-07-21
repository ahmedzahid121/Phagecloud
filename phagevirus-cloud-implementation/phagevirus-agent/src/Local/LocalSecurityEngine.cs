using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using PhageVirus.Agent.Shared;

namespace PhageVirus.Agent.Local
{
    public class LocalSecurityEngine
    {
        private readonly ILogger<LocalSecurityEngine> _logger;
        private readonly IConfiguration _configuration;
        private readonly CancellationTokenSource _cancellationTokenSource;
        
        private bool _isRunning = false;
        private readonly List<ILocalSecurityModule> _modules = new();
        private readonly Dictionary<string, object> _threatCache = new();

        public LocalSecurityEngine(IConfiguration configuration, ILogger<LocalSecurityEngine> logger)
        {
            _configuration = configuration;
            _logger = logger;
            _cancellationTokenSource = new CancellationTokenSource();
            
            InitializeModules();
        }

        private void InitializeModules()
        {
            var enabledModules = _configuration.GetSection("local:modules").Get<Dictionary<string, bool>>() ?? new();

            if (enabledModules.GetValueOrDefault("ProcessWatcher", false))
            {
                _modules.Add(new LightweightProcessWatcher(_configuration, _logger));
            }

            if (enabledModules.GetValueOrDefault("MemoryTrap", false))
            {
                _modules.Add(new LightweightMemoryTrap(_configuration, _logger));
            }

            if (enabledModules.GetValueOrDefault("CredentialTrap", false))
            {
                _modules.Add(new LightweightCredentialTrap(_configuration, _logger));
            }

            if (enabledModules.GetValueOrDefault("ExploitShield", false))
            {
                _modules.Add(new LightweightExploitShield(_configuration, _logger));
            }

            if (enabledModules.GetValueOrDefault("FirewallGuard", false))
            {
                _modules.Add(new LightweightFirewallGuard(_configuration, _logger));
            }

            _logger.LogInformation($"Initialized {_modules.Count} local security modules");
        }

        public async Task StartAsync()
        {
            if (_isRunning)
            {
                _logger.LogWarning("Local security engine is already running");
                return;
            }

            _logger.LogInformation("Starting local security engine");
            _isRunning = true;

            try
            {
                // Start all modules
                var startTasks = _modules.Select(module => module.StartAsync());
                await Task.WhenAll(startTasks);

                // Start monitoring loop
                _ = Task.Run(MonitoringLoopAsync, _cancellationTokenSource.Token);

                _logger.LogInformation("Local security engine started successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to start local security engine");
                throw;
            }
        }

        public async Task StopAsync()
        {
            if (!_isRunning)
            {
                return;
            }

            _logger.LogInformation("Stopping local security engine");
            _isRunning = false;

            try
            {
                _cancellationTokenSource.Cancel();

                // Stop all modules
                var stopTasks = _modules.Select(module => module.StopAsync());
                await Task.WhenAll(stopTasks);

                _logger.LogInformation("Local security engine stopped successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error stopping local security engine");
            }
        }

        private async Task MonitoringLoopAsync()
        {
            var scanInterval = _configuration.GetValue<int>("local:scan_interval", 60);
            var maxMemoryUsage = _configuration.GetValue<int>("local:max_memory_usage", 100);

            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                try
                {
                    // Check system resources
                    if (IsSystemOverloaded(maxMemoryUsage))
                    {
                        _logger.LogWarning("System overloaded, skipping scan cycle");
                        await Task.Delay(TimeSpan.FromSeconds(30), _cancellationTokenSource.Token);
                        continue;
                    }

                    // Run quick threat scan
                    await RunQuickThreatScanAsync();

                    // Wait for next cycle
                    await Task.Delay(TimeSpan.FromSeconds(scanInterval), _cancellationTokenSource.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in monitoring loop");
                    await Task.Delay(TimeSpan.FromSeconds(30), _cancellationTokenSource.Token);
                }
            }
        }

        private bool IsSystemOverloaded(int maxMemoryUsageMB)
        {
            try
            {
                var process = Process.GetCurrentProcess();
                var memoryUsageMB = process.WorkingSet64 / (1024 * 1024);
                
                return memoryUsageMB > maxMemoryUsageMB;
            }
            catch
            {
                return false;
            }
        }

        private async Task RunQuickThreatScanAsync()
        {
            try
            {
                var threats = new List<ThreatData>();

                // Quick process scan
                var suspiciousProcesses = await ScanSuspiciousProcessesAsync();
                threats.AddRange(suspiciousProcesses);

                // Quick memory scan (if enabled)
                if (_modules.Any(m => m is LightweightMemoryTrap))
                {
                    var memoryThreats = await ScanMemoryThreatsAsync();
                    threats.AddRange(memoryThreats);
                }

                // Process threats
                foreach (var threat in threats)
                {
                    await ProcessThreatAsync(threat);
                }

                if (threats.Count > 0)
                {
                    _logger.LogInformation($"Quick scan found {threats.Count} potential threats");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in quick threat scan");
            }
        }

        private async Task<List<ThreatData>> ScanSuspiciousProcessesAsync()
        {
            var threats = new List<ThreatData>();
            var suspiciousKeywords = new[] { "stealer", "keylogger", "trojan", "backdoor", "miner", "bot", "spy" };

            try
            {
                var processes = Process.GetProcesses();
                
                foreach (var process in processes.Take(50)) // Limit to first 50 processes
                {
                    try
                    {
                        var processName = process.ProcessName.ToLower();
                        
                        // Check for suspicious names
                        if (suspiciousKeywords.Any(keyword => processName.Contains(keyword)))
                        {
                            threats.Add(new ThreatData
                            {
                                AgentId = Environment.MachineName + "_" + Environment.UserName,
                                Timestamp = DateTime.UtcNow,
                                ThreatType = "SuspiciousProcess",
                                Target = process.ProcessName,
                                Description = $"Suspicious process name: {process.ProcessName}",
                                Severity = ThreatSeverity.Medium,
                                Metadata = new Dictionary<string, object>
                                {
                                    ["ProcessId"] = process.Id,
                                    ["MemoryUsage"] = process.WorkingSet64,
                                    ["StartTime"] = process.StartTime
                                }
                            });
                        }

                        // Check for high memory usage
                        if (process.WorkingSet64 > 500 * 1024 * 1024) // 500MB
                        {
                            threats.Add(new ThreatData
                            {
                                AgentId = Environment.MachineName + "_" + Environment.UserName,
                                Timestamp = DateTime.UtcNow,
                                ThreatType = "HighMemoryProcess",
                                Target = process.ProcessName,
                                Description = $"High memory usage: {process.ProcessName} ({process.WorkingSet64 / (1024 * 1024)}MB)",
                                Severity = ThreatSeverity.Low,
                                Metadata = new Dictionary<string, object>
                                {
                                    ["ProcessId"] = process.Id,
                                    ["MemoryUsage"] = process.WorkingSet64,
                                    ["Threshold"] = 500 * 1024 * 1024
                                }
                            });
                        }
                    }
                    catch
                    {
                        // Skip processes we can't access
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error scanning suspicious processes");
            }

            return threats;
        }

        private async Task<List<ThreatData>> ScanMemoryThreatsAsync()
        {
            var threats = new List<ThreatData>();

            try
            {
                // This is a simplified memory scan for the lightweight version
                // In a real implementation, you'd do more thorough scanning
                var processes = Process.GetProcesses().Take(10); // Only scan first 10 processes

                foreach (var process in processes)
                {
                    try
                    {
                        // Quick check for suspicious memory patterns
                        if (process.WorkingSet64 > 200 * 1024 * 1024) // 200MB threshold
                        {
                            threats.Add(new ThreatData
                            {
                                AgentId = Environment.MachineName + "_" + Environment.UserName,
                                Timestamp = DateTime.UtcNow,
                                ThreatType = "MemoryAnomaly",
                                Target = process.ProcessName,
                                Description = $"Large memory usage detected: {process.ProcessName}",
                                Severity = ThreatSeverity.Low,
                                Metadata = new Dictionary<string, object>
                                {
                                    ["ProcessId"] = process.Id,
                                    ["MemoryUsage"] = process.WorkingSet64,
                                    ["Threshold"] = 200 * 1024 * 1024
                                }
                            });
                        }
                    }
                    catch
                    {
                        // Skip processes we can't access
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error scanning memory threats");
            }

            return threats;
        }

        private async Task ProcessThreatAsync(ThreatData threat)
        {
            try
            {
                // Check if we've seen this threat recently
                var threatKey = $"{threat.ThreatType}_{threat.Target}";
                if (_threatCache.ContainsKey(threatKey))
                {
                    var lastSeen = (DateTime)_threatCache[threatKey];
                    if (DateTime.UtcNow - lastSeen < TimeSpan.FromMinutes(5))
                    {
                        return; // Skip if seen recently
                    }
                }

                // Update cache
                _threatCache[threatKey] = DateTime.UtcNow;

                // Log the threat
                _logger.LogWarning($"Local threat detected: {threat.ThreatType} - {threat.Description}");

                // Take local action based on severity
                switch (threat.Severity)
                {
                    case ThreatSeverity.Critical:
                        await HandleCriticalThreatAsync(threat);
                        break;
                    case ThreatSeverity.High:
                        await HandleHighThreatAsync(threat);
                        break;
                    case ThreatSeverity.Medium:
                        await HandleMediumThreatAsync(threat);
                        break;
                    case ThreatSeverity.Low:
                        await HandleLowThreatAsync(threat);
                        break;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing threat");
            }
        }

        private async Task HandleCriticalThreatAsync(ThreatData threat)
        {
            _logger.LogError($"CRITICAL THREAT: {threat.Description}");
            // In a real implementation, you'd take immediate action
            // For now, just log it
        }

        private async Task HandleHighThreatAsync(ThreatData threat)
        {
            _logger.LogWarning($"HIGH THREAT: {threat.Description}");
            // Log and monitor closely
        }

        private async Task HandleMediumThreatAsync(ThreatData threat)
        {
            _logger.LogInformation($"MEDIUM THREAT: {threat.Description}");
            // Log for analysis
        }

        private async Task HandleLowThreatAsync(ThreatData threat)
        {
            _logger.LogDebug($"LOW THREAT: {threat.Description}");
            // Log for trending analysis
        }

        public async Task<ThreatAnalysisResult> AnalyzeThreatAsync(ThreatData threatData)
        {
            try
            {
                var result = new ThreatAnalysisResult
                {
                    AnalysisId = Guid.NewGuid().ToString(),
                    Timestamp = DateTime.UtcNow,
                    AnalysisSource = "local",
                    DetectedPatterns = new List<string>(),
                    Recommendations = new List<string>(),
                    AnalysisMetadata = new Dictionary<string, object>()
                };

                // Quick local analysis
                switch (threatData.ThreatType)
                {
                    case "SuspiciousProcess":
                        result.RiskScore = 0.7;
                        result.Confidence = 0.6;
                        result.DetectedPatterns.Add("Suspicious process name");
                        result.Recommendations.Add("Investigate process legitimacy");
                        result.CalculatedSeverity = ThreatSeverity.Medium;
                        break;

                    case "HighMemoryProcess":
                        result.RiskScore = 0.3;
                        result.Confidence = 0.8;
                        result.DetectedPatterns.Add("Unusual memory usage");
                        result.Recommendations.Add("Monitor process behavior");
                        result.CalculatedSeverity = ThreatSeverity.Low;
                        break;

                    case "MemoryAnomaly":
                        result.RiskScore = 0.5;
                        result.Confidence = 0.7;
                        result.DetectedPatterns.Add("Memory usage anomaly");
                        result.Recommendations.Add("Perform deep memory analysis");
                        result.CalculatedSeverity = ThreatSeverity.Medium;
                        break;

                    default:
                        result.RiskScore = 0.1;
                        result.Confidence = 0.5;
                        result.CalculatedSeverity = ThreatSeverity.Low;
                        break;
                }

                result.RequiresImmediateAction = result.RiskScore > 0.8;

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing threat locally");
                return CreateDefaultAnalysisResult();
            }
        }

        private ThreatAnalysisResult CreateDefaultAnalysisResult()
        {
            return new ThreatAnalysisResult
            {
                AnalysisId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                RiskScore = 0.0,
                Confidence = 0.0,
                DetectedPatterns = new List<string>(),
                Recommendations = new List<string>(),
                AnalysisSource = "local",
                CalculatedSeverity = ThreatSeverity.Low,
                RequiresImmediateAction = false,
                AnalysisMetadata = new Dictionary<string, object>()
            };
        }
    }

    public interface ILocalSecurityModule
    {
        Task StartAsync();
        Task StopAsync();
    }
} 
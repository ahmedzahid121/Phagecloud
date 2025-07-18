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
    public class LightweightProcessWatcher : ILocalSecurityModule
    {
        private readonly ILogger<LightweightProcessWatcher> _logger;
        private readonly IConfiguration _configuration;
        private readonly CancellationTokenSource _cancellationTokenSource;
        
        private bool _isRunning = false;
        private readonly HashSet<int> _monitoredProcesses = new();
        private readonly Dictionary<string, DateTime> _threatCache = new();

        private static readonly string[] SuspiciousKeywords = {
            "stealer", "keylogger", "trojan", "backdoor", "miner", "bot", "spy",
            "hack", "crack", "inject", "hook", "dump", "steal"
        };

        private static readonly string[] HighRiskExecutables = {
            "powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe",
            "rundll32.exe", "regsvr32.exe", "nc.exe", "ncat.exe", "telnet.exe"
        };

        public LightweightProcessWatcher(IConfiguration configuration, ILogger<LightweightProcessWatcher> logger)
        {
            _configuration = configuration;
            _logger = logger;
            _cancellationTokenSource = new CancellationTokenSource();
        }

        public async Task StartAsync()
        {
            if (_isRunning)
            {
                _logger.LogWarning("Lightweight process watcher is already running");
                return;
            }

            _logger.LogInformation("Starting lightweight process watcher");
            _isRunning = true;

            try
            {
                // Start monitoring loop
                _ = Task.Run(MonitoringLoopAsync, _cancellationTokenSource.Token);

                _logger.LogInformation("Lightweight process watcher started successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to start lightweight process watcher");
                throw;
            }
        }

        public async Task StopAsync()
        {
            if (!_isRunning)
            {
                return;
            }

            _logger.LogInformation("Stopping lightweight process watcher");
            _isRunning = false;

            try
            {
                _cancellationTokenSource.Cancel();
                _logger.LogInformation("Lightweight process watcher stopped successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error stopping lightweight process watcher");
            }
        }

        private async Task MonitoringLoopAsync()
        {
            var scanInterval = _configuration.GetValue<int>("local:scan_interval", 60);

            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                try
                {
                    await ScanProcessesAsync();
                    await Task.Delay(TimeSpan.FromSeconds(scanInterval), _cancellationTokenSource.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in process monitoring loop");
                    await Task.Delay(TimeSpan.FromSeconds(30), _cancellationTokenSource.Token);
                }
            }
        }

        private async Task ScanProcessesAsync()
        {
            try
            {
                var processes = Process.GetProcesses();
                var currentProcessIds = new HashSet<int>();

                foreach (var process in processes.Take(100)) // Limit to first 100 processes
                {
                    try
                    {
                        currentProcessIds.Add(process.Id);

                        // Check if this is a new process we haven't seen before
                        if (!_monitoredProcesses.Contains(process.Id))
                        {
                            await AnalyzeProcessAsync(process);
                            _monitoredProcesses.Add(process.Id);
                        }
                    }
                    catch
                    {
                        // Skip processes we can't access
                    }
                }

                // Clean up terminated processes
                _monitoredProcesses.RemoveWhere(id => !currentProcessIds.Contains(id));

                // Limit monitored processes to prevent memory leaks
                if (_monitoredProcesses.Count > 1000)
                {
                    var oldestProcesses = _monitoredProcesses.Take(500).ToList();
                    foreach (var processId in oldestProcesses)
                    {
                        _monitoredProcesses.Remove(processId);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error scanning processes");
            }
        }

        private async Task AnalyzeProcessAsync(Process process)
        {
            try
            {
                var threatLevel = ThreatSeverity.Low;
                var detectedPatterns = new List<string>();

                // Check process name
                var processName = process.ProcessName.ToLower();
                
                // Check for suspicious keywords
                if (SuspiciousKeywords.Any(keyword => processName.Contains(keyword)))
                {
                    threatLevel = ThreatSeverity.High;
                    detectedPatterns.Add($"Suspicious process name: {process.ProcessName}");
                }

                // Check for high-risk executables
                if (HighRiskExecutables.Contains(process.ProcessName, StringComparer.OrdinalIgnoreCase))
                {
                    threatLevel = ThreatSeverity.Medium;
                    detectedPatterns.Add($"High-risk executable: {process.ProcessName}");
                }

                // Check memory usage
                if (process.WorkingSet64 > 500 * 1024 * 1024) // 500MB
                {
                    detectedPatterns.Add($"High memory usage: {process.WorkingSet64 / (1024 * 1024)}MB");
                }

                // Check for processes with no window but high CPU usage
                if (process.MainWindowHandle == IntPtr.Zero && process.TotalProcessorTime.TotalSeconds > 10)
                {
                    detectedPatterns.Add("Background process with high CPU usage");
                }

                // If threats detected, log them
                if (detectedPatterns.Count > 0)
                {
                    var threatKey = $"{process.ProcessName}_{process.Id}";
                    
                    // Check if we've already reported this threat recently
                    if (!_threatCache.ContainsKey(threatKey) || 
                        DateTime.UtcNow - _threatCache[threatKey] > TimeSpan.FromMinutes(5))
                    {
                        _threatCache[threatKey] = DateTime.UtcNow;

                        _logger.LogWarning($"Suspicious process detected: {process.ProcessName} (PID: {process.Id})");
                        _logger.LogWarning($"Patterns: {string.Join(", ", detectedPatterns)}");

                        // In a real implementation, you'd send this to the cloud for analysis
                        // For now, just log it locally
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error analyzing process {process.ProcessName}");
            }
        }
    }
} 
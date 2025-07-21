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
    public class LightweightMemoryTrap : ILocalSecurityModule
    {
        private readonly ILogger<LightweightMemoryTrap> _logger;
        private readonly IConfiguration _configuration;
        private readonly CancellationTokenSource _cancellationTokenSource;
        
        private bool _isRunning = false;
        private readonly Dictionary<int, DateTime> _lastScanTime = new();

        public LightweightMemoryTrap(IConfiguration configuration, ILogger<LightweightMemoryTrap> logger)
        {
            _configuration = configuration;
            _logger = logger;
            _cancellationTokenSource = new CancellationTokenSource();
        }

        public async Task StartAsync()
        {
            if (_isRunning)
            {
                _logger.LogWarning("Lightweight memory trap is already running");
                return;
            }

            _logger.LogInformation("Starting lightweight memory trap");
            _isRunning = true;

            try
            {
                // Start monitoring loop
                _ = Task.Run(MonitoringLoopAsync, _cancellationTokenSource.Token);

                _logger.LogInformation("Lightweight memory trap started successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to start lightweight memory trap");
                throw;
            }
        }

        public async Task StopAsync()
        {
            if (!_isRunning)
            {
                return;
            }

            _logger.LogInformation("Stopping lightweight memory trap");
            _isRunning = false;

            try
            {
                _cancellationTokenSource.Cancel();
                _logger.LogInformation("Lightweight memory trap stopped successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error stopping lightweight memory trap");
            }
        }

        private async Task MonitoringLoopAsync()
        {
            var scanInterval = _configuration.GetValue<int>("local:scan_interval", 60);

            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                try
                {
                    await ScanMemoryAsync();
                    await Task.Delay(TimeSpan.FromSeconds(scanInterval), _cancellationTokenSource.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in memory monitoring loop");
                    await Task.Delay(TimeSpan.FromSeconds(30), _cancellationTokenSource.Token);
                }
            }
        }

        private async Task ScanMemoryAsync()
        {
            try
            {
                var processes = Process.GetProcesses().Take(20); // Only scan first 20 processes

                foreach (var process in processes)
                {
                    try
                    {
                        // Check if we should scan this process
                        if (ShouldScanProcess(process))
                        {
                            await AnalyzeProcessMemoryAsync(process);
                            _lastScanTime[process.Id] = DateTime.UtcNow;
                        }
                    }
                    catch
                    {
                        // Skip processes we can't access
                    }
                }

                // Clean up old scan times
                var cutoffTime = DateTime.UtcNow.AddMinutes(-10);
                var oldProcessIds = _lastScanTime.Where(kvp => kvp.Value < cutoffTime)
                                               .Select(kvp => kvp.Key)
                                               .ToList();
                foreach (var processId in oldProcessIds)
                {
                    _lastScanTime.Remove(processId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error scanning memory");
            }
        }

        private bool ShouldScanProcess(Process process)
        {
            // Don't scan our own process
            if (process.Id == Process.GetCurrentProcess().Id)
                return false;

            // Don't scan system processes
            if (process.ProcessName.ToLower().Contains("system") ||
                process.ProcessName.ToLower().Contains("svchost") ||
                process.ProcessName.ToLower().Contains("csrss") ||
                process.ProcessName.ToLower().Contains("winlogon"))
                return false;

            // Only scan processes with significant memory usage
            if (process.WorkingSet64 < 50 * 1024 * 1024) // Less than 50MB
                return false;

            // Don't scan the same process too frequently
            if (_lastScanTime.ContainsKey(process.Id))
            {
                var timeSinceLastScan = DateTime.UtcNow - _lastScanTime[process.Id];
                if (timeSinceLastScan < TimeSpan.FromMinutes(5))
                    return false;
            }

            return true;
        }

        private async Task AnalyzeProcessMemoryAsync(Process process)
        {
            try
            {
                var threats = new List<string>();

                // Check for unusually high memory usage
                if (process.WorkingSet64 > 1000 * 1024 * 1024) // 1GB
                {
                    threats.Add($"Extremely high memory usage: {process.WorkingSet64 / (1024 * 1024)}MB");
                }

                // Check for processes with high memory usage but low CPU time
                if (process.WorkingSet64 > 500 * 1024 * 1024 && process.TotalProcessorTime.TotalSeconds < 1)
                {
                    threats.Add("High memory usage with low CPU activity (potential memory leak or malware)");
                }

                // Check for processes with unusual memory patterns
                if (process.WorkingSet64 > 200 * 1024 * 1024 && process.ProcessName.Length < 5)
                {
                    threats.Add("Large memory usage with short process name (suspicious)");
                }

                // If threats detected, log them
                if (threats.Count > 0)
                {
                    _logger.LogWarning($"Memory threats detected in {process.ProcessName} (PID: {process.Id})");
                    _logger.LogWarning($"Threats: {string.Join(", ", threats)}");
                    _logger.LogWarning($"Memory usage: {process.WorkingSet64 / (1024 * 1024)}MB");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error analyzing memory for process {process.ProcessName}");
            }
        }
    }
} 
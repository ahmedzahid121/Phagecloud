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
    public class LightweightCredentialTrap : ILocalSecurityModule
    {
        private readonly ILogger<LightweightCredentialTrap> _logger;
        private readonly IConfiguration _configuration;
        private readonly CancellationTokenSource _cancellationTokenSource;
        
        private bool _isRunning = false;
        private readonly HashSet<int> _monitoredProcesses = new();

        private static readonly string[] CredentialTheftTools = {
            "mimikatz", "procdump", "wce", "pwdump", "fgdump", "quarks-pwdump",
            "wdigest", "sekurlsa", "lsass", "sam", "system", "ntds"
        };

        public LightweightCredentialTrap(IConfiguration configuration, ILogger<LightweightCredentialTrap> logger)
        {
            _configuration = configuration;
            _logger = logger;
            _cancellationTokenSource = new CancellationTokenSource();
        }

        public async Task StartAsync()
        {
            if (_isRunning)
            {
                _logger.LogWarning("Lightweight credential trap is already running");
                return;
            }

            _logger.LogInformation("Starting lightweight credential trap");
            _isRunning = true;

            try
            {
                // Start monitoring loop
                _ = Task.Run(MonitoringLoopAsync, _cancellationTokenSource.Token);

                _logger.LogInformation("Lightweight credential trap started successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to start lightweight credential trap");
                throw;
            }
        }

        public async Task StopAsync()
        {
            if (!_isRunning)
            {
                return;
            }

            _logger.LogInformation("Stopping lightweight credential trap");
            _isRunning = false;

            try
            {
                _cancellationTokenSource.Cancel();
                _logger.LogInformation("Lightweight credential trap stopped successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error stopping lightweight credential trap");
            }
        }

        private async Task MonitoringLoopAsync()
        {
            var scanInterval = _configuration.GetValue<int>("local:scan_interval", 60);

            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                try
                {
                    await ScanForCredentialTheftAsync();
                    await Task.Delay(TimeSpan.FromSeconds(scanInterval), _cancellationTokenSource.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in credential monitoring loop");
                    await Task.Delay(TimeSpan.FromSeconds(30), _cancellationTokenSource.Token);
                }
            }
        }

        private async Task ScanForCredentialTheftAsync()
        {
            try
            {
                var processes = Process.GetProcesses();

                foreach (var process in processes.Take(50)) // Limit to first 50 processes
                {
                    try
                    {
                        // Check for credential theft tools
                        if (IsCredentialTheftTool(process))
                        {
                            _logger.LogError($"CRITICAL: Credential theft tool detected: {process.ProcessName} (PID: {process.Id})");
                            
                            // In a real implementation, you'd take immediate action
                            // For now, just log the threat
                        }

                        // Check for processes accessing LSASS
                        if (IsAccessingLSASS(process))
                        {
                            _logger.LogWarning($"Suspicious LSASS access detected: {process.ProcessName} (PID: {process.Id})");
                        }

                        // Check for processes with credential-related names
                        if (HasCredentialRelatedName(process))
                        {
                            _logger.LogWarning($"Process with credential-related name: {process.ProcessName} (PID: {process.Id})");
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
                _logger.LogError(ex, "Error scanning for credential theft");
            }
        }

        private bool IsCredentialTheftTool(Process process)
        {
            try
            {
                var processName = process.ProcessName.ToLower();
                
                // Check for known credential theft tools
                if (CredentialTheftTools.Any(tool => processName.Contains(tool)))
                {
                    return true;
                }

                // Check for suspicious process names
                if (processName.Contains("dump") || processName.Contains("extract") || processName.Contains("steal"))
                {
                    return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private bool IsAccessingLSASS(Process process)
        {
            try
            {
                // This is a simplified check
                // In a real implementation, you'd use more sophisticated methods
                var processName = process.ProcessName.ToLower();
                
                // Check for processes that commonly access LSASS
                if (processName.Contains("procdump") || processName.Contains("mimikatz") || processName.Contains("wce"))
                {
                    return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private bool HasCredentialRelatedName(Process process)
        {
            try
            {
                var processName = process.ProcessName.ToLower();
                
                // Check for credential-related keywords
                var credentialKeywords = new[] { "pass", "cred", "auth", "login", "user", "admin" };
                
                return credentialKeywords.Any(keyword => processName.Contains(keyword));
            }
            catch
            {
                return false;
            }
        }
    }
} 
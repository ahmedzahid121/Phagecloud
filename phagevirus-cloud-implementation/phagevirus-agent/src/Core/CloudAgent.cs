using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using PhageVirus.Agent.Cloud;
using PhageVirus.Agent.Local;
using PhageVirus.Agent.Shared;

namespace PhageVirus.Agent.Core
{
    public class CloudAgent
    {
        private readonly ILogger<CloudAgent> _logger;
        private readonly IConfiguration _configuration;
        private readonly AzureCommunicator _azureCommunicator;
        private readonly AWSCommunicator _awsCommunicator;
        private readonly LocalSecurityEngine _localEngine;
        private readonly TelemetryCollector _telemetryCollector;
        private readonly CancellationTokenSource _cancellationTokenSource;
        
        private AgentMode _currentMode;
        private bool _isRunning = false;

        public CloudAgent(ILogger<CloudAgent> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
            _cancellationTokenSource = new CancellationTokenSource();
            
            // Initialize cloud communicators
            _azureCommunicator = new AzureCommunicator(configuration, logger);
            _awsCommunicator = new AWSCommunicator(configuration, logger);
            
            // Initialize local security engine
            _localEngine = new LocalSecurityEngine(configuration, logger);
            
            // Initialize telemetry collector
            _telemetryCollector = new TelemetryCollector(configuration, logger);
            
            // Determine agent mode
            _currentMode = DetermineAgentMode();
        }

        public async Task StartAsync()
        {
            if (_isRunning)
            {
                _logger.LogWarning("Agent is already running");
                return;
            }

            _logger.LogInformation($"Starting PhageVirus Cloud Agent in {_currentMode} mode");
            _isRunning = true;

            try
            {
                // Initialize cloud connections
                await InitializeCloudConnectionsAsync();

                // Start local security engine if needed
                if (_currentMode == AgentMode.Hybrid || _currentMode == AgentMode.Local)
                {
                    await _localEngine.StartAsync();
                }

                // Start telemetry collection
                await StartTelemetryCollectionAsync();

                // Start heartbeat
                await StartHeartbeatAsync();

                _logger.LogInformation("PhageVirus Cloud Agent started successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to start Cloud Agent");
                throw;
            }
        }

        public async Task StopAsync()
        {
            if (!_isRunning)
            {
                return;
            }

            _logger.LogInformation("Stopping PhageVirus Cloud Agent");
            _isRunning = false;

            try
            {
                _cancellationTokenSource.Cancel();

                // Stop local engine
                if (_localEngine != null)
                {
                    await _localEngine.StopAsync();
                }

                // Stop telemetry collection
                await _telemetryCollector.StopAsync();

                _logger.LogInformation("PhageVirus Cloud Agent stopped successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error stopping Cloud Agent");
            }
        }

        private AgentMode DetermineAgentMode()
        {
            var mode = _configuration["mode"]?.ToLower();
            return mode switch
            {
                "cloud" => AgentMode.Cloud,
                "hybrid" => AgentMode.Hybrid,
                "local" => AgentMode.Local,
                _ => AgentMode.Cloud // Default to cloud mode
            };
        }

        private async Task InitializeCloudConnectionsAsync()
        {
            _logger.LogInformation("Initializing cloud connections");

            try
            {
                // Initialize Azure connection
                if (_currentMode == AgentMode.Cloud || _currentMode == AgentMode.Hybrid)
                {
                    await _azureCommunicator.InitializeAsync();
                    _logger.LogInformation("Azure connection initialized");
                }

                // Initialize AWS connection
                if (_currentMode == AgentMode.Cloud || _currentMode == AgentMode.Hybrid)
                {
                    await _awsCommunicator.InitializeAsync();
                    _logger.LogInformation("AWS connection initialized");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize cloud connections");
                throw;
            }
        }

        private async Task StartTelemetryCollectionAsync()
        {
            if (_currentMode == AgentMode.Cloud || _currentMode == AgentMode.Hybrid)
            {
                await _telemetryCollector.StartAsync(_cancellationTokenSource.Token);
                _logger.LogInformation("Telemetry collection started");
            }
        }

        private async Task StartHeartbeatAsync()
        {
            if (_currentMode == AgentMode.Cloud || _currentMode == AgentMode.Hybrid)
            {
                var heartbeatInterval = _configuration.GetValue<int>("telemetry:heartbeat_interval", 60);
                
                _ = Task.Run(async () =>
                {
                    while (!_cancellationTokenSource.Token.IsCancellationRequested)
                    {
                        try
                        {
                            await SendHeartbeatAsync();
                            await Task.Delay(TimeSpan.FromSeconds(heartbeatInterval), _cancellationTokenSource.Token);
                        }
                        catch (OperationCanceledException)
                        {
                            break;
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "Error sending heartbeat");
                            await Task.Delay(TimeSpan.FromSeconds(30), _cancellationTokenSource.Token);
                        }
                    }
                }, _cancellationTokenSource.Token);

                _logger.LogInformation("Heartbeat started");
            }
        }

        private async Task SendHeartbeatAsync()
        {
            var heartbeat = new HeartbeatData
            {
                AgentId = GetAgentId(),
                Timestamp = DateTime.UtcNow,
                Mode = _currentMode.ToString(),
                Status = "healthy",
                Version = GetAgentVersion(),
                SystemInfo = await GetSystemInfoAsync()
            };

            // Send to both Azure and AWS
            var tasks = new List<Task>();

            if (_azureCommunicator.IsInitialized)
            {
                tasks.Add(_azureCommunicator.SendHeartbeatAsync(heartbeat));
            }

            if (_awsCommunicator.IsInitialized)
            {
                tasks.Add(_awsCommunicator.SendHeartbeatAsync(heartbeat));
            }

            await Task.WhenAll(tasks);
        }

        private string GetAgentId()
        {
            // Generate or retrieve unique agent ID
            return Environment.MachineName + "_" + Environment.UserName;
        }

        private string GetAgentVersion()
        {
            return "2.0.0";
        }

        private async Task<SystemInfo> GetSystemInfoAsync()
        {
            return new SystemInfo
            {
                MachineName = Environment.MachineName,
                UserName = Environment.UserName,
                OSVersion = Environment.OSVersion.ToString(),
                ProcessorCount = Environment.ProcessorCount,
                WorkingSet = Environment.WorkingSet,
                Is64BitProcess = Environment.Is64BitProcess,
                Is64BitOperatingSystem = Environment.Is64BitOperatingSystem
            };
        }

        public async Task<ThreatAnalysisResult> AnalyzeThreatAsync(ThreatData threatData)
        {
            if (_currentMode == AgentMode.Cloud)
            {
                // Send to cloud for analysis
                return await _azureCommunicator.AnalyzeThreatAsync(threatData);
            }
            else if (_currentMode == AgentMode.Hybrid)
            {
                // Quick local analysis first
                var localResult = await _localEngine.AnalyzeThreatAsync(threatData);
                
                // If high risk, send to cloud for deep analysis
                if (localResult.RiskScore > 0.7)
                {
                    var cloudResult = await _azureCommunicator.AnalyzeThreatAsync(threatData);
                    return MergeAnalysisResults(localResult, cloudResult);
                }
                
                return localResult;
            }
            else
            {
                // Local analysis only
                return await _localEngine.AnalyzeThreatAsync(threatData);
            }
        }

        private ThreatAnalysisResult MergeAnalysisResults(ThreatAnalysisResult local, ThreatAnalysisResult cloud)
        {
            return new ThreatAnalysisResult
            {
                RiskScore = Math.Max(local.RiskScore, cloud.RiskScore),
                Confidence = Math.Max(local.Confidence, cloud.Confidence),
                DetectedPatterns = new List<string>(local.DetectedPatterns)
                {
                    // Add cloud patterns
                },
                Recommendations = new List<string>(local.Recommendations)
                {
                    // Add cloud recommendations
                },
                AnalysisSource = "hybrid"
            };
        }
    }

    public enum AgentMode
    {
        Cloud,
        Hybrid,
        Local
    }
} 
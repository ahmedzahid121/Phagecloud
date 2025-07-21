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
    /// <summary>
    /// Main cloud agent orchestrator for PhageVirus
    /// Uses AWS as primary cloud service with Azure Key Vault for secrets
    /// </summary>
    public class CloudAgent
    {
        private readonly ILogger<CloudAgent> _logger;
        private readonly IConfiguration _configuration;
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
            
            // Initialize AWS communicator (primary cloud service)
            _awsCommunicator = new AWSCommunicator(configuration, logger);
            
            // Initialize local security engine
            _localEngine = new LocalSecurityEngine(configuration, logger);
            
            // Initialize telemetry collector (AWS-focused)
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

            _logger.LogInformation($"Starting PhageVirus Cloud Agent in {_currentMode} mode (AWS Primary)");
            _isRunning = true;

            try
            {
                // Initialize AWS connections
                await InitializeAWSConnectionsAsync();

                // Start local security engine if needed
                if (_currentMode == AgentMode.Hybrid || _currentMode == AgentMode.Local)
                {
                    await _localEngine.StartAsync();
                }

                // Start telemetry collection
                await StartTelemetryCollectionAsync();

                // Start heartbeat
                await StartHeartbeatAsync();

                _logger.LogInformation("PhageVirus Cloud Agent started successfully with AWS integration");
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

        private async Task InitializeAWSConnectionsAsync()
        {
            _logger.LogInformation("Initializing AWS connections for ap-southeast-2 region");

            try
            {
                // Initialize AWS communicator
                await _awsCommunicator.InitializeAsync();
                _logger.LogInformation("AWS connections initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize AWS connections");
                throw;
            }
        }

        private async Task StartTelemetryCollectionAsync()
        {
            if (_currentMode == AgentMode.Cloud || _currentMode == AgentMode.Hybrid)
            {
                await _telemetryCollector.StartAsync(_cancellationTokenSource.Token);
                _logger.LogInformation("AWS telemetry collection started");
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
                            _logger.LogError(ex, "Error sending heartbeat to AWS");
                            await Task.Delay(TimeSpan.FromSeconds(30), _cancellationTokenSource.Token);
                        }
                    }
                }, _cancellationTokenSource.Token);

                _logger.LogInformation("AWS heartbeat started");
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

            await _awsCommunicator.SendHeartbeatAsync(heartbeat);
        }

        private string GetAgentId()
        {
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
                OsVersion = Environment.OSVersion.ToString(),
                MachineName = Environment.MachineName,
                UserName = Environment.UserName,
                ProcessorCount = Environment.ProcessorCount,
                WorkingSet = Environment.WorkingSet,
                Is64BitProcess = Environment.Is64BitProcess,
                Is64BitOperatingSystem = Environment.Is64BitOperatingSystem
            };
        }

        public async Task<ThreatAnalysisResult> AnalyzeThreatAsync(ThreatData threatData)
        {
            try
            {
                // For cloud mode, send to AWS Lambda for analysis
                if (_currentMode == AgentMode.Cloud)
                {
                    // Store threat data in S3
                    var threatJson = System.Text.Json.JsonSerializer.Serialize(threatData);
                    await _awsCommunicator.StoreScanReportAsync(GetAgentId(), threatJson, "threat_analysis");
                    
                    // Return basic analysis (Lambda would provide detailed analysis)
                    return new ThreatAnalysisResult
                    {
                        AnalysisId = Guid.NewGuid().ToString(),
                        Timestamp = DateTime.UtcNow,
                        RiskScore = 0.5,
                        Confidence = 0.8,
                        DetectedPatterns = new List<string> { "Cloud analysis pending" },
                        Recommendations = new List<string> { "Threat data sent to AWS for analysis" },
                        AnalysisSource = "aws",
                        CalculatedSeverity = ThreatSeverity.Medium,
                        RequiresImmediateAction = false,
                        AnalysisMetadata = new Dictionary<string, object>()
                    };
                }

                // For hybrid/local modes, combine local and cloud analysis
                var localResult = await _localEngine.AnalyzeThreatAsync(threatData);
                
                // Store in AWS for correlation
                var threatJson = System.Text.Json.JsonSerializer.Serialize(threatData);
                await _awsCommunicator.StoreScanReportAsync(GetAgentId(), threatJson, "threat_analysis");
                
                return localResult;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing threat");
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

        public async Task SendAlertAsync(AlertData alert)
        {
            try
            {
                // Store alert in AWS
                var alertJson = System.Text.Json.JsonSerializer.Serialize(alert);
                await _awsCommunicator.StoreScanReportAsync(GetAgentId(), alertJson, "alert");
                
                _logger.LogInformation($"Alert sent to AWS: {alert.AlertType}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending alert to AWS");
            }
        }

        public async Task<ConfigurationData?> GetConfigurationAsync(string agentId)
        {
            try
            {
                // Get configuration from AWS DynamoDB
                var configData = await _awsCommunicator.GetEndpointDataAsync(agentId);
                if (configData != null && configData.ContainsKey("Configuration"))
                {
                    var configJson = configData["Configuration"].ToString();
                    return System.Text.Json.JsonSerializer.Deserialize<ConfigurationData>(configJson);
                }
                
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting configuration from AWS");
                return null;
            }
        }

        public async Task<bool> UpdateConfigurationAsync(ConfigurationData configuration)
        {
            try
            {
                // Store configuration in AWS DynamoDB
                await _awsCommunicator.StoreEndpointDataAsync(GetAgentId(), new Dictionary<string, object>
                {
                    ["Configuration"] = System.Text.Json.JsonSerializer.Serialize(configuration),
                    ["LastUpdated"] = DateTime.UtcNow
                });
                
                _logger.LogInformation("Configuration updated in AWS");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating configuration in AWS");
                return false;
            }
        }

        public async Task<HealthCheckData> GetHealthCheckAsync()
        {
            try
            {
                var healthCheck = new HealthCheckData
                {
                    AgentId = GetAgentId(),
                    Timestamp = DateTime.UtcNow,
                    Status = _isRunning ? "healthy" : "stopped",
                    Metrics = new Dictionary<string, object>
                    {
                        ["Mode"] = _currentMode.ToString(),
                        ["Uptime"] = Environment.TickCount / 1000.0,
                        ["MemoryUsage"] = Environment.WorkingSet,
                        ["ProcessCount"] = System.Diagnostics.Process.GetProcesses().Length
                    },
                    Issues = new List<string>(),
                    IsHealthy = _isRunning
                };

                // Store health check in AWS
                await _awsCommunicator.StoreEndpointDataAsync(GetAgentId(), new Dictionary<string, object>
                {
                    ["HealthCheck"] = System.Text.Json.JsonSerializer.Serialize(healthCheck),
                    ["Timestamp"] = DateTime.UtcNow
                });

                return healthCheck;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting health check");
                return CreateDefaultHealthCheck();
            }
        }

        private HealthCheckData CreateDefaultHealthCheck()
        {
            return new HealthCheckData
            {
                AgentId = GetAgentId(),
                Timestamp = DateTime.UtcNow,
                Status = "unknown",
                Metrics = new Dictionary<string, object>(),
                Issues = new List<string>(),
                IsHealthy = false
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
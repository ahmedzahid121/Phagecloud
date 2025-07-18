using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using PhageVirus.Agent.Shared;

namespace PhageVirus.Agent.Cloud
{
    public class AzureCommunicator
    {
        private readonly ILogger<AzureCommunicator> _logger;
        private readonly IConfiguration _configuration;
        private readonly HttpClient _httpClient;
        private readonly JsonSerializerOptions _jsonOptions;
        
        private string _azureEndpoint = string.Empty;
        private string _threatAnalysisEndpoint = string.Empty;
        private string _logForwarderEndpoint = string.Empty;
        private string _mlScoringEndpoint = string.Empty;
        
        public bool IsInitialized { get; private set; } = false;

        public AzureCommunicator(IConfiguration configuration, ILogger<AzureCommunicator> logger)
        {
            _configuration = configuration;
            _logger = logger;
            _httpClient = new HttpClient();
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = false
            };
        }

        public async Task InitializeAsync()
        {
            try
            {
                _logger.LogInformation("Initializing Azure communicator");

                // Load configuration
                _azureEndpoint = _configuration["cloud:azure:endpoint"] ?? string.Empty;
                _threatAnalysisEndpoint = _configuration["cloud:azure:functions:threat_analysis"] ?? string.Empty;
                _logForwarderEndpoint = _configuration["cloud:azure:functions:log_forwarder"] ?? string.Empty;
                _mlScoringEndpoint = _configuration["cloud:azure:functions:ml_scoring"] ?? string.Empty;

                if (string.IsNullOrEmpty(_azureEndpoint))
                {
                    throw new InvalidOperationException("Azure endpoint not configured");
                }

                // Configure HTTP client
                _httpClient.BaseAddress = new Uri(_azureEndpoint);
                _httpClient.Timeout = TimeSpan.FromSeconds(
                    _configuration.GetValue<int>("cloud:azure:telemetry:timeout", 30));

                // Test connection
                await TestConnectionAsync();

                IsInitialized = true;
                _logger.LogInformation("Azure communicator initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize Azure communicator");
                throw;
            }
        }

        public async Task<bool> TestConnectionAsync()
        {
            try
            {
                var response = await _httpClient.GetAsync("/api/health");
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Azure connection test failed");
                return false;
            }
        }

        public async Task SendHeartbeatAsync(HeartbeatData heartbeat)
        {
            if (!IsInitialized)
            {
                _logger.LogWarning("Azure communicator not initialized");
                return;
            }

            try
            {
                var json = JsonSerializer.Serialize(heartbeat, _jsonOptions);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync("/api/heartbeat", content);
                
                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning($"Failed to send heartbeat: {response.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending heartbeat to Azure");
            }
        }

        public async Task<ThreatAnalysisResult> AnalyzeThreatAsync(ThreatData threatData)
        {
            if (!IsInitialized)
            {
                _logger.LogWarning("Azure communicator not initialized");
                return CreateDefaultAnalysisResult();
            }

            try
            {
                var json = JsonSerializer.Serialize(threatData, _jsonOptions);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync(_threatAnalysisEndpoint, content);
                
                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    var result = JsonSerializer.Deserialize<ThreatAnalysisResult>(responseContent, _jsonOptions);
                    return result ?? CreateDefaultAnalysisResult();
                }
                else
                {
                    _logger.LogWarning($"Threat analysis failed: {response.StatusCode}");
                    return CreateDefaultAnalysisResult();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing threat with Azure");
                return CreateDefaultAnalysisResult();
            }
        }

        public async Task SendTelemetryAsync(TelemetryData telemetry)
        {
            if (!IsInitialized)
            {
                _logger.LogWarning("Azure communicator not initialized");
                return;
            }

            try
            {
                var json = JsonSerializer.Serialize(telemetry, _jsonOptions);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync("/api/telemetry", content);
                
                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning($"Failed to send telemetry: {response.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending telemetry to Azure");
            }
        }

        public async Task SendAlertAsync(AlertData alert)
        {
            if (!IsInitialized)
            {
                _logger.LogWarning("Azure communicator not initialized");
                return;
            }

            try
            {
                var json = JsonSerializer.Serialize(alert, _jsonOptions);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync("/api/alerts", content);
                
                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning($"Failed to send alert: {response.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending alert to Azure");
            }
        }

        public async Task<ConfigurationData?> GetConfigurationAsync(string agentId)
        {
            if (!IsInitialized)
            {
                _logger.LogWarning("Azure communicator not initialized");
                return null;
            }

            try
            {
                var response = await _httpClient.GetAsync($"/api/configuration/{agentId}");
                
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    return JsonSerializer.Deserialize<ConfigurationData>(content, _jsonOptions);
                }
                else
                {
                    _logger.LogWarning($"Failed to get configuration: {response.StatusCode}");
                    return null;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting configuration from Azure");
                return null;
            }
        }

        public async Task<bool> UpdateConfigurationAsync(ConfigurationData configuration)
        {
            if (!IsInitialized)
            {
                _logger.LogWarning("Azure communicator not initialized");
                return false;
            }

            try
            {
                var json = JsonSerializer.Serialize(configuration, _jsonOptions);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PutAsync("/api/configuration", content);
                
                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("Configuration updated successfully");
                    return true;
                }
                else
                {
                    _logger.LogWarning($"Failed to update configuration: {response.StatusCode}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating configuration with Azure");
                return false;
            }
        }

        public async Task<HealthCheckData> GetHealthCheckAsync()
        {
            if (!IsInitialized)
            {
                _logger.LogWarning("Azure communicator not initialized");
                return CreateDefaultHealthCheck();
            }

            try
            {
                var response = await _httpClient.GetAsync("/api/health");
                
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var healthCheck = JsonSerializer.Deserialize<HealthCheckData>(content, _jsonOptions);
                    return healthCheck ?? CreateDefaultHealthCheck();
                }
                else
                {
                    _logger.LogWarning($"Health check failed: {response.StatusCode}");
                    return CreateDefaultHealthCheck();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting health check from Azure");
                return CreateDefaultHealthCheck();
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

        private HealthCheckData CreateDefaultHealthCheck()
        {
            return new HealthCheckData
            {
                AgentId = Environment.MachineName + "_" + Environment.UserName,
                Timestamp = DateTime.UtcNow,
                Status = "unknown",
                Metrics = new Dictionary<string, object>(),
                Issues = new List<string>(),
                IsHealthy = false
            };
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
} 
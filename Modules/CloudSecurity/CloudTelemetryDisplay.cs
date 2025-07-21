using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Management;
using System.Linq;

namespace PhageVirus.Modules
{
    /// <summary>
    /// Cloud Telemetry Display Module
    /// Fetches and displays cloud telemetry data in the PhageVirus desktop application
    /// Shows CPU, RAM usage, threats detected, and other metrics from AWS Lambda
    /// </summary>
    public class CloudTelemetryDisplay
    {
        private static readonly HttpClient httpClient = new HttpClient();
        private static readonly object displayLock = new object();
        private static bool isInitialized = false;
        private static Timer? displayTimer;
        
        // Cloud configuration
        private static CloudDisplayConfig config = new();
        
        // Display data
        private static CloudMetrics currentMetrics = new();
        private static List<CloudThreatData> recentThreats = new();
        private static List<CloudPerformanceData> performanceHistory = new();
        
        // UI callback for real-time updates
        private static Action<string>? uiLogCallback;
        private static Action<CloudMetrics>? uiMetricsCallback;
        private static Action<List<CloudThreatData>>? uiThreatsCallback;

        public class CloudDisplayConfig
        {
            public string LambdaFunctionUrl { get; set; } = "";
            public string ApiGatewayUrl { get; set; } = "";
            public string EndpointId { get; set; } = "";
            public int RefreshIntervalSeconds { get; set; } = 30;
            public bool EnableRealTimeUpdates { get; set; } = true;
            public bool ShowDetailedMetrics { get; set; } = true;
            public int MaxHistoryItems { get; set; } = 100;
        }

        public class CloudMetrics
        {
            public DateTime Timestamp { get; set; } = DateTime.UtcNow;
            public double CloudCpuUsage { get; set; }
            public double CloudMemoryUsage { get; set; }
            public double LocalCpuUsage { get; set; }
            public double LocalMemoryUsage { get; set; }
            public int ThreatsDetected { get; set; }
            public int ThreatsBlocked { get; set; }
            public double RiskScore { get; set; }
            public string Severity { get; set; } = "Normal";
            public int TelemetryRecordsProcessed { get; set; }
            public int LambdaInvocations { get; set; }
            public double LambdaDuration { get; set; }
            public string LambdaStatus { get; set; } = "Unknown";
            public Dictionary<string, object> AdditionalMetrics { get; set; } = new();
        }

        public class CloudThreatData
        {
            public DateTime Timestamp { get; set; } = DateTime.UtcNow;
            public string ThreatType { get; set; } = "";
            public string Target { get; set; } = "";
            public string Action { get; set; } = "";
            public string Status { get; set; } = "";
            public double RiskScore { get; set; }
            public string Severity { get; set; } = "Info";
            public string Analysis { get; set; } = "";
            public string[] Recommendations { get; set; } = new string[0];
        }

        public class CloudPerformanceData
        {
            public DateTime Timestamp { get; set; } = DateTime.UtcNow;
            public double CpuUsage { get; set; }
            public double MemoryUsage { get; set; }
            public int ProcessCount { get; set; }
            public int SuspiciousProcesses { get; set; }
            public int NetworkConnections { get; set; }
            public int SuspiciousConnections { get; set; }
        }

        public static void Initialize(CloudDisplayConfig? displayConfig = null, 
            Action<string>? logCallback = null,
            Action<CloudMetrics>? metricsCallback = null,
            Action<List<CloudThreatData>>? threatsCallback = null)
        {
            lock (displayLock)
            {
                if (isInitialized) return;

                try
                {
                    EnhancedLogger.LogInfo("Initializing cloud telemetry display...", logCallback);
                    
                    // Load configuration
                    if (displayConfig != null)
                        config = displayConfig;
                    else
                        LoadDisplayConfig();

                    // Set UI callbacks
                    uiLogCallback = logCallback;
                    uiMetricsCallback = metricsCallback;
                    uiThreatsCallback = threatsCallback;

                    // Generate endpoint ID if not set
                    if (string.IsNullOrEmpty(config.EndpointId))
                    {
                        config.EndpointId = GenerateEndpointId();
                    }

                    // Start display timer
                    if (config.EnableRealTimeUpdates)
                    {
                        displayTimer = new Timer(UpdateDisplay, null, 
                            TimeSpan.Zero, 
                            TimeSpan.FromSeconds(config.RefreshIntervalSeconds));
                    }

                    isInitialized = true;
                    EnhancedLogger.LogSuccess("Cloud telemetry display initialized successfully", logCallback);
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to initialize cloud telemetry display: {ex.Message}", logCallback);
                }
            }
        }

        private static void LoadDisplayConfig()
        {
            try
            {
                var configPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "PhageVirus", "config", "cloud-display-config.json");

                if (File.Exists(configPath))
                {
                    var json = File.ReadAllText(configPath);
                    config = JsonSerializer.Deserialize<CloudDisplayConfig>(json) ?? new CloudDisplayConfig();
                }
                else
                {
                    // Create default config
                    Directory.CreateDirectory(Path.GetDirectoryName(configPath)!);
                    config.LambdaFunctionUrl = "https://phagevirus-telemetry-processor.lambda-url.ap-southeast-2.on.aws/";
                    config.ApiGatewayUrl = "https://9tjtwblsg3.execute-api.ap-southeast-2.amazonaws.com/";
                    config.EndpointId = GenerateEndpointId();
                    
                    var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(configPath, json);
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to load cloud display config, using defaults: {ex.Message}", uiLogCallback);
            }
        }

        private static string GenerateEndpointId()
        {
            try
            {
                var computerName = Environment.MachineName;
                var userName = Environment.UserName;
                var processId = Process.GetCurrentProcess().Id;
                return $"endpoint-{computerName}-{userName}-{processId}";
            }
            catch
            {
                return $"endpoint-{Guid.NewGuid():N}";
            }
        }

        private static async void UpdateDisplay(object? state)
        {
            try
            {
                // Fetch cloud metrics
                var cloudMetrics = await FetchCloudMetricsAsync();
                if (cloudMetrics != null)
                {
                    currentMetrics = cloudMetrics;
                    uiMetricsCallback?.Invoke(currentMetrics);
                }

                // Fetch recent threats
                var threats = await FetchRecentThreatsAsync();
                if (threats != null && threats.Count > 0)
                {
                    recentThreats = threats;
                    uiThreatsCallback?.Invoke(recentThreats);
                }

                // Update performance history
                var performanceData = GetLocalPerformanceData();
                performanceHistory.Add(performanceData);
                
                // Limit history size
                if (performanceHistory.Count > config.MaxHistoryItems)
                {
                    performanceHistory.RemoveAt(0);
                }

                // Log summary to UI
                LogMetricsSummary();
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to update cloud display: {ex.Message}", uiLogCallback);
            }
        }

        private static async Task<CloudMetrics?> FetchCloudMetricsAsync()
        {
            try
            {
                if (string.IsNullOrEmpty(config.LambdaFunctionUrl))
                    return null;

                var requestData = new
                {
                    agentId = config.EndpointId,
                    timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                    dataType = "Metrics",
                    data = new
                    {
                        requestType = "get_metrics",
                        includePerformance = true,
                        includeThreats = true
                    }
                };

                var json = JsonSerializer.Serialize(requestData);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await httpClient.PostAsync(config.LambdaFunctionUrl, content);
                if (response.IsSuccessStatusCode)
                {
                    var responseJson = await response.Content.ReadAsStringAsync();
                    var responseData = JsonSerializer.Deserialize<JsonElement>(responseJson);

                    return new CloudMetrics
                    {
                        Timestamp = DateTime.UtcNow,
                        CloudCpuUsage = GetDoubleValue(responseData, "cloudCpuUsage"),
                        CloudMemoryUsage = GetDoubleValue(responseData, "cloudMemoryUsage"),
                        LocalCpuUsage = GetLocalCpuUsage(),
                        LocalMemoryUsage = GetLocalMemoryUsage(),
                        ThreatsDetected = GetIntValue(responseData, "threatsDetected"),
                        ThreatsBlocked = GetIntValue(responseData, "threatsBlocked"),
                        RiskScore = GetDoubleValue(responseData, "riskScore"),
                        Severity = GetStringValue(responseData, "severity"),
                        TelemetryRecordsProcessed = GetIntValue(responseData, "telemetryProcessed"),
                        LambdaInvocations = GetIntValue(responseData, "lambdaInvocations"),
                        LambdaDuration = GetDoubleValue(responseData, "lambdaDuration"),
                        LambdaStatus = GetStringValue(responseData, "lambdaStatus")
                    };
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to fetch cloud metrics: {ex.Message}", uiLogCallback);
            }

            return null;
        }

        private static async Task<List<CloudThreatData>?> FetchRecentThreatsAsync()
        {
            try
            {
                if (string.IsNullOrEmpty(config.ApiGatewayUrl))
                    return null;

                var url = $"{config.ApiGatewayUrl}telemetry?agentId={config.EndpointId}&limit=10";
                var response = await httpClient.GetAsync(url);
                
                if (response.IsSuccessStatusCode)
                {
                    var responseJson = await response.Content.ReadAsStringAsync();
                    var threatsArray = JsonSerializer.Deserialize<JsonElement[]>(responseJson);
                    
                    var threats = new List<CloudThreatData>();
                    foreach (var threatElement in threatsArray)
                    {
                        if (threatElement.TryGetProperty("data", out var dataElement))
                        {
                            var threat = new CloudThreatData
                            {
                                Timestamp = DateTime.Parse(GetStringValue(threatElement, "timestamp")),
                                ThreatType = GetStringValue(dataElement, "threatType"),
                                Target = GetStringValue(dataElement, "target"),
                                Action = GetStringValue(dataElement, "action"),
                                Status = GetStringValue(dataElement, "status"),
                                RiskScore = GetDoubleValue(threatElement, "riskScore"),
                                Severity = GetStringValue(threatElement, "severity"),
                                Analysis = GetStringValue(dataElement, "analysis"),
                                Recommendations = GetStringArrayValue(dataElement, "recommendations")
                            };
                            threats.Add(threat);
                        }
                    }
                    
                    return threats;
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to fetch recent threats: {ex.Message}", uiLogCallback);
            }

            return null;
        }

        private static CloudPerformanceData GetLocalPerformanceData()
        {
            return new CloudPerformanceData
            {
                Timestamp = DateTime.UtcNow,
                CpuUsage = GetLocalCpuUsage(),
                MemoryUsage = GetLocalMemoryUsage(),
                ProcessCount = Process.GetProcesses().Length,
                SuspiciousProcesses = GetSuspiciousProcessCount(),
                NetworkConnections = GetNetworkConnectionCount(),
                SuspiciousConnections = GetSuspiciousConnectionCount()
            };
        }

        private static double GetLocalCpuUsage()
        {
            try
            {
                using var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                return Math.Round(cpuCounter.NextValue(), 2);
            }
            catch
            {
                return 0.0;
            }
        }

        private static double GetLocalMemoryUsage()
        {
            try
            {
                var process = Process.GetCurrentProcess();
                var totalMemory = GC.GetTotalMemory(false);
                var maxMemory = process.MaxWorkingSet.ToInt64();
                return Math.Round((double)totalMemory / maxMemory * 100, 2);
            }
            catch
            {
                return 0.0;
            }
        }

        private static int GetSuspiciousProcessCount()
        {
            try
            {
                var suspiciousProcesses = Process.GetProcesses()
                    .Where(p => IsSuspiciousProcess(p.ProcessName))
                    .Count();
                return suspiciousProcesses;
            }
            catch
            {
                return 0;
            }
        }

        private static bool IsSuspiciousProcess(string processName)
        {
            var suspiciousNames = new[]
            {
                "powershell", "cmd", "mshta", "wscript", "cscript", "regsvr32",
                "rundll32", "certutil", "bitsadmin", "wmic", "schtasks"
            };
            
            return suspiciousNames.Any(name => 
                processName.ToLower().Contains(name.ToLower()));
        }

        private static int GetNetworkConnectionCount()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_NetworkConnection");
                return searcher.Get().Count;
            }
            catch
            {
                return 0;
            }
        }

        private static int GetSuspiciousConnectionCount()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_NetworkConnection WHERE RemoteName IS NOT NULL");
                var connections = searcher.Get();
                
                int suspiciousCount = 0;
                foreach (ManagementObject connection in connections)
                {
                    var remoteName = connection["RemoteName"]?.ToString() ?? "";
                    if (IsSuspiciousConnection(remoteName))
                        suspiciousCount++;
                }
                
                return suspiciousCount;
            }
            catch
            {
                return 0;
            }
        }

        private static bool IsSuspiciousConnection(string remoteName)
        {
            var suspiciousPatterns = new[]
            {
                "*.tor2web.org", "*.onion", "*.bit", "*.i2p",
                "*.malware.com", "*.botnet.com", "*.c2.com"
            };
            
            return suspiciousPatterns.Any(pattern => 
                remoteName.Contains(pattern.Replace("*", "")));
        }

        private static void LogMetricsSummary()
        {
            if (uiLogCallback == null) return;

            var summary = $"[CLOUD METRICS] " +
                         $"Local CPU: {currentMetrics.LocalCpuUsage:F1}% | " +
                         $"Local RAM: {currentMetrics.LocalMemoryUsage:F1}% | " +
                         $"Cloud CPU: {currentMetrics.CloudCpuUsage:F1}% | " +
                         $"Cloud RAM: {currentMetrics.CloudMemoryUsage:F1}% | " +
                         $"Threats: {currentMetrics.ThreatsDetected} | " +
                         $"Risk Score: {currentMetrics.RiskScore:F1}% | " +
                         $"Lambda Status: {currentMetrics.LambdaStatus}";

            uiLogCallback(summary + "\n");
        }

        // Helper methods for JSON parsing
        private static double GetDoubleValue(JsonElement element, string propertyName)
        {
            if (element.TryGetProperty(propertyName, out var property))
            {
                if (property.ValueKind == JsonValueKind.Number)
                    return property.GetDouble();
                if (property.ValueKind == JsonValueKind.String && double.TryParse(property.GetString(), out var result))
                    return result;
            }
            return 0.0;
        }

        private static int GetIntValue(JsonElement element, string propertyName)
        {
            if (element.TryGetProperty(propertyName, out var property))
            {
                if (property.ValueKind == JsonValueKind.Number)
                    return property.GetInt32();
                if (property.ValueKind == JsonValueKind.String && int.TryParse(property.GetString(), out var result))
                    return result;
            }
            return 0;
        }

        private static string GetStringValue(JsonElement element, string propertyName)
        {
            if (element.TryGetProperty(propertyName, out var property))
            {
                return property.GetString() ?? "";
            }
            return "";
        }

        private static string[] GetStringArrayValue(JsonElement element, string propertyName)
        {
            if (element.TryGetProperty(propertyName, out var property) && 
                property.ValueKind == JsonValueKind.Array)
            {
                return property.EnumerateArray()
                    .Select(p => p.GetString() ?? "")
                    .Where(s => !string.IsNullOrEmpty(s))
                    .ToArray();
            }
            return new string[0];
        }

        // Public methods for external access
        public static CloudMetrics GetCurrentMetrics() => currentMetrics;
        public static List<CloudThreatData> GetRecentThreats() => recentThreats;
        public static List<CloudPerformanceData> GetPerformanceHistory() => performanceHistory;
        public static bool IsInitialized => isInitialized;
        public static CloudDisplayConfig Config => config;

        public static void Dispose()
        {
            displayTimer?.Dispose();
            httpClient?.Dispose();
            isInitialized = false;
        }
    }
} 
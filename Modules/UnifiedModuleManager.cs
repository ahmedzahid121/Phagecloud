using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace PhageVirus.Modules
{
    /// <summary>
    /// Unified module manager that coordinates all PhageVirus modules with cloud integration
    /// Provides centralized control, monitoring, and resource management
    /// </summary>
    public class UnifiedModuleManager
    {
        private static UnifiedModuleManager? instance;
        private static readonly object managerLock = new object();
        private static bool isInitialized = false;
        private static bool isRunning = false;
        
        // Module tracking
        private static readonly ConcurrentDictionary<string, ModuleStatus> moduleStatus = new();
        private static readonly ConcurrentDictionary<string, Task> moduleTasks = new();
        
        // Performance monitoring
        private static readonly PerformanceMonitor performanceMonitor = new();
        private static readonly ResourceManager resourceManager = new();
        
        // Cloud integration
        private static CloudIntegration? cloudIntegration;

        public class ModuleStatus
        {
            public string Name { get; set; } = "";
            public bool IsEnabled { get; set; } = false;
            public bool IsRunning { get; set; } = false;
            public ModuleHealth Health { get; set; } = ModuleHealth.Stopped;
            public DateTime StartTime { get; set; }
            public DateTime LastActivity { get; set; }
            public int ErrorCount { get; set; } = 0;
            public string LastError { get; set; } = "";
            public bool CloudEnabled { get; set; } = false;
            public long MemoryUsage { get; set; } = 0;
            public double CpuUsage { get; set; } = 0.0;
        }

        public class PerformanceMonitor
        {
            public long TotalMemoryUsage { get; set; } = 0;
            public double TotalCpuUsage { get; set; } = 0.0;
            public int ActiveModules { get; set; } = 0;
            public int FailedModules { get; set; } = 0;
            public DateTime LastUpdate { get; set; } = DateTime.Now;
        }

        public class ResourceManager
        {
            private static readonly object resourceLock = new object();
            private static long currentMemoryUsage = 0;
            private static double currentCpuUsage = 0.0;

            public bool CanStartModule(string moduleName)
            {
                lock (resourceLock)
                {
                    var config = UnifiedConfig.Instance;
                    var moduleSettings = config.GetModulePerformanceSettings(moduleName);
                    
                    // Check memory limit
                    var estimatedMemory = GetEstimatedMemoryUsage(moduleName);
                    if (currentMemoryUsage + estimatedMemory > moduleSettings.MaxMemoryUsage * 1024 * 1024)
                    {
                        return false;
                    }
                    
                    // Check CPU limit
                    var estimatedCpu = GetEstimatedCpuUsage(moduleName);
                    if (currentCpuUsage + estimatedCpu > moduleSettings.MaxCpuUsage)
                    {
                        return false;
                    }
                    
                    return true;
                }
            }

            public void RegisterModuleResource(string moduleName, long memoryUsage, double cpuUsage)
            {
                lock (resourceLock)
                {
                    currentMemoryUsage += memoryUsage;
                    currentCpuUsage += cpuUsage;
                }
            }

            public void UnregisterModuleResource(string moduleName, long memoryUsage, double cpuUsage)
            {
                lock (resourceLock)
                {
                    currentMemoryUsage = Math.Max(0, currentMemoryUsage - memoryUsage);
                    currentCpuUsage = Math.Max(0.0, currentCpuUsage - cpuUsage);
                }
            }

            private long GetEstimatedMemoryUsage(string moduleName)
            {
                return moduleName.ToLower() switch
                {
                    "processwatcher" => 20 * 1024 * 1024, // 20MB
                    "memorytrap" => 30 * 1024 * 1024, // 30MB
                    "credentialtrap" => 25 * 1024 * 1024, // 25MB
                    "exploitshield" => 35 * 1024 * 1024, // 35MB
                    "firewallguard" => 15 * 1024 * 1024, // 15MB
                    "anomalyscoreclassifier" => 50 * 1024 * 1024, // 50MB
                    "diagnostictest" => 100 * 1024 * 1024, // 100MB
                    "behaviortest" => 75 * 1024 * 1024, // 75MB
                    "redteamagent" => 150 * 1024 * 1024, // 150MB
                    "livecommandshell" => 40 * 1024 * 1024, // 40MB
                    "dnssinkhole" => 20 * 1024 * 1024, // 20MB
                    "phagesync" => 30 * 1024 * 1024, // 30MB
                    "honeyprocess" => 25 * 1024 * 1024, // 25MB
                    "zerotrustruntime" => 45 * 1024 * 1024, // 45MB
                    "rollbackengine" => 60 * 1024 * 1024, // 60MB
                    "phishingguard" => 15 * 1024 * 1024, // 15MB
                    "autorunblocker" => 20 * 1024 * 1024, // 20MB
                    "sandboxmode" => 30 * 1024 * 1024, // 30MB
                    "watchdogcore" => 25 * 1024 * 1024, // 25MB
                    "selfreplicator" => 35 * 1024 * 1024, // 35MB
                    "virushunter" => 80 * 1024 * 1024, // 80MB
                    "payloadreplacer" => 40 * 1024 * 1024, // 40MB
                    "systemhacker" => 50 * 1024 * 1024, // 50MB
                    _ => 25 * 1024 * 1024 // Default 25MB
                };
            }

            private double GetEstimatedCpuUsage(string moduleName)
            {
                return moduleName.ToLower() switch
                {
                    "processwatcher" => 2.0, // 2%
                    "memorytrap" => 3.0, // 3%
                    "credentialtrap" => 2.5, // 2.5%
                    "exploitshield" => 4.0, // 4%
                    "firewallguard" => 1.5, // 1.5%
                    "anomalyscoreclassifier" => 3.0, // 3%
                    "diagnostictest" => 5.0, // 5%
                    "behaviortest" => 4.0, // 4%
                    "redteamagent" => 8.0, // 8%
                    "livecommandshell" => 2.0, // 2%
                    "dnssinkhole" => 1.5, // 1.5%
                    "phagesync" => 2.0, // 2%
                    "honeyprocess" => 2.5, // 2.5%
                    "zerotrustruntime" => 3.5, // 3.5%
                    "rollbackengine" => 4.5, // 4.5%
                    "phishingguard" => 1.0, // 1%
                    "autorunblocker" => 1.5, // 1.5%
                    "sandboxmode" => 2.5, // 2.5%
                    "watchdogcore" => 2.0, // 2%
                    "selfreplicator" => 3.0, // 3%
                    "virushunter" => 6.0, // 6%
                    "payloadreplacer" => 3.5, // 3.5%
                    "systemhacker" => 4.0, // 4%
                    _ => 2.0 // Default 2%
                };
            }
        }

        public static UnifiedModuleManager Instance
        {
            get
            {
                if (instance == null)
                {
                    lock (managerLock)
                    {
                        instance ??= new UnifiedModuleManager();
                    }
                }
                return instance;
            }
        }

        private UnifiedModuleManager() { }

        public async Task InitializeAsync()
        {
            if (isInitialized) return;

            lock (managerLock)
            {
                if (isInitialized) return;

                try
                {
                    EnhancedLogger.LogInfo("Initializing unified module manager...");
                    
                    // Load configuration
                    var config = UnifiedConfig.Instance;
                    config.ApplyModeOptimizations();
                    
                    // Initialize cloud integration
                    if (config.Cloud.Enabled)
                    {
                        cloudIntegration = new CloudIntegration();
                        cloudIntegration.Initialize(new CloudIntegration.CloudConfig
                        {
                            Mode = config.Mode,
                            Azure = new CloudIntegration.AzureConfig
                            {
                                Endpoint = config.Cloud.Azure.Endpoint,
                                AuthMethod = config.Cloud.Azure.AuthMethod,
                                ApiKey = config.Cloud.Azure.ApiKey,
                                Enabled = config.Cloud.Azure.Enabled
                            },
                            AWS = new CloudIntegration.AWSConfig
                            {
                                Region = config.Cloud.AWS.Region,
                                KinesisStream = config.Cloud.AWS.KinesisStream,
                                DynamoDBTable = config.Cloud.AWS.DynamoDBTable,
                                AccessKey = config.Cloud.AWS.AccessKey,
                                SecretKey = config.Cloud.AWS.SecretKey,
                                Enabled = config.Cloud.AWS.Enabled
                            },
                            Telemetry = new CloudIntegration.TelemetryConfig
                            {
                                Enabled = config.Cloud.Telemetry.Enabled,
                                HeartbeatInterval = config.Cloud.Telemetry.HeartbeatInterval,
                                BatchSize = config.Cloud.Telemetry.BatchSize,
                                RetryAttempts = config.Cloud.Telemetry.RetryAttempts,
                                Compression = config.Cloud.Telemetry.Compression,
                                Encryption = config.Cloud.Telemetry.Encryption
                            }
                        });
                    }
                    
                    // Initialize module status tracking
                    InitializeModuleStatus();
                    
                    isInitialized = true;
                    EnhancedLogger.LogSuccess("Unified module manager initialized successfully");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to initialize unified module manager: {ex.Message}");
                    throw;
                }
            }
        }

        public async Task StartAsync()
        {
            if (!isInitialized)
                await InitializeAsync();

            if (isRunning) return;

            lock (managerLock)
            {
                if (isRunning) return;

                try
                {
                    EnhancedLogger.LogInfo("Starting unified module manager...");
                    
                    var config = UnifiedConfig.Instance;
                    
                    // Start enabled modules
                    await StartEnabledModulesAsync();
                    
                    // Start performance monitoring
                    Task.Run(() => MonitorPerformanceAsync());
                    
                    // Start resource management
                    Task.Run(() => ManageResourcesAsync());
                    
                    isRunning = true;
                    EnhancedLogger.LogSuccess("Unified module manager started successfully");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to start unified module manager: {ex.Message}");
                    throw;
                }
            }
        }

        public async Task StopAsync()
        {
            if (!isRunning) return;

            lock (managerLock)
            {
                if (!isRunning) return;

                try
                {
                    EnhancedLogger.LogInfo("Stopping unified module manager...");
                    
                    // Stop all modules
                    foreach (var kvp in moduleTasks)
                    {
                        try
                        {
                            // Signal modules to stop (they should check for cancellation)
                            if (moduleStatus.TryGetValue(kvp.Key, out var status))
                            {
                                status.IsRunning = false;
                                status.Health = ModuleHealth.Stopped;
                            }
                        }
                        catch (Exception ex)
                        {
                            EnhancedLogger.LogWarning($"Failed to stop module {kvp.Key}: {ex.Message}");
                        }
                    }
                    
                    // Wait for modules to stop
                    Task.WaitAll(moduleTasks.Values.ToArray(), TimeSpan.FromSeconds(30));
                    
                    isRunning = false;
                    EnhancedLogger.LogSuccess("Unified module manager stopped successfully");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to stop unified module manager: {ex.Message}");
                }
            }
        }

        private void InitializeModuleStatus()
        {
            var config = UnifiedConfig.Instance;
            var modules = new[]
            {
                "ProcessWatcher", "MemoryTrap", "CredentialTrap", "ExploitShield", "FirewallGuard",
                "AnomalyScoreClassifier", "DiagnosticTest", "BehaviorTest", "RedTeamAgent",
                "LiveCommandShell", "DnsSinkhole", "PhageSync", "HoneyProcess", "ZeroTrustRuntime",
                "RollbackEngine", "PhishingGuard", "AutorunBlocker", "SandboxMode", "WatchdogCore",
                "SelfReplicator", "VirusHunter", "PayloadReplacer", "SystemHacker"
            };

            foreach (var module in modules)
            {
                moduleStatus[module] = new ModuleStatus
                {
                    Name = module,
                    IsEnabled = config.IsModuleEnabled(module),
                    CloudEnabled = config.IsCloudAvailableForModule(module),
                    Health = ModuleHealth.Stopped
                };
            }
        }

        private async Task StartEnabledModulesAsync()
        {
            var config = UnifiedConfig.Instance;
            
            foreach (var kvp in moduleStatus)
            {
                var moduleName = kvp.Key;
                var status = kvp.Value;
                
                if (!status.IsEnabled) continue;
                
                // Check resource availability
                if (!resourceManager.CanStartModule(moduleName))
                {
                    EnhancedLogger.LogWarning($"Insufficient resources to start module: {moduleName}");
                    status.Health = ModuleHealth.Failed;
                    continue;
                }
                
                // Start module
                try
                {
                    var task = StartModuleAsync(moduleName);
                    moduleTasks[moduleName] = task;
                    status.IsRunning = true;
                    status.Health = ModuleHealth.Running;
                    status.StartTime = DateTime.Now;
                    
                    EnhancedLogger.LogInfo($"Started module: {moduleName}");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to start module {moduleName}: {ex.Message}");
                    status.Health = ModuleHealth.Failed;
                    status.LastError = ex.Message;
                    status.ErrorCount++;
                }
            }
        }

        private async Task StartModuleAsync(string moduleName)
        {
            var status = moduleStatus[moduleName];
            var config = UnifiedConfig.Instance;
            
            try
            {
                // Estimate resource usage
                var estimatedMemory = resourceManager.GetEstimatedMemoryUsage(moduleName);
                var estimatedCpu = resourceManager.GetEstimatedCpuUsage(moduleName);
                resourceManager.RegisterModuleResource(moduleName, estimatedMemory, estimatedCpu);
                
                // Start module based on name
                switch (moduleName.ToLower())
                {
                    case "processwatcher":
                        ProcessWatcher.StartWatching();
                        break;
                    case "memorytrap":
                        // MemoryTrap would be started here
                        break;
                    case "credentialtrap":
                        CredentialTrap.StartCredentialMonitoring();
                        break;
                    case "anomalyscoreclassifier":
                        AnomalyScoreClassifier.Initialize();
                        break;
                    case "exploitshield":
                        // ExploitShield would be started here
                        break;
                    case "firewallguard":
                        // FirewallGuard would be started here
                        break;
                    case "dnssinkhole":
                        // DnsSinkhole would be started here
                        break;
                    case "phagesync":
                        // PhageSync would be started here
                        break;
                    case "honeyprocess":
                        // HoneyProcess would be started here
                        break;
                    case "zerotrustruntime":
                        // ZeroTrustRuntime would be started here
                        break;
                    case "rollbackengine":
                        // RollbackEngine would be started here
                        break;
                    case "phishingguard":
                        // PhishingGuard would be started here
                        break;
                    case "autorunblocker":
                        // AutorunBlocker would be started here
                        break;
                    case "sandboxmode":
                        // SandboxMode would be started here
                        break;
                    case "watchdogcore":
                        // WatchdogCore would be started here
                        break;
                    case "selfreplicator":
                        // SelfReplicator would be started here
                        break;
                    case "virushunter":
                        // VirusHunter would be started here
                        break;
                    case "payloadreplacer":
                        // PayloadReplacer would be started here
                        break;
                    case "systemhacker":
                        // SystemHacker would be started here
                        break;
                    case "diagnostictest":
                        // DiagnosticTest would be started here
                        break;
                    case "behaviortest":
                        // BehaviorTest would be started here
                        break;
                    case "redteamagent":
                        // RedTeamAgent would be started here
                        break;
                    case "livecommandshell":
                        // LiveCommandShell would be started here
                        break;
                }
                
                // Monitor module health
                while (status.IsRunning && isRunning)
                {
                    status.LastActivity = DateTime.Now;
                    
                    // Update resource usage
                    var currentMemory = GC.GetTotalMemory(false);
                    var currentCpu = Process.GetCurrentProcess().TotalProcessorTime.TotalSeconds;
                    status.MemoryUsage = currentMemory;
                    status.CpuUsage = currentCpu;
                    
                    await Task.Delay(TimeSpan.FromSeconds(30));
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Module {moduleName} failed: {ex.Message}");
                status.Health = ModuleHealth.Failed;
                status.LastError = ex.Message;
                status.ErrorCount++;
            }
            finally
            {
                // Cleanup resources
                resourceManager.UnregisterModuleResource(moduleName, 
                    resourceManager.GetEstimatedMemoryUsage(moduleName),
                    resourceManager.GetEstimatedCpuUsage(moduleName));
                
                status.IsRunning = false;
                status.Health = ModuleHealth.Stopped;
            }
        }

        private async Task MonitorPerformanceAsync()
        {
            while (isRunning)
            {
                try
                {
                    var totalMemory = 0L;
                    var totalCpu = 0.0;
                    var activeModules = 0;
                    var failedModules = 0;
                    
                    foreach (var kvp in moduleStatus)
                    {
                        var status = kvp.Value;
                        if (status.IsRunning)
                        {
                            totalMemory += status.MemoryUsage;
                            totalCpu += status.CpuUsage;
                            activeModules++;
                        }
                        else if (status.Health == ModuleHealth.Failed)
                        {
                            failedModules++;
                        }
                    }
                    
                    performanceMonitor.TotalMemoryUsage = totalMemory;
                    performanceMonitor.TotalCpuUsage = totalCpu;
                    performanceMonitor.ActiveModules = activeModules;
                    performanceMonitor.FailedModules = failedModules;
                    performanceMonitor.LastUpdate = DateTime.Now;
                    
                    // Send performance telemetry to cloud
                    if (cloudIntegration != null)
                    {
                        await cloudIntegration.SendTelemetryAsync("UnifiedModuleManager", "performance", new
                        {
                            total_memory_mb = totalMemory / (1024 * 1024),
                            total_cpu_percent = totalCpu,
                            active_modules = activeModules,
                            failed_modules = failedModules,
                            timestamp = DateTime.UtcNow
                        });
                    }
                    
                    await Task.Delay(TimeSpan.FromMinutes(1));
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogWarning($"Performance monitoring error: {ex.Message}");
                    await Task.Delay(TimeSpan.FromSeconds(30));
                }
            }
        }

        private async Task ManageResourcesAsync()
        {
            while (isRunning)
            {
                try
                {
                    var config = UnifiedConfig.Instance;
                    
                    // Check if we need to throttle modules due to resource constraints
                    if (performanceMonitor.TotalMemoryUsage > config.Performance.MaxMemoryUsage * 1024 * 1024 ||
                        performanceMonitor.TotalCpuUsage > config.Performance.MaxCpuUsage)
                    {
                        EnhancedLogger.LogWarning("Resource limits exceeded, throttling modules...");
                        
                        // Throttle heavy modules
                        foreach (var kvp in moduleStatus)
                        {
                            var moduleName = kvp.Key;
                            var status = kvp.Value;
                            
                            if (status.IsRunning && IsHeavyModule(moduleName))
                            {
                                // Signal module to reduce activity
                                EnhancedLogger.LogInfo($"Throttling module: {moduleName}");
                            }
                        }
                    }
                    
                    await Task.Delay(TimeSpan.FromMinutes(2));
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogWarning($"Resource management error: {ex.Message}");
                    await Task.Delay(TimeSpan.FromSeconds(60));
                }
            }
        }

        private bool IsHeavyModule(string moduleName)
        {
            return moduleName.ToLower() switch
            {
                "anomalyscoreclassifier" => true,
                "diagnostictest" => true,
                "behaviortest" => true,
                "redteamagent" => true,
                "virushunter" => true,
                _ => false
            };
        }

        public Dictionary<string, ModuleStatus> GetModuleStatus() => new(moduleStatus);
        public PerformanceMonitor GetPerformanceMonitor() => performanceMonitor;
        public bool IsInitialized => isInitialized;
        public bool IsRunning => isRunning;
    }
} 
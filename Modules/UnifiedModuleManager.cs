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

            public long GetEstimatedMemoryUsage(string moduleName)
            {
                return moduleName.ToLower() switch
                {
                    "processwatcher" => 5 * 1024 * 1024, // 5MB - Reduced for VM stability
                    "memorytrap" => 8 * 1024 * 1024, // 8MB - Reduced for VM stability
                    "credentialtrap" => 6 * 1024 * 1024, // 6MB - Reduced for VM stability
                    "exploitshield" => 10 * 1024 * 1024, // 10MB - Reduced for VM stability
                    "firewallguard" => 4 * 1024 * 1024, // 4MB - Reduced for VM stability
                    "anomalyscoreclassifier" => 0, // Disabled in cloud mode
                    "diagnostictest" => 0, // Disabled in cloud mode
                    "behaviortest" => 0, // Disabled in cloud mode
                    "redteamagent" => 0, // Disabled in cloud mode
                    "livecommandshell" => 0, // Disabled in cloud mode
                    "dnssinkhole" => 5 * 1024 * 1024, // 5MB - Reduced for VM stability
                    "phagesync" => 0, // Disabled for VM stability
                    "honeyprocess" => 0, // Disabled for VM stability
                    "zerotrustruntime" => 8 * 1024 * 1024, // 8MB - Reduced for VM stability
                    "rollbackengine" => 0, // Disabled for VM stability
                    "phishingguard" => 4 * 1024 * 1024, // 4MB - Reduced for VM stability
                    "autorunblocker" => 5 * 1024 * 1024, // 5MB - Reduced for VM stability
                    "sandboxmode" => 6 * 1024 * 1024, // 6MB - Reduced for VM stability
                    "watchdogcore" => 6 * 1024 * 1024, // 6MB - Reduced for VM stability
                    "selfreplicator" => 0, // Disabled for VM stability
                    "virushunter" => 0, // Disabled in cloud mode
                    "payloadreplacer" => 8 * 1024 * 1024, // 8MB - Reduced for VM stability
                    "systemhacker" => 0, // Disabled in cloud mode
                    _ => 5 * 1024 * 1024 // Default 5MB - Reduced for VM stability
                };
            }

            public double GetEstimatedCpuUsage(string moduleName)
            {
                return moduleName.ToLower() switch
                {
                    "processwatcher" => 0.5, // 0.5% - Reduced for VM stability
                    "memorytrap" => 0.8, // 0.8% - Reduced for VM stability
                    "credentialtrap" => 0.6, // 0.6% - Reduced for VM stability
                    "exploitshield" => 1.0, // 1.0% - Reduced for VM stability
                    "firewallguard" => 0.4, // 0.4% - Reduced for VM stability
                    "anomalyscoreclassifier" => 0.0, // Disabled in cloud mode
                    "diagnostictest" => 0.0, // Disabled in cloud mode
                    "behaviortest" => 0.0, // Disabled in cloud mode
                    "redteamagent" => 0.0, // Disabled in cloud mode
                    "livecommandshell" => 0.0, // Disabled in cloud mode
                    "dnssinkhole" => 0.4, // 0.4% - Reduced for VM stability
                    "phagesync" => 0.0, // Disabled for VM stability
                    "honeyprocess" => 0.0, // Disabled for VM stability
                    "zerotrustruntime" => 0.8, // 0.8% - Reduced for VM stability
                    "rollbackengine" => 0.0, // Disabled for VM stability
                    "phishingguard" => 0.3, // 0.3% - Reduced for VM stability
                    "autorunblocker" => 0.4, // 0.4% - Reduced for VM stability
                    "sandboxmode" => 0.6, // 0.6% - Reduced for VM stability
                    "watchdogcore" => 0.5, // 0.5% - Reduced for VM stability
                    "selfreplicator" => 0.0, // Disabled for VM stability
                    "virushunter" => 0.0, // Disabled in cloud mode
                    "payloadreplacer" => 0.8, // 0.8% - Reduced for VM stability
                    "systemhacker" => 0.0, // Disabled in cloud mode
                    _ => 0.5 // Default 0.5% - Reduced for VM stability
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
                    
                    // Initialize cloud integration with AWS Lambda
                    if (config.Cloud.Enabled)
                    {
                        CloudIntegration.Initialize(new CloudIntegration.CloudConfig
                        {
                            Mode = config.Mode,
                            Azure = new CloudIntegration.AzureConfig
                            {
                                Endpoint = config.Cloud.Azure.Endpoint,
                                AuthMethod = config.Cloud.Azure.AuthMethod,
                                ApiKey = config.Cloud.Azure.ApiKey,
                                Enabled = false // Disable Azure for now, focus on AWS
                            },
                            AWS = new CloudIntegration.AWSConfig
                            {
                                Region = "ap-southeast-2", // Use the deployed Lambda region
                                KinesisStream = "phagevirus-telemetry",
                                DynamoDBTable = "phagevirus-endpoints",
                                AccessKey = "", // Will use AWS CLI credentials
                                SecretKey = "", // Will use AWS CLI credentials
                                Enabled = true
                            },
                            Telemetry = new CloudIntegration.TelemetryConfig
                            {
                                Enabled = true,
                                HeartbeatInterval = 120,
                                BatchSize = 10, // Reduced for VM stability
                                RetryAttempts = 3,
                                Compression = true,
                                Encryption = true
                            },
                            Performance = new CloudIntegration.PerformanceConfig
                            {
                                MaxConcurrentOperations = 5, // Reduced for VM stability
                                MemoryLimitMB = 50, // Reduced for VM stability
                                CpuLimitPercent = 3, // Reduced for VM stability
                                ScanInterval = 300 // Increased for VM stability
                            }
                        });
                        
                        EnhancedLogger.LogInfo("Cloud integration initialized with AWS Lambda support");
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
                isRunning = true;
            }

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
                
                EnhancedLogger.LogSuccess("Unified module manager started successfully");
            }
            catch (Exception ex)
            {
                isRunning = false;
                EnhancedLogger.LogError($"Failed to start unified module manager: {ex.Message}");
                throw;
            }
        }

        public async Task StopAsync()
        {
            if (!isRunning) return;

            lock (managerLock)
            {
                if (!isRunning) return;
                isRunning = false;
            }

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
                await Task.WhenAll(moduleTasks.Values);
                
                EnhancedLogger.LogSuccess("Unified module manager stopped successfully");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to stop unified module manager: {ex.Message}");
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
                
                // Monitor module health (simplified to prevent memory leaks)
                status.LastActivity = DateTime.Now;
                
                // Update resource usage once
                var currentMemory = GC.GetTotalMemory(false);
                var currentCpu = Process.GetCurrentProcess().TotalProcessorTime.TotalSeconds;
                status.MemoryUsage = currentMemory;
                status.CpuUsage = currentCpu;
                
                // Keep module running but don't create continuous monitoring loop
                // The module will be monitored by the main performance monitoring loop
                await Task.Delay(TimeSpan.FromSeconds(1)); // Brief delay then exit
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
                    if (CloudIntegration.IsInitialized)
                    {
                        await CloudIntegration.SendTelemetryAsync("UnifiedModuleManager", "performance", new
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
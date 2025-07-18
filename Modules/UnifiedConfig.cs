using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace PhageVirus.Modules
{
    /// <summary>
    /// Unified configuration system for PhageVirus modules
    /// Supports local, hybrid, and cloud modes with resource optimization
    /// </summary>
    public class UnifiedConfig
    {
        private static UnifiedConfig? instance;
        private static readonly object configLock = new object();
        private static readonly string ConfigPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "PhageVirus", "config", "unified-config.json");

        public string Mode { get; set; } = "hybrid"; // local, hybrid, cloud
        public PerformanceSettings Performance { get; set; } = new();
        public ModuleSettings Modules { get; set; } = new();
        public CloudSettings Cloud { get; set; } = new();
        public SecuritySettings Security { get; set; } = new();
        public LoggingSettings Logging { get; set; } = new();

        public class PerformanceSettings
        {
            // Memory limits (MB)
            public int MaxMemoryUsage { get; set; } = 200;
            public int TargetMemoryUsage { get; set; } = 100;
            
            // CPU limits (%)
            public int MaxCpuUsage { get; set; } = 10;
            public int TargetCpuUsage { get; set; } = 5;
            
            // Scan intervals (seconds)
            public int ProcessScanInterval { get; set; } = 60;
            public int MemoryScanInterval { get; set; } = 120;
            public int FileScanInterval { get; set; } = 300;
            
            // Batch processing
            public int MaxBatchSize { get; set; } = 50;
            public int TelemetryBatchSize { get; set; } = 25;
            
            // Optimization flags
            public bool EnableBatching { get; set; } = true;
            public bool EnableThrottling { get; set; } = true;
            public bool EnableCaching { get; set; } = true;
        }

        public class ModuleSettings
        {
            // Core modules
            public bool ProcessWatcher { get; set; } = true;
            public bool MemoryTrap { get; set; } = true;
            public bool CredentialTrap { get; set; } = true;
            public bool ExploitShield { get; set; } = true;
            public bool FirewallGuard { get; set; } = true;
            
            // Advanced modules (disabled in cloud mode)
            public bool AnomalyScoreClassifier { get; set; } = true;
            public bool DiagnosticTest { get; set; } = true;
            public bool BehaviorTest { get; set; } = true;
            public bool RedTeamAgent { get; set; } = true;
            public bool LiveCommandShell { get; set; } = true;
            
            // Network modules
            public bool DnsSinkhole { get; set; } = true;
            public bool PhageSync { get; set; } = true;
            public bool HoneyProcess { get; set; } = true;
            
            // System modules
            public bool ZeroTrustRuntime { get; set; } = true;
            public bool RollbackEngine { get; set; } = true;
            public bool PhishingGuard { get; set; } = true;
            public bool AutorunBlocker { get; set; } = true;
            public bool SandboxMode { get; set; } = true;
            
            // Core system modules
            public bool WatchdogCore { get; set; } = true;
            public bool SelfReplicator { get; set; } = true;
            public bool VirusHunter { get; set; } = true;
            public bool PayloadReplacer { get; set; } = true;
            public bool SystemHacker { get; set; } = true;
        }

        public class CloudSettings
        {
            public bool Enabled { get; set; } = true;
            public string PrimaryCloud { get; set; } = "azure"; // azure, aws, both
            public AzureSettings Azure { get; set; } = new();
            public AWSSettings AWS { get; set; } = new();
            public TelemetrySettings Telemetry { get; set; } = new();
        }

        public class AzureSettings
        {
            public string Endpoint { get; set; } = "";
            public string AuthMethod { get; set; } = "managed-identity";
            public string ApiKey { get; set; } = "";
            public bool Enabled { get; set; } = true;
        }

        public class AWSSettings
        {
            public string Region { get; set; } = "us-east-1";
            public string KinesisStream { get; set; } = "phagevirus-telemetry";
            public string DynamoDBTable { get; set; } = "phagevirus-endpoints";
            public string AccessKey { get; set; } = "";
            public string SecretKey { get; set; } = "";
            public bool Enabled { get; set; } = true;
        }

        public class TelemetrySettings
        {
            public bool Enabled { get; set; } = true;
            public int HeartbeatInterval { get; set; } = 120;
            public int BatchSize { get; set; } = 50;
            public int RetryAttempts { get; set; } = 3;
            public bool Compression { get; set; } = true;
            public bool Encryption { get; set; } = true;
        }

        public class SecuritySettings
        {
            public bool RequireAdmin { get; set; } = true;
            public bool EnableSelfDestruct { get; set; } = true;
            public bool EnableQuarantine { get; set; } = true;
            public bool EnableRollback { get; set; } = true;
            public int MaxThreatsBeforeRollback { get; set; } = 5;
            public string[] ExcludedPaths { get; set; } = new string[0];
            public string[] ExcludedProcesses { get; set; } = new string[0];
        }

        public class LoggingSettings
        {
            public bool Enabled { get; set; } = true;
            public string Level { get; set; } = "Info"; // Debug, Info, Warning, Error
            public bool ConsoleLogging { get; set; } = true;
            public bool FileLogging { get; set; } = true;
            public bool CloudLogging { get; set; } = true;
            public int MaxLogSizeMB { get; set; } = 100;
            public int LogRetentionDays { get; set; } = 30;
        }

        public static UnifiedConfig Instance
        {
            get
            {
                if (instance == null)
                {
                    lock (configLock)
                    {
                        instance ??= LoadConfig();
                    }
                }
                return instance;
            }
        }

        private static UnifiedConfig LoadConfig()
        {
            try
            {
                if (File.Exists(ConfigPath))
                {
                    var json = File.ReadAllText(ConfigPath);
                    var config = JsonSerializer.Deserialize<UnifiedConfig>(json);
                    if (config != null)
                    {
                        return config;
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to load config: {ex.Message}");
            }

            // Return default configuration
            return CreateDefaultConfig();
        }

        private static UnifiedConfig CreateDefaultConfig()
        {
            return new UnifiedConfig
            {
                Mode = "hybrid",
                Performance = new PerformanceSettings(),
                Modules = new ModuleSettings(),
                Cloud = new CloudSettings(),
                Security = new SecuritySettings(),
                Logging = new LoggingSettings()
            };
        }

        public void SaveConfig()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
                var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(ConfigPath, json);
                EnhancedLogger.LogInfo("Configuration saved successfully");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to save config: {ex.Message}");
            }
        }

        /// <summary>
        /// Apply mode-specific optimizations
        /// </summary>
        public void ApplyModeOptimizations()
        {
            switch (Mode.ToLower())
            {
                case "local":
                    ApplyLocalModeOptimizations();
                    break;
                case "hybrid":
                    ApplyHybridModeOptimizations();
                    break;
                case "cloud":
                    ApplyCloudModeOptimizations();
                    break;
                default:
                    ApplyHybridModeOptimizations();
                    break;
            }
        }

        private void ApplyLocalModeOptimizations()
        {
            // Full power mode - all modules enabled
            Performance.MaxMemoryUsage = 500;
            Performance.MaxCpuUsage = 20;
            Performance.ProcessScanInterval = 30;
            Performance.MemoryScanInterval = 60;
            Performance.FileScanInterval = 120;
            
            // Enable all modules
            Modules.AnomalyScoreClassifier = true;
            Modules.DiagnosticTest = true;
            Modules.BehaviorTest = true;
            Modules.RedTeamAgent = true;
            Modules.LiveCommandShell = true;
            
            // Disable cloud features
            Cloud.Enabled = false;
            
            EnhancedLogger.LogInfo("Applied local mode optimizations - full power enabled");
        }

        private void ApplyHybridModeOptimizations()
        {
            // Balanced mode - moderate resource usage
            Performance.MaxMemoryUsage = 200;
            Performance.MaxCpuUsage = 10;
            Performance.ProcessScanInterval = 60;
            Performance.MemoryScanInterval = 120;
            Performance.FileScanInterval = 300;
            
            // Enable core modules locally, advanced modules with cloud offloading
            Modules.AnomalyScoreClassifier = true;
            Modules.DiagnosticTest = true;
            Modules.BehaviorTest = true;
            Modules.RedTeamAgent = false; // Cloud-based
            Modules.LiveCommandShell = true;
            
            // Enable cloud features
            Cloud.Enabled = true;
            
            EnhancedLogger.LogInfo("Applied hybrid mode optimizations - balanced local and cloud processing");
        }

        private void ApplyCloudModeOptimizations()
        {
            // Lightweight mode - minimal local processing
            Performance.MaxMemoryUsage = 100;
            Performance.MaxCpuUsage = 5;
            Performance.ProcessScanInterval = 120;
            Performance.MemoryScanInterval = 300;
            Performance.FileScanInterval = 600;
            
            // Disable heavy local modules, rely on cloud
            Modules.AnomalyScoreClassifier = false; // Cloud-based
            Modules.DiagnosticTest = false; // Cloud-based
            Modules.BehaviorTest = false; // Cloud-based
            Modules.RedTeamAgent = false; // Cloud-based
            Modules.LiveCommandShell = false; // Cloud-based
            
            // Enable cloud features
            Cloud.Enabled = true;
            
            EnhancedLogger.LogInfo("Applied cloud mode optimizations - lightweight local processing with cloud offloading");
        }

        /// <summary>
        /// Get module-specific configuration
        /// </summary>
        public bool IsModuleEnabled(string moduleName)
        {
            return moduleName.ToLower() switch
            {
                "processwatcher" => Modules.ProcessWatcher,
                "memorytrap" => Modules.MemoryTrap,
                "credentialtrap" => Modules.CredentialTrap,
                "exploitshield" => Modules.ExploitShield,
                "firewallguard" => Modules.FirewallGuard,
                "anomalyscoreclassifier" => Modules.AnomalyScoreClassifier,
                "diagnostictest" => Modules.DiagnosticTest,
                "behaviortest" => Modules.BehaviorTest,
                "redteamagent" => Modules.RedTeamAgent,
                "livecommandshell" => Modules.LiveCommandShell,
                "dnssinkhole" => Modules.DnsSinkhole,
                "phagesync" => Modules.PhageSync,
                "honeyprocess" => Modules.HoneyProcess,
                "zerotrustruntime" => Modules.ZeroTrustRuntime,
                "rollbackengine" => Modules.RollbackEngine,
                "phishingguard" => Modules.PhishingGuard,
                "autorunblocker" => Modules.AutorunBlocker,
                "sandboxmode" => Modules.SandboxMode,
                "watchdogcore" => Modules.WatchdogCore,
                "selfreplicator" => Modules.SelfReplicator,
                "virushunter" => Modules.VirusHunter,
                "payloadreplacer" => Modules.PayloadReplacer,
                "systemhacker" => Modules.SystemHacker,
                _ => false
            };
        }

        /// <summary>
        /// Check if cloud features are available for a module
        /// </summary>
        public bool IsCloudAvailableForModule(string moduleName)
        {
            if (!Cloud.Enabled) return false;

            // Modules that can be cloud-offloaded
            var cloudModules = new[]
            {
                "anomalyscoreclassifier",
                "diagnostictest", 
                "behaviortest",
                "redteamagent",
                "livecommandshell",
                "virushunter"
            };

            return Array.Exists(cloudModules, m => m.Equals(moduleName, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Get performance settings for a module
        /// </summary>
        public PerformanceSettings GetModulePerformanceSettings(string moduleName)
        {
            var settings = new PerformanceSettings
            {
                MaxMemoryUsage = Performance.MaxMemoryUsage,
                MaxCpuUsage = Performance.MaxCpuUsage,
                EnableBatching = Performance.EnableBatching,
                EnableThrottling = Performance.EnableThrottling,
                EnableCaching = Performance.EnableCaching
            };

            // Module-specific adjustments
            switch (moduleName.ToLower())
            {
                case "anomalyscoreclassifier":
                    settings.MaxMemoryUsage = Math.Min(settings.MaxMemoryUsage, 50);
                    settings.MaxCpuUsage = Math.Min(settings.MaxCpuUsage, 3);
                    break;
                case "diagnostictest":
                    settings.MaxMemoryUsage = Math.Min(settings.MaxMemoryUsage, 100);
                    settings.MaxCpuUsage = Math.Min(settings.MaxCpuUsage, 5);
                    break;
                case "behaviortest":
                    settings.MaxMemoryUsage = Math.Min(settings.MaxMemoryUsage, 75);
                    settings.MaxCpuUsage = Math.Min(settings.MaxCpuUsage, 4);
                    break;
                case "redteamagent":
                    settings.MaxMemoryUsage = Math.Min(settings.MaxMemoryUsage, 150);
                    settings.MaxCpuUsage = Math.Min(settings.MaxCpuUsage, 8);
                    break;
            }

            return settings;
        }
    }
} 
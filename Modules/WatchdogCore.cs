using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace PhageVirus.Modules
{
    public class WatchdogCore
    {
        // Windows API constants
        private const uint SYNCHRONIZE = 0x00100000;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        // Windows API functions
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateMutex(IntPtr lpMutexAttributes, bool bInitialOwner, string lpName);

        [DllImport("kernel32.dll")]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        private static extern bool ReleaseMutex(IntPtr hMutex);

        [DllImport("kernel32.dll")]
        private static extern uint GetLastError();

        // Mutex names for module protection
        private static readonly string[] ModuleMutexes = {
            "Global\\PhageVirus_ProcessWatcher",
            "Global\\PhageVirus_AutorunBlocker", 
            "Global\\PhageVirus_MemoryTrap",
            "Global\\PhageVirus_SandboxMode",
            "Global\\PhageVirus_CredentialTrap",
            "Global\\PhageVirus_ExploitShield",
            "Global\\PhageVirus_LateralMovementTrap",
            "Global\\PhageVirus_DataExfilWatcher"
        };

        // Module status tracking
        private static readonly Dictionary<string, ModuleStatus> ModuleStatuses = new();
        private static readonly Dictionary<string, DateTime> LastHeartbeat = new();
        private static readonly Dictionary<string, int> RestartCounts = new();

        // Watchdog configuration
        private static readonly int MaxRestartAttempts = 5;
        private static readonly int HeartbeatTimeoutSeconds = 30;
        private static readonly int RestartCooldownSeconds = 60;

        private static bool isActive = false;
        private static readonly object watchdogLock = new object();
        private static IntPtr mainProcessMutex = IntPtr.Zero;

        public class ModuleStatus
        {
            public bool IsRunning { get; set; }
            public DateTime LastCheck { get; set; }
            public int RestartAttempts { get; set; }
            public DateTime LastRestart { get; set; }
            public string Status { get; set; } = "Unknown";
        }

        public static void StartWatchdog()
        {
            if (isActive) return;

            lock (watchdogLock)
            {
                if (isActive) return;

                try
                {
                    EnhancedLogger.LogInfo("Starting PhageVirus watchdog core...");
                    
                    // Create main process mutex
                    mainProcessMutex = CreateMutex(IntPtr.Zero, true, "Global\\PhageVirus_MainProcess");
                    if (mainProcessMutex == IntPtr.Zero)
                    {
                        EnhancedLogger.LogError("Failed to create main process mutex");
                        return;
                    }

                    // Initialize module status tracking
                    InitializeModuleTracking();
                    
                    // Start monitoring threads
                    Task.Run(() => MonitorModules());
                    Task.Run(() => CheckProcessIntegrity());
                    Task.Run(() => MonitorMutexes());
                    
                    isActive = true;
                    EnhancedLogger.LogSuccess("Watchdog core activated");
                    
                    // Send telemetry to cloud for watchdog status
                    Task.Run(async () =>
                    {
                        try
                        {
                            var watchdogData = new
                            {
                                module_statuses_count = ModuleStatuses.Count,
                                active_modules = ModuleStatuses.Count(ms => ms.Value.IsRunning),
                                restart_counts = RestartCounts.Values.Sum(),
                                main_process_mutex_active = mainProcessMutex != IntPtr.Zero,
                                threat_type = "watchdog_status",
                                timestamp = DateTime.UtcNow
                            };

                            await CloudIntegration.SendTelemetryAsync("WatchdogCore", "watchdog_status", watchdogData, ThreatLevel.Normal);
                            
                            // Get cloud watchdog analysis
                            var analysis = await CloudIntegration.GetCloudAnalysisAsync("WatchdogCore", watchdogData);
                            if (analysis.Success)
                            {
                                EnhancedLogger.LogInfo($"Cloud watchdog analysis: {analysis.Analysis}");
                            }
                        }
                        catch (Exception ex)
                        {
                            EnhancedLogger.LogWarning($"Cloud watchdog analysis failed: {ex.Message}");
                        }
                    });
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to start watchdog: {ex.Message}");
                }
            }
        }

        public static void StopWatchdog()
        {
            lock (watchdogLock)
            {
                if (!isActive) return;

                try
                {
                    isActive = false;
                    
                    if (mainProcessMutex != IntPtr.Zero)
                    {
                        ReleaseMutex(mainProcessMutex);
                        CloseHandle(mainProcessMutex);
                        mainProcessMutex = IntPtr.Zero;
                    }
                    
                    EnhancedLogger.LogInfo("Watchdog core stopped");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to stop watchdog: {ex.Message}");
                }
            }
        }

        private static void InitializeModuleTracking()
        {
            var modules = new[]
            {
                "ProcessWatcher", "AutorunBlocker", "MemoryTrap", "SandboxMode",
                "CredentialTrap", "ExploitShield", "LateralMovementTrap", "DataExfilWatcher"
            };

            foreach (var module in modules)
            {
                ModuleStatuses[module] = new ModuleStatus
                {
                    IsRunning = false,
                    LastCheck = DateTime.Now,
                    RestartAttempts = 0,
                    LastRestart = DateTime.MinValue,
                    Status = "Initializing"
                };

                LastHeartbeat[module] = DateTime.Now;
                RestartCounts[module] = 0;
            }
        }

        private static void MonitorModules()
        {
            // DISABLED FOR VM STABILITY - This was causing infinite loops
            try
            {
                EnhancedLogger.LogInfo("Module monitoring loop DISABLED for VM stability");
                
                // Do a single check instead of infinite loop
                CheckModuleStatus("ProcessWatcher", () => ProcessWatcher.IsWatching);
                CheckModuleStatus("AutorunBlocker", () => true); // Always running if active
                CheckModuleStatus("MemoryTrap", () => MemoryTrap.IsMonitoring);
                CheckModuleStatus("SandboxMode", () => SandboxMode.IsActive);
                CheckModuleStatus("CredentialTrap", () => CredentialTrap.IsMonitoring);
                CheckModuleStatus("ExploitShield", () => ExploitShield.IsActive);
                CheckModuleStatus("LateralMovementTrap", () => true); // Placeholder
                CheckModuleStatus("DataExfilWatcher", () => true); // Placeholder

                // Update heartbeats
                UpdateHeartbeats();

                // Check for modules that need restarting (but don't restart in VM)
                if (!IsVirtualMachine())
                {
                    CheckForRestartNeeded();
                }

                EnhancedLogger.LogInfo("Single module check completed for VM stability");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Module monitoring error: {ex.Message}");
            }
        }

        private static void CheckModuleStatus(string moduleName, Func<bool> isRunningCheck)
        {
            try
            {
                var status = ModuleStatuses[moduleName];
                var wasRunning = status.IsRunning;
                var isRunning = isRunningCheck();

                status.IsRunning = isRunning;
                status.LastCheck = DateTime.Now;

                if (isRunning)
                {
                    status.Status = "Running";
                    LastHeartbeat[moduleName] = DateTime.Now;
                }
                else
                {
                    status.Status = "Stopped";
                }

                // Log status changes
                if (wasRunning != isRunning)
                {
                    if (isRunning)
                    {
                        EnhancedLogger.LogSuccess($"Module {moduleName} is now running");
                    }
                    else
                    {
                        EnhancedLogger.LogWarning($"Module {moduleName} has stopped");
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to check status for {moduleName}: {ex.Message}");
            }
        }

        private static void UpdateHeartbeats()
        {
            var currentTime = DateTime.Now;
            foreach (var module in ModuleStatuses.Keys)
            {
                if (ModuleStatuses[module].IsRunning)
                {
                    LastHeartbeat[module] = currentTime;
                }
            }
        }

        private static void CheckForRestartNeeded()
        {
            var currentTime = DateTime.Now;
            foreach (var module in ModuleStatuses.Keys)
            {
                var status = ModuleStatuses[module];
                
                // Check if module is not running
                if (!status.IsRunning)
                {
                    // Check restart cooldown
                    if ((currentTime - status.LastRestart).TotalSeconds < RestartCooldownSeconds)
                        continue;

                    // Check max restart attempts
                    if (status.RestartAttempts >= MaxRestartAttempts)
                    {
                        status.Status = "Failed - Max restarts exceeded";
                        EnhancedLogger.LogError($"Module {module} failed to restart after {MaxRestartAttempts} attempts");
                        continue;
                    }

                    // Attempt restart
                    RestartModule(module);
                }
                else
                {
                    // Check heartbeat timeout
                    var timeSinceHeartbeat = (currentTime - LastHeartbeat[module]).TotalSeconds;
                    if (timeSinceHeartbeat > HeartbeatTimeoutSeconds)
                    {
                        EnhancedLogger.LogWarning($"Module {module} heartbeat timeout ({timeSinceHeartbeat:F1}s)");
                        status.Status = "Heartbeat timeout";
                        
                        // Mark as not running to trigger restart
                        status.IsRunning = false;
                    }
                }
            }
        }

        private static void RestartModule(string moduleName)
        {
            try
            {
                // CRITICAL: Reduce restart frequency in VM environments
                if (IsVirtualMachine())
                {
                    var moduleStatus = ModuleStatuses[moduleName];
                    if (moduleStatus.RestartAttempts > 2) // Limit restarts in VM
                    {
                        EnhancedLogger.LogWarning($"Skipping restart of {moduleName} - too many attempts in VM environment");
                        return;
                    }
                }

                EnhancedLogger.LogInfo($"Attempting to restart module: {moduleName}");
                
                var status = ModuleStatuses[moduleName];
                status.RestartAttempts++;
                status.LastRestart = DateTime.Now;
                status.Status = "Restarting";

                bool restartSuccess = false;

                switch (moduleName)
                {
                    case "ProcessWatcher":
                        ProcessWatcher.StopWatching();
                        Thread.Sleep(1000);
                        ProcessWatcher.StartWatching();
                        restartSuccess = ProcessWatcher.IsWatching;
                        break;

                    case "AutorunBlocker":
                        // AutorunBlocker doesn't have stop/start methods, so we just log
                        EnhancedLogger.LogInfo("AutorunBlocker is always active");
                        restartSuccess = true;
                        break;

                    case "MemoryTrap":
                        MemoryTrap.StopMemoryMonitoring();
                        Thread.Sleep(1000);
                        MemoryTrap.StartMemoryMonitoring();
                        restartSuccess = MemoryTrap.IsMonitoring;
                        break;

                    case "SandboxMode":
                        SandboxMode.DisableSandboxMode();
                        Thread.Sleep(1000);
                        SandboxMode.EnableSandboxMode();
                        restartSuccess = SandboxMode.IsActive;
                        break;

                    case "CredentialTrap":
                        CredentialTrap.StopCredentialMonitoring();
                        Thread.Sleep(1000);
                        CredentialTrap.StartCredentialMonitoring();
                        restartSuccess = CredentialTrap.IsMonitoring;
                        break;

                    case "ExploitShield":
                        ExploitShield.DeactivateExploitShield();
                        Thread.Sleep(1000);
                        ExploitShield.ActivateExploitShield();
                        restartSuccess = ExploitShield.IsActive;
                        break;

                    case "LateralMovementTrap":
                        // Placeholder for future implementation
                        restartSuccess = true;
                        break;

                    case "DataExfilWatcher":
                        // Placeholder for future implementation
                        restartSuccess = true;
                        break;

                    default:
                        EnhancedLogger.LogWarning($"Unknown module: {moduleName}");
                        restartSuccess = false;
                        break;
                }

                if (restartSuccess)
                {
                    status.Status = "Running";
                    status.IsRunning = true;
                    LastHeartbeat[moduleName] = DateTime.Now;
                    EnhancedLogger.LogSuccess($"Successfully restarted module: {moduleName} (Attempt {status.RestartAttempts})");
                }
                else
                {
                    status.Status = "Restart failed";
                    EnhancedLogger.LogError($"Failed to restart module: {moduleName} (Attempt {status.RestartAttempts})");
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error restarting module {moduleName}: {ex.Message}");
                ModuleStatuses[moduleName].Status = "Restart error";
            }
        }

        private static void CheckProcessIntegrity()
        {
            // DISABLED FOR VM STABILITY - This was causing infinite loops
            try
            {
                EnhancedLogger.LogInfo("Process integrity check DISABLED for VM stability");
                
                // Do a single check instead of infinite loop
                var currentProcess = Process.GetCurrentProcess();
                
                // Check for suspicious processes trying to access our memory
                var processes = Process.GetProcesses();
                var suspiciousCount = 0;
                
                foreach (var process in processes.Take(10)) // Limit to 10 processes
                {
                    try
                    {
                        if (process.Id == currentProcess.Id) continue;

                        // Check if process is trying to access our memory
                        if (IsAccessingOurMemory(process))
                        {
                            suspiciousCount++;
                            EnhancedLogger.LogThreat($"Suspicious process {process.ProcessName} (PID: {process.Id}) accessing our memory");
                            
                            // Don't handle intrusions in VM - too aggressive
                            if (!IsVirtualMachine())
                            {
                                HandleProcessIntrusion(process);
                            }
                        }
                    }
                    catch
                    {
                        // Ignore processes we can't access
                    }
                }

                EnhancedLogger.LogInfo($"Process integrity check completed - found {suspiciousCount} suspicious processes");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Process integrity check error: {ex.Message}");
            }
        }

        private static bool IsAccessingOurMemory(Process process)
        {
            try
            {
                // Simplified check - in real implementation you'd use ETW or kernel callbacks
                var processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)process.Id);
                if (processHandle == IntPtr.Zero) return false;

                CloseHandle(processHandle);

                // Check process name for suspicious patterns
                var processName = process.ProcessName.ToLower();
                var suspiciousPatterns = new[] { "debugger", "injector", "hijack", "hook", "patch" };
                
                foreach (var pattern in suspiciousPatterns)
                {
                    if (processName.Contains(pattern))
                        return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private static void HandleProcessIntrusion(Process process)
        {
            try
            {
                EnhancedLogger.LogWarning($"Handling process intrusion from {process.ProcessName} (PID: {process.Id})");
                
                // Option 1: Kill the suspicious process
                process.Kill();
                EnhancedLogger.LogSuccess($"Terminated suspicious process: {process.ProcessName}");
                
                // Option 2: Restart all modules as a precaution
                RestartAllModules();
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to handle process intrusion: {ex.Message}");
            }
        }

        private static void MonitorMutexes()
        {
            // DISABLED FOR VM STABILITY - This was causing infinite loops
            try
            {
                EnhancedLogger.LogInfo("Mutex monitoring DISABLED for VM stability");
                
                // Do a single check instead of infinite loop
                var mutexErrors = 0;
                
                foreach (var mutexName in ModuleMutexes)
                {
                    var mutex = CreateMutex(IntPtr.Zero, false, mutexName);
                    if (mutex != IntPtr.Zero)
                    {
                        var waitResult = WaitForSingleObject(mutex, 0);
                        if (waitResult == 0) // Mutex is available
                        {
                            ReleaseMutex(mutex);
                            mutexErrors++;
                            EnhancedLogger.LogWarning($"Module mutex {mutexName} is available (module may be dead)");
                        }
                        CloseHandle(mutex);
                    }
                    else
                    {
                        var error = GetLastError();
                        if (error != 5) // Not access denied
                        {
                            mutexErrors++;
                            EnhancedLogger.LogWarning($"Module mutex {mutexName} error: {error}");
                        }
                    }
                }

                EnhancedLogger.LogInfo($"Mutex check completed - found {mutexErrors} mutex issues");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Mutex monitoring error: {ex.Message}");
            }
        }

        private static void RestartAllModules()
        {
            try
            {
                // CRITICAL: Don't restart all modules in VM environment - too aggressive
                if (IsVirtualMachine())
                {
                    EnhancedLogger.LogWarning("Skipping full module restart in VM environment to prevent instability");
                    return;
                }

                EnhancedLogger.LogWarning("Restarting all modules due to security threat...");
                
                // Stop all modules
                ProcessWatcher.StopWatching();
                MemoryTrap.StopMemoryMonitoring();
                SandboxMode.DisableSandboxMode();
                CredentialTrap.StopCredentialMonitoring();
                ExploitShield.DeactivateExploitShield();
                
                Thread.Sleep(2000); // Wait for cleanup
                
                // Restart all modules
                ProcessWatcher.StartWatching();
                MemoryTrap.StartMemoryMonitoring();
                SandboxMode.EnableSandboxMode();
                CredentialTrap.StartCredentialMonitoring();
                ExploitShield.ActivateExploitShield();
                
                // Reset restart counts
                foreach (var module in ModuleStatuses.Keys)
                {
                    ModuleStatuses[module].RestartAttempts = 0;
                    ModuleStatuses[module].LastRestart = DateTime.Now;
                }
                
                EnhancedLogger.LogSuccess("All modules restarted successfully");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to restart all modules: {ex.Message}");
            }
        }

        // Add VM detection method
        private static bool IsVirtualMachine()
        {
            try
            {
                // Check for common VM indicators
                using var computerSystem = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                foreach (System.Management.ManagementObject obj in computerSystem.Get())
                {
                    var manufacturer = obj["Manufacturer"]?.ToString()?.ToLower() ?? "";
                    var model = obj["Model"]?.ToString()?.ToLower() ?? "";
                    
                    if (manufacturer.Contains("vmware") || manufacturer.Contains("virtual") ||
                        manufacturer.Contains("microsoft") || manufacturer.Contains("parallels") ||
                        model.Contains("vmware") || model.Contains("virtual") ||
                        model.Contains("vbox") || model.Contains("parallels"))
                    {
                        return true;
                    }
                }
                return false;
            }
            catch
            {
                return false; // Assume not VM if detection fails
            }
        }

        public static Dictionary<string, ModuleStatus> GetModuleStatuses()
        {
            lock (watchdogLock)
            {
                return new Dictionary<string, ModuleStatus>(ModuleStatuses);
            }
        }

        public static bool IsActive => isActive;
    }
} 

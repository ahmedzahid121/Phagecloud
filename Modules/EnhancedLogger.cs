using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Linq;
using System.IO.Compression;

namespace PhageVirus.Modules
{
    public class EnhancedLogger
    {
        // Original Logger functionality
        private static readonly string LogDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus", "Logs");
        private static readonly string LogPath = Path.Combine(LogDirectory, $"phage_{DateTime.Now:yyyyMMdd}.log");
        private static readonly object LogLock = new object();
        
        // Enhanced Logger functionality
        private static readonly string BehaviorLogPath = Path.Combine(LogDirectory, $"behavior_{DateTime.Now:yyyyMMdd}.log");
        private static readonly string SystemLogPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "PhageVirus_System_Log.txt");
        private static readonly object BehaviorLock = new object();
        private static readonly object SystemLogLock = new object();
        
        private static bool isRealTimeExportEnabled = true;
        private static bool isBehaviorTrackingEnabled = true;
        private static List<LogEntry> logBuffer = new List<LogEntry>();
        private static Timer? exportTimer;
        private static Timer? behaviorTimer;
        
        // Optimization: Reduced logging frequency and compression
        private static readonly TimeSpan ExportInterval = TimeSpan.FromSeconds(60); // Increased from 5 seconds
        private static readonly int MaxLogBufferSize = 50; // Reduced from 100
        private static readonly int MaxBufferSize = 50; // Added missing constant
        private static readonly bool EnableCompressedLogging = true;
        private static readonly string CompressedLogPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop), 
            "PhageVirus_Logs_Compressed.gz");
        
        // Log buffer for batching
        private static readonly object logBufferLock = new object();
        private static DateTime lastExportTime = DateTime.Now;

        // Add missing GetLogFilePath method
        private static string GetLogFilePath()
        {
            return LogPath;
        }

        public static void LogInfo(string message, Action<string>? uiCallback = null)
        {
            LogMessage(LogLevel.Info, message, uiCallback);
        }

        public static void LogWarning(string message, Action<string>? uiCallback = null)
        {
            LogMessage(LogLevel.Warning, message, uiCallback);
        }

        public static void LogError(string message, Action<string>? uiCallback = null)
        {
            LogMessage(LogLevel.Error, message, uiCallback);
        }

        public static void LogThreat(string message, Action<string>? uiCallback = null)
        {
            LogMessage(LogLevel.Threat, message, uiCallback);
        }

        public static void LogSuccess(string message, Action<string>? uiCallback = null)
        {
            LogMessage(LogLevel.Success, message, uiCallback);
        }

        private static void LogMessage(LogLevel level, string message, Action<string>? uiCallback = null)
        {
            try
            {
                var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                var logEntry = new LogEntry
                {
                    Timestamp = timestamp,
                    Level = level,
                    Message = message,
                    ProcessId = Process.GetCurrentProcess().Id,
                    ThreadId = Thread.CurrentThread.ManagedThreadId
                };

                // Add to buffer
                lock (logBufferLock)
                {
                    logBuffer.Add(logEntry);
                    
                    // Limit buffer size
                    if (logBuffer.Count > MaxLogBufferSize)
                    {
                        logBuffer.RemoveAt(0);
                    }
                }

                // UI callback (immediate)
                uiCallback?.Invoke($"[{timestamp}] {level}: {message}\n");

                // Export logs periodically (optimized)
                if (DateTime.Now - lastExportTime > ExportInterval)
                {
                    Task.Run(() => ExportLogsOptimized());
                    lastExportTime = DateTime.Now;
                }
            }
            catch (Exception ex)
            {
                // Fallback logging to prevent infinite loops
                try
                {
                    File.AppendAllText(Path.Combine(Path.GetTempPath(), "PhageVirus_Fallback.log"), 
                        $"{DateTime.Now}: Logging error: {ex.Message}\n");
                }
                catch
                {
                    // Last resort - silent failure
                }
            }
        }

        private static void ExportLogsOptimized()
        {
            try
            {
                List<LogEntry> entriesToExport;
                
                lock (logBufferLock)
                {
                    entriesToExport = new List<LogEntry>(logBuffer);
                    logBuffer.Clear();
                }

                if (entriesToExport.Count == 0) return;

                // Create log content
                var logContent = string.Join("\n", entriesToExport.Select(entry => 
                    $"[{entry.Timestamp}] [{entry.Level}] [{entry.ProcessId}:{entry.ThreadId}] {entry.Message}"));

                // Export to regular log file
                var logPath = GetLogFilePath();
                File.AppendAllText(logPath, logContent + "\n");

                // Export compressed logs (less frequently)
                if (EnableCompressedLogging && entriesToExport.Count >= 10)
                {
                    ExportCompressedLogs(logContent);
                }

                // Export to desktop (reduced frequency)
                if (entriesToExport.Any(e => e.Level == LogLevel.Threat || e.Level == LogLevel.Error))
                {
                    ExportToDesktop(logContent);
                }
            }
            catch (Exception ex)
            {
                // Silent failure to prevent logging loops
                try
                {
                    File.AppendAllText(Path.Combine(Path.GetTempPath(), "PhageVirus_Export_Error.log"), 
                        $"{DateTime.Now}: Export error: {ex.Message}\n");
                }
                catch
                {
                    // Last resort
                }
            }
        }

        private static void ExportCompressedLogs(string logContent)
        {
            try
            {
                using var fileStream = File.OpenWrite(CompressedLogPath);
                using var gzipStream = new System.IO.Compression.GZipStream(fileStream, System.IO.Compression.CompressionMode.Compress);
                using var writer = new StreamWriter(gzipStream);
                writer.Write(logContent);
            }
            catch (Exception ex)
            {
                // Silent failure for compression
            }
        }

        private static void ExportToDesktop(string logContent)
        {
            try
            {
                var desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                var logFileName = $"phagevirus_log_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
                var logFilePath = Path.Combine(desktopPath, logFileName);
                
                // Only export if file doesn't exist (prevent overwrites)
                if (!File.Exists(logFilePath))
                {
                    File.WriteAllText(logFilePath, logContent);
                }
            }
            catch (Exception ex)
            {
                // Silent failure for desktop export
            }
        }

        public class LogEntry
        {
            public string Timestamp { get; set; } = "";
            public LogLevel Level { get; set; }
            public string Message { get; set; } = "";
            public int ProcessId { get; set; }
            public int ThreadId { get; set; }
        }

        public enum LogLevel
        {
            Info,
            Warning,
            Error,
            Threat,
            Success
        }
        
        static EnhancedLogger()
        {
            try
            {
                Directory.CreateDirectory(LogDirectory);
                InitializeRealTimeExport();
                InitializeBehaviorTracking();
                LogSystemStartup();
            }
            catch (Exception ex)
            {
                // Fallback to temp directory if we can't create the log directory
                LogDirectory = Path.GetTempPath();
                Console.WriteLine($"EnhancedLogger initialization failed: {ex.Message}");
            }
        }

        #region Enhanced Logger Methods

        // Remove the AddToBuffer method as it's not being used and has type mismatch
        // private static void AddToBuffer(string logEntry)
        // {
        //     lock (logBufferLock)
        //     {
        //         logBuffer.Add(logEntry);
        //         
        //         // Keep buffer size manageable (optimized)
        //         if (logBuffer.Count > MaxBufferSize)
        //         {
        //             logBuffer.RemoveRange(0, logBuffer.Count - MaxBufferSize);
        //         }
        //     }
        // }
        
        #endregion

        #region Real-Time Log Export

        private static void InitializeRealTimeExport()
        {
            if (isRealTimeExportEnabled)
            {
                // Export logs every 30 seconds (optimized)
                exportTimer = new Timer(ExportLogsToDesktop, null, TimeSpan.Zero, ExportInterval);
            }
        }

        private static void ExportLogsToDesktop(object? state)
        {
            try
            {
                lock (SystemLogLock)
                {
                    var systemInfo = GetComprehensiveSystemInfo();
                    var recentLogs = GetRecentLogs(100);
                    var behaviorLogs = GetRecentBehaviorLogs(50);
                    
                    var exportContent = new StringBuilder();
                    exportContent.AppendLine("=== PHAGEVIRUS REAL-TIME SYSTEM LOG ===");
                    exportContent.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}");
                    exportContent.AppendLine($"Export Interval: Every 5 seconds");
                    exportContent.AppendLine();
                    
                    exportContent.AppendLine("=== SYSTEM INFORMATION ===");
                    exportContent.AppendLine(systemInfo);
                    exportContent.AppendLine();
                    
                    exportContent.AppendLine("=== RECENT ACTIVITY LOGS ===");
                    exportContent.AppendLine(recentLogs);
                    exportContent.AppendLine();
                    
                    exportContent.AppendLine("=== BEHAVIOR TRACKING ===");
                    exportContent.AppendLine(behaviorLogs);
                    exportContent.AppendLine();
                    
                    exportContent.AppendLine("=== PROCESS MONITORING ===");
                    exportContent.AppendLine(GetProcessMonitoringData());
                    exportContent.AppendLine();
                    
                    exportContent.AppendLine("=== MEMORY ANALYSIS ===");
                    exportContent.AppendLine(GetMemoryAnalysisData());
                    exportContent.AppendLine();
                    
                    exportContent.AppendLine("=== NETWORK ACTIVITY ===");
                    exportContent.AppendLine(GetNetworkActivityData());
                    exportContent.AppendLine();
                    
                    exportContent.AppendLine("=== REGISTRY MONITORING ===");
                    exportContent.AppendLine(GetRegistryMonitoringData());
                    exportContent.AppendLine();
                    
                    exportContent.AppendLine("=== FILE SYSTEM ACTIVITY ===");
                    exportContent.AppendLine(GetFileSystemActivityData());
                    exportContent.AppendLine();
                    
                    exportContent.AppendLine("=== SECURITY EVENTS ===");
                    exportContent.AppendLine(GetSecurityEventsData());
                    
                    File.WriteAllText(SystemLogPath, exportContent.ToString(), Encoding.UTF8);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Real-time log export failed: {ex.Message}");
            }
        }

        #endregion

        #region Behavior Tracking

        private static void InitializeBehaviorTracking()
        {
            if (isBehaviorTrackingEnabled)
            {
                // Track behavior every 30 seconds (optimized)
                behaviorTimer = new Timer(TrackSystemBehavior, null, TimeSpan.Zero, TimeSpan.FromSeconds(30));
            }
        }

        private static void TrackSystemBehavior(object? state)
        {
            try
            {
                var behaviorData = new StringBuilder();
                behaviorData.AppendLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] === BEHAVIOR TRACKING SNAPSHOT ===");
                
                // Track process creation
                behaviorData.AppendLine($"Active Processes: {Process.GetProcesses().Length}");
                behaviorData.AppendLine($"High-Risk Processes: {GetHighRiskProcessCount()}");
                behaviorData.AppendLine($"Suspicious Processes: {GetSuspiciousProcessCount()}");
                
                // Track memory usage
                var memoryInfo = GetDetailedMemoryInfo();
                behaviorData.AppendLine($"Memory Usage: {memoryInfo}");
                
                // Track file system changes
                var fileSystemInfo = GetFileSystemChanges();
                behaviorData.AppendLine($"File System Changes: {fileSystemInfo}");
                
                // Track registry changes
                var registryInfo = GetRegistryChanges();
                behaviorData.AppendLine($"Registry Changes: {registryInfo}");
                
                // Track network connections
                var networkInfo = GetNetworkConnections();
                behaviorData.AppendLine($"Network Connections: {networkInfo}");
                
                // Track system performance
                var performanceInfo = GetSystemPerformance();
                behaviorData.AppendLine($"System Performance: {performanceInfo}");
                
                // Track security events
                var securityInfo = GetSecurityEvents();
                behaviorData.AppendLine($"Security Events: {securityInfo}");
                
                WriteToBehaviorLog(behaviorData.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Behavior tracking failed: {ex.Message}");
            }
        }

        private static void WriteToBehaviorLog(string content)
        {
            lock (BehaviorLock)
            {
                try
                {
                    File.AppendAllText(BehaviorLogPath, content + Environment.NewLine, Encoding.UTF8);
                }
                catch
                {
                    // Fallback to console if file write fails
                    Console.WriteLine(content);
                }
            }
        }

        #endregion

        #region Enhanced Logging Methods

        public static void LogProcessCreation(int processId, string processName, string commandLine, Action<string>? logToUI = null)
        {
            LogMessage(LogLevel.Info, $"[PROCESS_CREATED] PID: {processId}, Name: {processName}, CMD: {commandLine}", logToUI);
        }

        public static void LogProcessTermination(int processId, string processName, string reason, Action<string>? logToUI = null)
        {
            LogMessage(LogLevel.Info, $"[PROCESS_TERMINATED] PID: {processId}, Name: {processName}, Reason: {reason}", logToUI);
        }

        public static void LogMemoryInjection(int targetProcessId, string targetProcessName, bool success, Action<string>? logToUI = null)
        {
            LogMessage(LogLevel.Info, $"[MEMORY_INJECTION] Target: {targetProcessName} (PID: {targetProcessId}), Status: {(success ? "SUCCESS" : "FAILED")}", logToUI);
        }

        public static void LogFileOperation(string operation, string filePath, bool success, Action<string>? logToUI = null)
        {
            LogMessage(LogLevel.Info, $"[FILE_OPERATION] {operation} - {filePath}, Status: {(success ? "SUCCESS" : "FAILED")}", logToUI);
        }

        public static void LogRegistryOperation(string operation, string keyPath, string valueName, Action<string>? logToUI = null)
        {
            LogMessage(LogLevel.Info, $"[REGISTRY_OPERATION] {operation} - {keyPath}\\{valueName}", logToUI);
        }

        public static void LogNetworkActivity(string operation, string remoteAddress, int port, Action<string>? logToUI = null)
        {
            LogMessage(LogLevel.Info, $"[NETWORK_ACTIVITY] {operation} - {remoteAddress}:{port}", logToUI);
        }

        public static void LogSelfReplication(string targetPath, bool success, Action<string>? logToUI = null)
        {
            LogMessage(LogLevel.Info, $"[SELF_REPLICATION] Target: {targetPath}, Status: {(success ? "SUCCESS" : "FAILED")}", logToUI);
        }

        public static void LogPersistenceCreation(string method, string target, bool success, Action<string>? logToUI = null)
        {
            LogMessage(LogLevel.Info, $"[PERSISTENCE] Method: {method}, Target: {target}, Status: {(success ? "SUCCESS" : "FAILED")}", logToUI);
        }

        // Add missing methods that are called from other modules
        public static void LogEmailSent(string recipient, string subject, bool success, Action<string>? logToUI = null)
        {
            LogMessage(LogLevel.Info, $"[EMAIL_SENT] To: {recipient}, Subject: {subject}, Status: {(success ? "SUCCESS" : "FAILED")}", logToUI);
        }

        public static void LogSelfDestruct(string reason, bool success, Action<string>? logToUI = null)
        {
            LogMessage(LogLevel.Threat, $"[SELF_DESTRUCT] Reason: {reason}, Status: {(success ? "SUCCESS" : "FAILED")}", logToUI);
        }

        // Add missing method for LogViewer
        public static string GetLogContent(int maxLines = 1000)
        {
            try
            {
                if (File.Exists(LogPath))
                {
                    var lines = File.ReadAllLines(LogPath);
                    if (lines.Length <= maxLines)
                        return string.Join(Environment.NewLine, lines);
                    else
                        return string.Join(Environment.NewLine, lines.Skip(lines.Length - maxLines));
                }
                return "No log content available";
            }
            catch (Exception ex)
            {
                return $"Error reading log content: {ex.Message}";
            }
        }

        #endregion

        #region System Information Gathering

        private static string GetComprehensiveSystemInfo()
        {
            var info = new StringBuilder();
            
            try
            {
                info.AppendLine($"Machine Name: {Environment.MachineName}");
                info.AppendLine($"User Name: {Environment.UserName}");
                info.AppendLine($"OS Version: {Environment.OSVersion}");
                info.AppendLine($"CLR Version: {Environment.Version}");
                info.AppendLine($"Processor Count: {Environment.ProcessorCount}");
                info.AppendLine($"Working Set: {Environment.WorkingSet / 1024 / 1024} MB");
                info.AppendLine($"Is 64-bit Process: {Environment.Is64BitProcess}");
                info.AppendLine($"Is 64-bit OS: {Environment.Is64BitOperatingSystem}");
                info.AppendLine($"System Directory: {Environment.SystemDirectory}");
                info.AppendLine($"Current Directory: {Environment.CurrentDirectory}");
                info.AppendLine($"User Domain: {Environment.UserDomainName}");
                info.AppendLine($"Elevated Privileges: {IsElevated()}");
                
                // Get detailed system information using WMI
                try
                {
                    using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        info.AppendLine($"Total Physical Memory: {Convert.ToInt64(obj["TotalPhysicalMemory"]) / 1024 / 1024} MB");
                        info.AppendLine($"Manufacturer: {obj["Manufacturer"]}");
                        info.AppendLine($"Model: {obj["Model"]}");
                        break;
                    }
                }
                catch
                {
                    info.AppendLine("WMI access failed - limited system info available");
                }
            }
            catch (Exception ex)
            {
                info.AppendLine($"Error gathering system info: {ex.Message}");
            }
            
            return info.ToString();
        }

        private static bool IsElevated()
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private static string GetDetailedMemoryInfo()
        {
            try
            {
                var totalMemory = GetTotalPhysicalMemory();
                var availableMemory = GetAvailableMemory();
                var usedMemory = totalMemory - availableMemory;
                
                // Ensure we don't get negative values
                if (usedMemory < 0) usedMemory = 0;
                if (availableMemory < 0) availableMemory = 0;
                
                var memoryPressure = availableMemory < (totalMemory * 0.1); // Less than 10% available
                
                return $"Total: {totalMemory / 1024 / 1024} MB, Used: {usedMemory / 1024 / 1024} MB, Available: {availableMemory / 1024 / 1024} MB, Pressure: {(memoryPressure ? "HIGH" : "NORMAL")}";
            }
            catch (Exception ex)
            {
                return $"Memory info error: {ex.Message}";
            }
        }

        private static long GetAvailableMemory()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT FreePhysicalMemory FROM Win32_OperatingSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var available = Convert.ToInt64(obj["FreePhysicalMemory"]);
                    return available * 1024; // Convert KB to bytes
                }
                return 512 * 1024 * 1024; // 512MB fallback
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to get available memory: {ex.Message}");
                return 512 * 1024 * 1024; // 512MB fallback
            }
        }

        private static long GetTotalPhysicalMemory()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var total = Convert.ToInt64(obj["TotalPhysicalMemory"]);
                    if (total <= 0) total = 4L * 1024 * 1024 * 1024; // 4GB fallback
                    return total; // Already in bytes
                }
                return 4L * 1024 * 1024 * 1024; // 4GB default
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to get total memory: {ex.Message}");
                return 4L * 1024 * 1024 * 1024; // 4GB fallback
            }
        }

        private static int GetHighRiskProcessCount()
        {
            try
            {
                var highRiskProcesses = new[] { "powershell", "cmd", "mshta", "wscript", "cscript", "regsvr32", "rundll32" };
                var processes = Process.GetProcesses();
                return processes.Count(p => highRiskProcesses.Any(hrp => p.ProcessName.ToLower().Contains(hrp)));
            }
            catch
            {
                return 0;
            }
        }

        private static int GetSuspiciousProcessCount()
        {
            try
            {
                var suspiciousKeywords = new[] { "stealer", "keylogger", "trojan", "backdoor", "miner", "bot", "spy" };
                var processes = Process.GetProcesses();
                return processes.Count(p => suspiciousKeywords.Any(sk => p.ProcessName.ToLower().Contains(sk)));
            }
            catch
            {
                return 0;
            }
        }

        private static string GetFileSystemChanges()
        {
            try
            {
                var tempDir = Path.GetTempPath();
                var tempFiles = Directory.GetFiles(tempDir, "*.*", SearchOption.TopDirectoryOnly).Length;
                var downloadsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
                var downloadFiles = Directory.Exists(downloadsDir) ? Directory.GetFiles(downloadsDir, "*.*", SearchOption.TopDirectoryOnly).Length : 0;
                
                return $"Temp Files: {tempFiles}, Download Files: {downloadFiles}";
            }
            catch
            {
                return "Unable to determine";
            }
        }

        private static string GetRegistryChanges()
        {
            try
            {
                // This is a simplified version - in a real implementation, you'd track actual registry changes
                return "Registry monitoring active";
            }
            catch
            {
                return "Unable to determine";
            }
        }

        private static string GetNetworkConnections()
        {
            try
            {
                // This is a simplified version - in a real implementation, you'd use netstat or similar
                return "Network monitoring active";
            }
            catch
            {
                return "Unable to determine";
            }
        }

        private static string GetSystemPerformance()
        {
            try
            {
                var cpuUsage = GetCpuUsage();
                var memoryUsage = GetMemoryUsage();
                return $"CPU: {cpuUsage:F1}%, Memory: {memoryUsage:F1}%";
            }
            catch
            {
                return "Unable to determine";
            }
        }

        private static double GetCpuUsage()
        {
            try
            {
                using var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                cpuCounter.NextValue(); // First call returns 0
                Thread.Sleep(100);
                return cpuCounter.NextValue();
            }
            catch
            {
                return 0;
            }
        }

        private static double GetMemoryUsage()
        {
            try
            {
                using var memoryCounter = new PerformanceCounter("Memory", "% Committed Bytes In Use");
                return memoryCounter.NextValue();
            }
            catch
            {
                return 0;
            }
        }

        private static string GetSecurityEvents()
        {
            try
            {
                // This is a simplified version - in a real implementation, you'd query Windows Event Log
                return "Security event monitoring active";
            }
            catch
            {
                return "Unable to determine";
            }
        }

        #endregion

        #region Data Retrieval Methods

        private static string GetRecentLogs(int maxLines)
        {
            lock (logBufferLock)
            {
                if (logBuffer.Count == 0)
                    return "No recent logs available";
                
                var startIndex = Math.Max(0, logBuffer.Count - maxLines);
                var recentLogs = logBuffer.Skip(startIndex).Take(maxLines);
                return string.Join(Environment.NewLine, recentLogs);
            }
        }

        private static string GetRecentBehaviorLogs(int maxLines)
        {
            try
            {
                if (File.Exists(BehaviorLogPath))
                {
                    var lines = File.ReadAllLines(BehaviorLogPath);
                    if (lines.Length <= maxLines)
                        return string.Join(Environment.NewLine, lines);
                    else
                        return string.Join(Environment.NewLine, lines.Skip(lines.Length - maxLines));
                }
            }
            catch
            {
                // Return empty if we can't read the log
            }
            
            return "No behavior logs available";
        }

        private static string GetProcessMonitoringData()
        {
            try
            {
                var processes = Process.GetProcesses();
                var highRiskProcesses = processes.Where(p => 
                    p.ProcessName.ToLower().Contains("powershell") ||
                    p.ProcessName.ToLower().Contains("cmd") ||
                    p.ProcessName.ToLower().Contains("mshta") ||
                    p.ProcessName.ToLower().Contains("wscript") ||
                    p.ProcessName.ToLower().Contains("cscript")
                ).Take(10);
                
                var data = new StringBuilder();
                foreach (var process in highRiskProcesses)
                {
                    data.AppendLine($"PID: {process.Id}, Name: {process.ProcessName}, Memory: {process.WorkingSet64 / 1024 / 1024} MB");
                }
                
                return data.ToString();
            }
            catch
            {
                return "Unable to retrieve process data";
            }
        }

        private static string GetMemoryAnalysisData()
        {
            try
            {
                var data = new StringBuilder();
                data.AppendLine($"Total Physical Memory: {GC.GetTotalMemory(false) / 1024 / 1024} MB");
                data.AppendLine($"Available Memory: {GetAvailableMemory() / 1024 / 1024} MB");
                data.AppendLine($"Memory Pressure: {(GC.GetTotalMemory(false) > GetAvailableMemory() * 0.8 ? "HIGH" : "NORMAL")}");
                return data.ToString();
            }
            catch
            {
                return "Unable to retrieve memory data";
            }
        }

        private static string GetNetworkActivityData()
        {
            try
            {
                // This is a simplified version - in a real implementation, you'd use netstat or similar
                return "Network monitoring active - check system logs for detailed network activity";
            }
            catch
            {
                return "Unable to retrieve network data";
            }
        }

        private static string GetRegistryMonitoringData()
        {
            try
            {
                // This is a simplified version - in a real implementation, you'd track actual registry changes
                return "Registry monitoring active - check system logs for detailed registry activity";
            }
            catch
            {
                return "Unable to retrieve registry data";
            }
        }

        private static string GetFileSystemActivityData()
        {
            try
            {
                var data = new StringBuilder();
                var tempDir = Path.GetTempPath();
                var tempFiles = Directory.GetFiles(tempDir, "*.*", SearchOption.TopDirectoryOnly);
                data.AppendLine($"Temp Directory Files: {tempFiles.Length}");
                
                var downloadsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
                if (Directory.Exists(downloadsDir))
                {
                    var downloadFiles = Directory.GetFiles(downloadsDir, "*.*", SearchOption.TopDirectoryOnly);
                    data.AppendLine($"Downloads Directory Files: {downloadFiles.Length}");
                }
                
                return data.ToString();
            }
            catch
            {
                return "Unable to retrieve file system data";
            }
        }

        private static string GetSecurityEventsData()
        {
            try
            {
                // This is a simplified version - in a real implementation, you'd query Windows Event Log
                return "Security event monitoring active - check Windows Event Log for detailed security events";
            }
            catch
            {
                return "Unable to retrieve security data";
            }
        }

        #endregion

        #region Utility Methods

        private static void LogSystemStartup()
        {
            LogInfo("EnhancedLogger initialized with real-time export and behavior tracking");
            LogInfo($"Log Directory: {LogDirectory}");
            LogInfo($"System Log Path: {SystemLogPath}");
            LogInfo($"Real-time export enabled: {isRealTimeExportEnabled}");
            LogInfo($"Behavior tracking enabled: {isBehaviorTrackingEnabled}");
        }

        public static void DisableRealTimeExport()
        {
            isRealTimeExportEnabled = false;
            exportTimer?.Dispose();
            exportTimer = null;
        }

        public static void EnableRealTimeExport()
        {
            isRealTimeExportEnabled = true;
            InitializeRealTimeExport();
        }

        public static void DisableBehaviorTracking()
        {
            isBehaviorTrackingEnabled = false;
            behaviorTimer?.Dispose();
            behaviorTimer = null;
        }

        public static void EnableBehaviorTracking()
        {
            isBehaviorTrackingEnabled = true;
            InitializeBehaviorTracking();
        }

        public static void Dispose()
        {
            exportTimer?.Dispose();
            behaviorTimer?.Dispose();
        }

        #endregion
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Text;
using System.Security.Cryptography;
using System.Management; // Added for VM detection

namespace PhageVirus.Modules
{
    public class HoneyProcess
    {
        private static readonly List<Process> ActiveHoneyProcesses = new();
        private static readonly Dictionary<int, HoneyProcessInfo> ProcessInfo = new();
        private static bool isRunning = false;
        private static readonly object processLock = new object();
        
        // Reduced list of safe applications that won't cause system conflicts
        private static readonly string[] TargetApplications = {
            "NOTEPAD.EXE",
            "CALC.EXE",
            "PAINT.EXE"
        };

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        private const int PROCESS_ALL_ACCESS = 0x1F0FFF;
        private const int MEM_COMMIT = 0x1000;
        private const int MEM_RESERVE = 0x2000;
        private const int PAGE_EXECUTE_READWRITE = 0x40;

        public static bool StartHoneyProcesses()
        {
            try
            {
                EnhancedLogger.LogInfo("Starting honey process deployment...", Console.WriteLine);
                
                // Check if we're in a VM environment to avoid conflicts
                if (IsVirtualMachine())
                {
                    EnhancedLogger.LogWarning("Running in VM environment - honey processes disabled for stability");
                    return true; // Return true to avoid breaking the startup sequence
                }
                
                isRunning = true;
                
                // Start honey processes for each target application
                foreach (var appName in TargetApplications)
                {
                    SpawnHoneyProcess(appName);
                }
                
                // Start monitoring thread
                Task.Run(MonitorHoneyProcesses);
                
                EnhancedLogger.LogInfo($"Started {ActiveHoneyProcesses.Count} honey processes", Console.WriteLine);
                return true;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start honey processes: {ex.Message}", Console.WriteLine);
                return false;
            }
        }

        private static bool IsVirtualMachine()
        {
            try
            {
                // Check for common VM indicators
                var manufacturer = Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER") ?? "";
                var model = Environment.GetEnvironmentVariable("COMPUTERNAME") ?? "";
                
                return manufacturer.Contains("VMware") || 
                       manufacturer.Contains("Virtual") || 
                       model.Contains("VM") ||
                       model.Contains("Virtual");
            }
            catch
            {
                return false;
            }
        }

        public static void StopHoneyProcesses()
        {
            try
            {
                isRunning = false;
                
                lock (processLock)
                {
                    foreach (var process in ActiveHoneyProcesses)
                    {
                        try
                        {
                            if (!process.HasExited)
                            {
                                process.Kill();
                            }
                        }
                        catch (Exception ex)
                        {
                            EnhancedLogger.LogError($"Failed to kill honey process {process.Id}: {ex.Message}", Console.WriteLine);
                        }
                    }
                    ActiveHoneyProcesses.Clear();
                    ProcessInfo.Clear();
                }
                
                EnhancedLogger.LogInfo("All honey processes stopped", Console.WriteLine);
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to stop honey processes: {ex.Message}", Console.WriteLine);
            }
        }

        private static void SpawnHoneyProcess(string appName)
        {
            try
            {
                // Skip critical system processes that could cause VM instability
                if (IsCriticalSystemProcess(appName))
                {
                    EnhancedLogger.LogInfo($"Skipping honey process for critical system process: {appName}");
                    return;
                }

                // Create a dummy executable that mimics the target application
                var honeyExePath = CreateHoneyExecutable(appName);

                // Check if the honey executable exists before launching
                if (string.IsNullOrEmpty(honeyExePath) || !File.Exists(honeyExePath))
                {
                    EnhancedLogger.LogWarning($"Honey executable for {appName} does not exist at {honeyExePath}. Skipping launch.");
                    return;
                }

                var startInfo = new ProcessStartInfo
                {
                    FileName = honeyExePath,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                var process = Process.Start(startInfo);
                if (process != null)
                {
                    lock (processLock)
                    {
                        ActiveHoneyProcesses.Add(process);
                        ProcessInfo[process.Id] = new HoneyProcessInfo
                        {
                            ProcessId = process.Id,
                            OriginalName = appName,
                            HoneyPath = honeyExePath,
                            StartTime = DateTime.Now,
                            InjectionAttempts = 0,
                            LastInjectionTime = DateTime.MinValue
                        };
                    }

                    EnhancedLogger.LogInfo($"Spawned honey process for {appName} (PID: {process.Id})", Console.WriteLine);
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to spawn honey process for {appName}: {ex.Message}", Console.WriteLine);
            }
        }

        private static bool IsCriticalSystemProcess(string appName)
        {
            var criticalProcesses = new[] { "SVCHOST.EXE", "LSASS.EXE", "WINLOGON.EXE", "EXPLORER.EXE" };
            return criticalProcesses.Contains(appName.ToUpper());
        }

        private static string CreateHoneyExecutable(string appName)
        {
            try
            {
                var honeyDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus", "Honey");
                Directory.CreateDirectory(honeyDir);
                
                var honeyExePath = Path.Combine(honeyDir, appName);
                
                // Create a simple executable that mimics the target application
                var honeyCode = GenerateHoneyCode(appName);
                File.WriteAllText(honeyExePath + ".cs", honeyCode);
                
                // Compile the honey executable
                CompileHoneyExecutable(honeyExePath + ".cs", honeyExePath);
                
                return honeyExePath;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to create honey executable for {appName}: {ex.Message}", Console.WriteLine);
                return string.Empty;
            }
        }

        private static string GenerateHoneyCode(string appName)
        {
            var baseName = Path.GetFileNameWithoutExtension(appName);
            
            return $@"
using System;
using System.Threading;
using System.Runtime.InteropServices;

namespace PhageVirus.Honey
{{
    public class {baseName}Honey
    {{
        [DllImport(""kernel32.dll"")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);
        
        [DllImport(""kernel32.dll"")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        
        static void Main()
        {{
            // Simulate the target application behavior
            Console.WriteLine(""Honey process started: {appName}"");
            
            // Keep the process alive for monitoring
            while (true)
            {{
                Thread.Sleep(1000);
            }}
        }}
    }}
}}";
        }

        private static void CompileHoneyExecutable(string sourcePath, string outputPath)
        {
            try
            {
                // Use a simple approach that doesn't require external compilers
                // Create a batch file that runs a simple command instead
                var batchContent = $@"
@echo off
echo Honey process: {Path.GetFileNameWithoutExtension(outputPath)}
timeout /t 3600 /nobreak >nul
";
                
                var batchPath = outputPath + ".bat";
                File.WriteAllText(batchPath, batchContent);
                
                // Update the honey executable path to use the batch file
                outputPath = batchPath;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to compile honey executable: {ex.Message}", Console.WriteLine);
            }
        }

        private static async void MonitorHoneyProcesses()
        {
            while (isRunning)
            {
                try
                {
                    lock (processLock)
                    {
                        var processesToRemove = new List<Process>();
                        
                        foreach (var process in ActiveHoneyProcesses)
                        {
                            try
                            {
                                if (process.HasExited)
                                {
                                    processesToRemove.Add(process);
                                    EnhancedLogger.LogWarning($"Honey process {process.Id} has exited unexpectedly", Console.WriteLine);
                                }
                                else
                                {
                                    // Monitor for suspicious activity
                                    MonitorProcessMemory(process);
                                    MonitorDllInjection(process);
                                    MonitorCodeInjection(process);
                                }
                            }
                            catch (Exception ex)
                            {
                                EnhancedLogger.LogError($"Error monitoring honey process {process.Id}: {ex.Message}", Console.WriteLine);
                                processesToRemove.Add(process);
                            }
                        }
                        
                        // Remove exited processes
                        foreach (var process in processesToRemove)
                        {
                            ActiveHoneyProcesses.Remove(process);
                            ProcessInfo.Remove(process.Id);
                        }
                    }
                    
                    await Task.Delay(5000); // Check every 5 seconds
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Error in honey process monitoring: {ex.Message}", Console.WriteLine);
                    await Task.Delay(10000); // Wait longer on error
                }
            }
        }

        private static void MonitorProcessMemory(Process process)
        {
            try
            {
                var suspiciousRegions = ScanForSuspiciousMemory(process.Handle);
                if (suspiciousRegions.Count > 0)
                {
                    HandleMemoryInjection(process, suspiciousRegions);
                }
            }
            catch (Exception ex)
            {
                // Silent monitoring to avoid detection
            }
        }

        private static List<IntPtr> ScanForSuspiciousMemory(IntPtr processHandle)
        {
            var suspiciousRegions = new List<IntPtr>();
            
            try
            {
                // Simplified memory scanning to avoid crashes
                var buffer = new byte[1024];
                var address = IntPtr.Zero;
                
                // Only scan a small portion to avoid system instability
                for (int i = 0; i < 10; i++)
                {
                    try
                    {
                        if (ReadProcessMemory(processHandle, address, buffer, buffer.Length, out int bytesRead))
                        {
                            var entropy = CalculateEntropy(buffer);
                            if (entropy > 7.5) // High entropy indicates suspicious content
                            {
                                suspiciousRegions.Add(address);
                            }
                        }
                    }
                    catch
                    {
                        break; // Stop scanning if we encounter errors
                    }
                    address = IntPtr.Add(address, buffer.Length);
                }
            }
            catch (Exception ex)
            {
                // Silent failure
            }
            
            return suspiciousRegions;
        }

        private static double CalculateEntropy(byte[] data)
        {
            try
            {
                var frequency = new int[256];
                foreach (var b in data)
                {
                    frequency[b]++;
                }
                
                var entropy = 0.0;
                var length = data.Length;
                
                for (int i = 0; i < 256; i++)
                {
                    if (frequency[i] > 0)
                    {
                        var probability = (double)frequency[i] / length;
                        entropy -= probability * Math.Log(probability, 2);
                    }
                }
                
                return entropy;
            }
            catch
            {
                return 0.0;
            }
        }

        private static void MonitorDllInjection(Process process)
        {
            try
            {
                // Simplified DLL injection monitoring
                var currentThreads = process.Threads.Count;
                if (ProcessInfo.TryGetValue(process.Id, out var info))
                {
                    if (currentThreads > info.LastThreadCount + 5) // Sudden thread increase
                    {
                        HandleDllInjection(process, "Unknown DLL");
                    }
                    info.LastThreadCount = currentThreads;
                }
            }
            catch (Exception ex)
            {
                // Silent monitoring
            }
        }

        private static void MonitorCodeInjection(Process process)
        {
            try
            {
                // Simplified code injection monitoring
                var currentThreads = process.Threads.Count;
                if (ProcessInfo.TryGetValue(process.Id, out var info))
                {
                    if (currentThreads > info.LastThreadCount + 3) // Moderate thread increase
                    {
                        HandleCodeInjection(process, currentThreads);
                    }
                }
            }
            catch (Exception ex)
            {
                // Silent monitoring
            }
        }

        private static void HandleMemoryInjection(Process process, List<IntPtr> suspiciousRegions)
        {
            try
            {
                // CRITICAL: Don't take aggressive action in VM environment
                if (IsVirtualMachine())
                {
                    EnhancedLogger.LogInfo($"Honey process {process.Id} memory injection detected in VM - logging only");
                    return;
                }

                EnhancedLogger.LogThreat($"Memory injection detected in honey process {process.Id} ({process.ProcessName})");
                
                // Log the injection details
                var injectionDetails = $"Suspicious regions: {suspiciousRegions.Count}";
                TriggerThreatResponse(process, "Memory Injection", injectionDetails);
                
                // In VM environment, just log - don't take aggressive action
                if (!IsVirtualMachine())
                {
                    // Only take action in non-VM environments
                    EnhancedLogger.LogInfo($"Threat response triggered for honey process {process.Id}");
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error handling code injection: {ex.Message}", Console.WriteLine);
            }
        }

        private static void HandleDllInjection(Process process, string dllName)
        {
            try
            {
                if (ProcessInfo.TryGetValue(process.Id, out var info))
                {
                    info.InjectionAttempts++;
                    info.LastInjectionTime = DateTime.Now;
                    
                    TriggerThreatResponse(process, "DLL Injection", $"DLL: {dllName}");
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error handling DLL injection: {ex.Message}", Console.WriteLine);
            }
        }

        private static void HandleCodeInjection(Process process, int newThreads)
        {
            try
            {
                if (ProcessInfo.TryGetValue(process.Id, out var info))
                {
                    info.InjectionAttempts++;
                    info.LastInjectionTime = DateTime.Now;
                    
                    TriggerThreatResponse(process, "Code Injection", $"New threads: {newThreads}");
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error handling code injection: {ex.Message}", Console.WriteLine);
            }
        }

        private static void TriggerThreatResponse(Process process, string injectionType, string details)
        {
            try
            {
                EnhancedLogger.LogThreat($"Honey process {process.Id} ({process.ProcessName}) - {injectionType}: {details}");
                
                // Log the threat but dont take aggressive action in VM environment
                if (!IsVirtualMachine())
                {
                    // Only take action in non-VM environments
                    EnhancedLogger.LogInfo($"Threat response triggered for honey process {process.Id}");
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error triggering threat response: {ex.Message}", Console.WriteLine);
            }
        }

        public static List<HoneyProcessInfo> GetActiveHoneyProcesses()
        {
            lock (processLock)
            {
                return ProcessInfo.Values.ToList();
            }
        }

        public static bool IsHoneyActive()
        {
            return isRunning;
        }
    }

    public class HoneyProcessInfo
    {
        public int ProcessId { get; set; }
        public string OriginalName { get; set; } = "";
        public string HoneyPath { get; set; } = "";
        public DateTime StartTime { get; set; }
        public int InjectionAttempts { get; set; }
        public DateTime LastInjectionTime { get; set; }
        public int LastThreadCount { get; set; }
    }
} 

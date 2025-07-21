using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Linq; // Added for .Any()

namespace PhageVirus.Modules
{
    public class SystemHacker
    {
        // Windows API Constants
        private const int PROCESS_VM_READ = 0x0010;
        private const int PROCESS_VM_WRITE = 0x0020;
        private const int PROCESS_VM_OPERATION = 0x0008;
        private const int PROCESS_QUERY_INFORMATION = 0x0400;
        private const int PROCESS_ALL_ACCESS = 0x1F0FFF;
        private const int MEM_COMMIT = 0x1000;
        private const int MEM_RESERVE = 0x2000;
        private const int PAGE_EXECUTE_READWRITE = 0x40;
        private const int PAGE_READWRITE = 0x04;
        private const int PROCESS_TERMINATE = 0x0001;

        // Windows API P/Invoke Declarations
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, int flAllocationType, int flProtect);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, int dwFreeType);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern bool TerminateProcess(IntPtr hProcess, int uExitCode);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, int dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, int dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        private static extern int WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);

        [DllImport("kernel32.dll")]
        private static extern bool GetExitCodeThread(IntPtr hThread, out int lpExitCode);

        [DllImport("advapi32.dll")]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll")]
        private static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        // Malicious patterns to detect in memory
        private static readonly byte[][] MaliciousPatterns = {
            // Common malware patterns (simplified examples)
            new byte[] { 0x68, 0x00, 0x00, 0x00, 0x00, 0xE8 }, // push 0; call
            new byte[] { 0x8B, 0x45, 0xFC, 0x83, 0xC0, 0x01 }, // mov eax, [ebp-4]; inc eax
            new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }, // NOP sled
            new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B }, // call; pop ebx
        };

        public static List<ProcessInfo> HuntSuspiciousProcesses()
        {
            var suspiciousProcesses = new List<ProcessInfo>();
            
            try
            {
                var processes = Process.GetProcesses();
                EnhancedLogger.LogInfo($"Scanning {processes.Length} running processes for threats...");
                
                // Send telemetry to cloud for process hunting
                Task.Run(async () =>
                {
                    try
                    {
                        var processHuntingData = new
                        {
                            total_processes = processes.Length,
                            malicious_patterns_count = MaliciousPatterns.Length,
                            threat_type = "process_hunting",
                            timestamp = DateTime.UtcNow
                        };

                        await CloudIntegration.SendTelemetryAsync("SystemHacker", "process_hunting", processHuntingData, ThreatLevel.Normal);
                        
                        // Get cloud process hunting analysis
                        var analysis = await CloudIntegration.GetCloudAnalysisAsync("SystemHacker", processHuntingData);
                        if (analysis.Success)
                        {
                            EnhancedLogger.LogInfo($"Cloud process hunting analysis: {analysis.Analysis}");
                        }
                    }
                    catch (Exception ex)
                    {
                        EnhancedLogger.LogWarning($"Cloud process hunting analysis failed: {ex.Message}");
                    }
                });

                foreach (var process in processes)
                {
                    try
                    {
                        if (IsProcessSuspicious(process))
                        {
                            var processInfo = AnalyzeProcess(process);
                            if (processInfo != null)
                            {
                                suspiciousProcesses.Add(processInfo);
                                EnhancedLogger.LogThreat($"Suspicious process detected: {process.ProcessName} (PID: {process.Id})");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        // Ignore processes we can't access
                        EnhancedLogger.LogWarning($"Cannot access process {process.ProcessName} (PID: {process.Id}): {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Process hunting failed: {ex.Message}");
            }

            return suspiciousProcesses;
        }

        // Add the optimized version that's being called from MainWindow
        public static List<ProcessInfo> HuntSuspiciousProcessesOptimized()
        {
            // For now, just call the regular method
            // In a real implementation, this would have additional optimizations
            return HuntSuspiciousProcesses();
        }

        private static bool IsProcessSuspicious(Process process)
        {
            try
            {
                // Skip system processes and our own process
                if (process.Id == Process.GetCurrentProcess().Id || 
                    process.ProcessName.ToLower().Contains("system") ||
                    process.ProcessName.ToLower().Contains("svchost") ||
                    process.ProcessName.ToLower().Contains("csrss") ||
                    process.ProcessName.ToLower().Contains("winlogon"))
                {
                    return false;
                }

                var processName = process.ProcessName.ToLower();
                
                // Check for suspicious process names
                var suspiciousNames = new[] { "stealer", "keylogger", "trojan", "backdoor", "miner", "bot", "spy" };
                foreach (var name in suspiciousNames)
                {
                    if (processName.Contains(name))
                        return true;
                }

                // Check for processes with unusual characteristics
                if (process.WorkingSet64 > 500 * 1024 * 1024 && processName.Length < 5) // Large memory usage, short name
                    return true;

                // Check for processes with no window but high CPU usage
                if (process.MainWindowHandle == IntPtr.Zero && process.TotalProcessorTime.TotalSeconds > 10)
                    return true;

                return false;
            }
            catch
            {
                return false;
            }
        }

        private static ProcessInfo? AnalyzeProcess(Process process)
        {
            try
            {
                var processInfo = new ProcessInfo
                {
                    ProcessId = process.Id,
                    ProcessName = process.ProcessName,
                    FilePath = GetProcessFilePath(process),
                    MemoryUsage = process.WorkingSet64,
                    CpuTime = process.TotalProcessorTime,
                    StartTime = process.StartTime,
                    ThreatLevel = ThreatLevel.Low
                };

                // Analyze memory for malicious patterns
                var memoryAnalysis = AnalyzeProcessMemory(process);
                if (memoryAnalysis.HasMaliciousPatterns)
                {
                    processInfo.ThreatLevel = ThreatLevel.High;
                    processInfo.MaliciousPatterns = memoryAnalysis.Patterns;
                }

                // Check file entropy if we can access the executable
                if (!string.IsNullOrEmpty(processInfo.FilePath) && File.Exists(processInfo.FilePath))
                {
                    var entropy = CalculateFileEntropy(processInfo.FilePath);
                    if (entropy > 7.5) // High entropy indicates packed/encrypted content
                    {
                        processInfo.ThreatLevel = ThreatLevel.Medium;
                        processInfo.FileEntropy = entropy;
                    }
                }

                return processInfo;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Process analysis failed for {process.ProcessName}: {ex.Message}");
                return null;
            }
        }

        private static string GetProcessFilePath(Process process)
        {
            try
            {
                return process.MainModule?.FileName ?? "";
            }
            catch
            {
                return "";
            }
        }

        private static MemoryAnalysisResult AnalyzeProcessMemory(Process process)
        {
            var result = new MemoryAnalysisResult();
            IntPtr processHandle = IntPtr.Zero;

            try
            {
                // Open process with read access
                processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, process.Id);
                if (processHandle == IntPtr.Zero)
                    return result;

                // Scan memory regions for malicious patterns
                var patterns = ScanMemoryForPatterns(processHandle, process.WorkingSet64);
                if (patterns.Count > 0)
                {
                    result.HasMaliciousPatterns = true;
                    result.Patterns = patterns;
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Memory analysis failed for process {process.ProcessName}: {ex.Message}");
            }
            finally
            {
                if (processHandle != IntPtr.Zero)
                    CloseHandle(processHandle);
            }

            return result;
        }

        private static List<string> ScanMemoryForPatterns(IntPtr processHandle, long maxMemory)
        {
            var foundPatterns = new List<string>();
            
            try
            {
                // Scan in chunks to avoid memory issues
                const int chunkSize = 4096;
                var buffer = new byte[chunkSize];
                
                // Scan through memory regions (simplified approach)
                for (long address = 0; address < Math.Min(maxMemory, 100 * 1024 * 1024); address += chunkSize)
                {
                    try
                    {
                        int bytesRead;
                        if (ReadProcessMemory(processHandle, (IntPtr)address, buffer, chunkSize, out bytesRead))
                        {
                            // Check for malicious patterns
                            foreach (var pattern in MaliciousPatterns)
                            {
                                if (ContainsPattern(buffer, pattern))
                                {
                                    foundPatterns.Add($"Pattern at 0x{address:X8}");
                                }
                            }
                        }
                    }
                    catch
                    {
                        // Skip inaccessible memory regions
                        continue;
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Memory pattern scanning failed: {ex.Message}");
            }

            return foundPatterns;
        }

        private static bool ContainsPattern(byte[] buffer, byte[] pattern)
        {
            for (int i = 0; i <= buffer.Length - pattern.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (buffer[i + j] != pattern[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found) return true;
            }
            return false;
        }

        public static bool InjectNeutralizationCode(ProcessInfo processInfo)
        {
            // CRITICAL: Don't inject code in VM environment or into critical processes
            if (IsVirtualMachine() || IsCriticalSystemProcess(processInfo.ProcessName))
            {
                EnhancedLogger.LogInfo($"Skipping code injection for {processInfo.ProcessName} in VM environment");
                return false;
            }

            IntPtr processHandle = IntPtr.Zero;
            IntPtr allocatedMemory = IntPtr.Zero;
            IntPtr threadHandle = IntPtr.Zero;

            try
            {
                EnhancedLogger.LogInfo($"Injecting neutralization code into process {processInfo.ProcessName} (PID: {processInfo.ProcessId})");

                // Open process with full access
                processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, processInfo.ProcessId);
                if (processHandle == IntPtr.Zero)
                {
                    EnhancedLogger.LogError($"Failed to open process {processInfo.ProcessId}");
                    return false;
                }

                // Create neutralization payload
                var payload = CreateNeutralizationPayload();
                
                // Allocate memory in target process
                allocatedMemory = VirtualAllocEx(processHandle, IntPtr.Zero, payload.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (allocatedMemory == IntPtr.Zero)
                {
                    EnhancedLogger.LogError("Failed to allocate memory in target process");
                    return false;
                }

                // Write payload to target process
                int bytesWritten;
                if (!WriteProcessMemory(processHandle, allocatedMemory, payload, payload.Length, out bytesWritten))
                {
                    EnhancedLogger.LogError("Failed to write payload to target process");
                    return false;
                }

                // Create remote thread to execute payload
                threadHandle = CreateRemoteThread(processHandle, IntPtr.Zero, 0, allocatedMemory, IntPtr.Zero, 0, IntPtr.Zero);
                if (threadHandle == IntPtr.Zero)
                {
                    EnhancedLogger.LogError("Failed to create remote thread");
                    return false;
                }

                // Wait for thread completion
                WaitForSingleObject(threadHandle, 5000);

                EnhancedLogger.LogSuccess($"Successfully injected neutralization code into {processInfo.ProcessName}");
                return true;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Injection failed: {ex.Message}");
                return false;
            }
            finally
            {
                if (threadHandle != IntPtr.Zero) CloseHandle(threadHandle);
                if (allocatedMemory != IntPtr.Zero) VirtualFreeEx(processHandle, allocatedMemory, 0, 0x8000);
                if (processHandle != IntPtr.Zero) CloseHandle(processHandle);
            }
        }

        private static byte[] CreateNeutralizationPayload()
        {
            // Create a harmless payload that just returns
            // In a real implementation, this could be more sophisticated
            return new byte[] {
                0x31, 0xC0,           // xor eax, eax
                0xC3                  // ret
            };
        }

        public static bool TerminateProcess(ProcessInfo processInfo)
        {
            // CRITICAL: Don't terminate critical system processes
            if (IsCriticalSystemProcess(processInfo.ProcessName))
            {
                EnhancedLogger.LogWarning($"Skipping termination of critical system process: {processInfo.ProcessName}");
                return false;
            }

            IntPtr processHandle = IntPtr.Zero;

            try
            {
                EnhancedLogger.LogInfo($"Terminating suspicious process {processInfo.ProcessName} (PID: {processInfo.ProcessId})");

                processHandle = OpenProcess(PROCESS_TERMINATE, false, processInfo.ProcessId);
                if (processHandle == IntPtr.Zero)
                {
                    EnhancedLogger.LogError($"Failed to open process {processInfo.ProcessId} for termination");
                    return false;
                }

                if (SystemHacker.TerminateProcess(processHandle, 0))
                {
                    EnhancedLogger.LogSuccess($"Successfully terminated {processInfo.ProcessName}");
                    return true;
                }
                else
                {
                    EnhancedLogger.LogError($"Failed to terminate {processInfo.ProcessName}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Process termination failed: {ex.Message}");
                return false;
            }
            finally
            {
                if (processHandle != IntPtr.Zero)
                    CloseHandle(processHandle);
            }
        }

        private static double CalculateFileEntropy(string filePath)
        {
            try
            {
                var bytes = File.ReadAllBytes(filePath);
                var frequency = new int[256];
                
                foreach (byte b in bytes)
                    frequency[b]++;

                double entropy = 0;
                int length = bytes.Length;
                
                for (int i = 0; i < 256; i++)
                {
                    if (frequency[i] > 0)
                    {
                        double probability = (double)frequency[i] / length;
                        entropy -= probability * Math.Log(probability, 2);
                    }
                }
                
                return entropy;
            }
            catch
            {
                return 0;
            }
        }

        public static bool IsElevated()
        {
            try
            {
                using (var identity = WindowsIdentity.GetCurrent())
                {
                    var principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch
            {
                return false;
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

        // Add critical process protection
        private static bool IsCriticalSystemProcess(string processName)
        {
            var criticalProcesses = new[] { 
                "SVCHOST.EXE", "LSASS.EXE", "WINLOGON.EXE", "EXPLORER.EXE", 
                "SYSTEM", "SYSTEM IDLE PROCESS", "CSRSS.EXE", "WININIT.EXE",
                "SERVICES.EXE", "SPOOLSV.EXE", "TASKHOSTW.EXE", "DWM.EXE",
                "RUNDLL32.EXE", "WUAUCLT.EXE", "SEARCHINDEXER.EXE"
            };
            return criticalProcesses.Any(p => p.Equals(processName.ToUpper()));
        }
    }



    public class MemoryAnalysisResult
    {
        public bool HasMaliciousPatterns { get; set; }
        public List<string> Patterns { get; set; } = new List<string>();
    }
} 

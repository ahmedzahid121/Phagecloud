using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Linq; // Added for .Any()

namespace PhageVirus.Modules
{
    public class MemoryTrap
    {
        // Windows API constants
        private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_READWRITE = 0x04;
        private const uint MEMORY_BASIC_INFORMATION_SIZE = 28;

        // Windows API structures
        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        // Windows API functions
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, int dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        private static readonly string[] SuspiciousPatterns = {
            // Common shellcode patterns
            "\x90\x90\x90", // NOP sled
            "\xCC\xCC\xCC", // INT3 sled
            "\xEB\xFE",     // JMP $-2 (infinite loop)
            "\xE9",         // JMP instruction
            "\xFF\xE4",     // JMP ESP
            "\xFF\xE0",     // JMP EAX
            "\xFF\xE1",     // JMP ECX
            "\xFF\xE2",     // JMP EDX
            "\xFF\xE3",     // JMP EBX
            "\xFF\xE5",     // JMP EBP
            "\xFF\xE6",     // JMP ESI
            "\xFF\xE7",     // JMP EDI
            
            // Common malware strings
            "cmd.exe",
            "powershell.exe",
            "mshta.exe",
            "wscript.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "http://",
            "https://",
            "\\\\",
            "base64",
            "Invoke-Expression",
            "IEX",
            "Invoke-Mimikatz",
            "Mimikatz",
            "meterpreter",
            "reverse_tcp",
            "bind_tcp",
            
            // Reflective DLL injection patterns
            "LoadLibrary",
            "GetProcAddress",
            "VirtualAlloc",
            "VirtualProtect",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtCreateThreadEx",
            "NtAllocateVirtualMemory",
            "NtWriteVirtualMemory",
            "NtProtectVirtualMemory",
            "RtlCreateUserThread",
            "SetWindowsHookEx",
            "SetThreadContext",
            "ResumeThread",
            "SuspendThread",
            
            // Fileless malware patterns
            "System.Reflection",
            "Assembly.Load",
            "Assembly.LoadFrom",
            "Assembly.LoadFile",
            "Activator.CreateInstance",
            "Type.GetType",
            "MethodInfo.Invoke",
            "Delegate.CreateDelegate",
            "Marshal.GetDelegateForFunctionPointer",
            "Marshal.GetFunctionPointerForDelegate",
            
            // PowerShell reflection patterns
            "Add-Type",
            "Invoke-ReflectivePEInjection",
            "Invoke-DllInjection",
            "Invoke-Shellcode",
            "Invoke-Mimikatz",
            "Invoke-WmiCommand",
            "Invoke-Command",
            "Invoke-Expression",
            "IEX",
            "Out-String",
            "ConvertFrom-Json",
            "ConvertTo-Json",
            
            // Ransomware patterns
            "CryptoAPI",
            "CryptEncrypt",
            "CryptDecrypt",
            "AES",
            "RSA",
            "ChaCha20",
            "Salsa20",
            "encrypt",
            "decrypt",
            "ransom",
            "bitcoin",
            "wallet",
            "payment",
            
            // Keylogging patterns
            "GetAsyncKeyState",
            "GetKeyboardState",
            "SetWindowsHookEx",
            "WH_KEYBOARD",
            "WH_KEYBOARD_LL",
            "keylog",
            "keystroke",
            "keyboard",
            
            // Screen capture patterns
            "BitBlt",
            "PrintWindow",
            "GetDC",
            "CreateCompatibleDC",
            "CreateCompatibleBitmap",
            "SelectObject",
            "screenshot",
            "screen capture",
            "desktop capture",
            
            // Process hollowing patterns
            "NtUnmapViewOfSection",
            "NtMapViewOfSection",
            "NtCreateSection",
            "NtOpenSection",
            "ZwUnmapViewOfSection",
            "ZwMapViewOfSection",
            "ZwCreateSection",
            "ZwOpenSection",
            "process hollowing",
            "process doppelganging",
            
            // Rootkit patterns
            "NtSetInformationThread",
            "NtSetInformationProcess",
            "NtQuerySystemInformation",
            "NtQueryInformationProcess",
            "NtQueryInformationThread",
            "PsLookupProcessByProcessId",
            "PsLookupThreadByThreadId",
            "ObReferenceObjectByHandle",
            "rootkit",
            "kernel hook",
            "SSDT hook",
            "IRP hook"
        };

        private static readonly byte[] SuspiciousBytes = {
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // NOP sled
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // INT3 sled
            0xEB, 0xFE, // JMP $-2
            0xE9, 0x00, 0x00, 0x00, 0x00, // JMP instruction
            0xFF, 0xE4, // JMP ESP
            0xFF, 0xE0, // JMP EAX
            0xFF, 0xE1, // JMP ECX
            0xFF, 0xE2, // JMP EDX
            0xFF, 0xE3, // JMP EBX
            0xFF, 0xE5, // JMP EBP
            0xFF, 0xE6, // JMP ESI
            0xFF, 0xE7  // JMP EDI
        };

        private static bool isMonitoring = false;
        private static readonly object monitorLock = new object();
        
        // Optimization: Throttling and filtering
        private static DateTime lastScanTime = DateTime.MinValue;
        private static readonly TimeSpan scanThrottle = TimeSpan.FromSeconds(30); // Increased from 10 seconds
        private static readonly HashSet<int> scannedProcesses = new();
        
        // Memory caching for optimization
        private static readonly Dictionary<int, MemoryAnalysisResult> memoryCache = new();
        private static readonly TimeSpan cacheExpiration = TimeSpan.FromMinutes(5);

        public class MemoryAnalysisResult
        {
            public DateTime Timestamp { get; set; }
            public bool IsSuspicious { get; set; }
            public double EntropyScore { get; set; }
            public List<string> DetectedPatterns { get; set; } = new();
        }

        public static void StartMemoryMonitoring()
        {
            if (isMonitoring) return;

            lock (monitorLock)
            {
                if (isMonitoring) return;

                try
                {
                    EnhancedLogger.LogInfo("Starting memory trap monitoring...");
                    
                    // Start background monitoring
                    Task.Run(() => MonitorMemoryRegions());
                    
                    isMonitoring = true;
                    EnhancedLogger.LogSuccess("Memory trap activated");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to start memory monitoring: {ex.Message}");
                }
            }
        }

        public static void StopMemoryMonitoring()
        {
            lock (monitorLock)
            {
                if (!isMonitoring) return;

                try
                {
                    isMonitoring = false;
                    EnhancedLogger.LogInfo("Memory trap monitoring stopped");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to stop memory monitoring: {ex.Message}");
                }
            }
        }

        private static void MonitorMemoryRegions()
        {
            // DISABLED FOR VM STABILITY - This was causing infinite loops
            try
            {
                EnhancedLogger.LogInfo("Memory monitoring loop DISABLED for VM stability");
                
                // Do a single scan instead of infinite loop
                var processes = Process.GetProcesses();
                
                // Filter processes to reduce workload - only scan high-risk processes
                var targetProcesses = processes.Where(p => 
                    p.Id != Process.GetCurrentProcess().Id &&
                    !p.ProcessName.ToLower().Contains("system") &&
                    !p.ProcessName.ToLower().Contains("svchost") &&
                    !p.ProcessName.ToLower().Contains("csrss") &&
                    !p.ProcessName.ToLower().Contains("winlogon") &&
                    ShouldScanProcess(p)
                ).Take(1); // Only scan 1 process for VM stability

                foreach (var process in targetProcesses)
                {
                    try
                    {
                        ScanProcessMemoryOptimized(process);
                        scannedProcesses.Add(process.Id);
                    }
                    catch
                    {
                        // Ignore processes we can't access
                    }
                }
                
                // Clean up scanned processes list
                if (scannedProcesses.Count > 10) // Reduced from 20
                {
                    scannedProcesses.Clear();
                }
                
                // Clean up memory cache
                CleanupMemoryCache();

                EnhancedLogger.LogInfo("Single memory scan completed for VM stability");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Memory monitoring error: {ex.Message}");
            }
        }
        
        private static bool ShouldScanProcess(Process process)
        {
            // Only scan processes that haven't been scanned recently
            if (scannedProcesses.Contains(process.Id))
                return false;
                
            // Focus on high-risk processes only
            var highRiskNames = new[] { "powershell", "cmd", "mshta", "rundll32", "regsvr32", "wscript", "cscript" };
            if (highRiskNames.Contains(process.ProcessName.ToLower()))
                return true;
                
            // Only scan processes with very high memory usage
            if (process.WorkingSet64 > 200 * 1024 * 1024) // > 200MB (increased threshold)
                return true;
                
            return false;
        }

        private static void ScanProcessMemoryOptimized(Process process)
        {
            try
            {
                // Check memory cache first
                if (memoryCache.TryGetValue(process.Id, out var cachedResult))
                {
                    if (DateTime.Now - cachedResult.Timestamp < cacheExpiration)
                    {
                        // Use cached result
                        if (cachedResult.IsSuspicious)
                        {
                            EnhancedLogger.LogWarning($"Using cached result: Suspicious memory detected in {process.ProcessName} (PID: {process.Id})");
                        }
                        return;
                    }
                }

                var processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)process.Id);
                if (processHandle == IntPtr.Zero) return;

                try
                {
                    var currentAddress = IntPtr.Zero;
                    var suspiciousRegions = new List<string>();
                    var analysisResult = new MemoryAnalysisResult
                    {
                        Timestamp = DateTime.Now,
                        IsSuspicious = false,
                        DetectedPatterns = new List<string>()
                    };

                    while (true)
                    {
                        var mbi = new MEMORY_BASIC_INFORMATION();
                        var result = VirtualQueryEx(processHandle, currentAddress, out mbi, MEMORY_BASIC_INFORMATION_SIZE);
                        
                        if (result == 0) break; // No more memory regions

                        // Check if this is a committed, readable memory region
                        if (mbi.State == MEM_COMMIT && 
                            (mbi.Protect == PAGE_EXECUTE_READWRITE || 
                             mbi.Protect == PAGE_EXECUTE_READ || 
                             mbi.Protect == PAGE_READWRITE))
                        {
                            // Scan this memory region (reduced size)
                            var regionSize = (int)mbi.RegionSize;
                            if (regionSize > 0 && regionSize <= 512 * 1024) // Max 512KB per region (reduced from 1MB)
                            {
                                var suspicious = ScanMemoryRegionOptimized(processHandle, mbi.BaseAddress, regionSize, process.ProcessName, analysisResult);
                                if (suspicious)
                                {
                                    suspiciousRegions.Add($"0x{mbi.BaseAddress:X8} (Size: {regionSize})");
                                    analysisResult.IsSuspicious = true;
                                }
                            }
                        }

                        // Move to next region
                        currentAddress = IntPtr.Add(mbi.BaseAddress, (int)mbi.RegionSize);
                        
                        // Prevent infinite loop
                        if (currentAddress.ToInt64() <= mbi.BaseAddress.ToInt64())
                            break;
                    }

                    // Cache the analysis result
                    memoryCache[process.Id] = analysisResult;

                    if (suspiciousRegions.Count > 0)
                    {
                        EnhancedLogger.LogThreat($"Suspicious memory regions detected in {process.ProcessName} (PID: {process.Id}): {string.Join(", ", suspiciousRegions)}");
                        
                        // Take action based on threat level
                        HandleSuspiciousMemory(process, suspiciousRegions);
                    }
                }
                finally
                {
                    CloseHandle(processHandle);
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to scan memory for {process.ProcessName}: {ex.Message}");
            }
        }

        private static bool ScanMemoryRegionOptimized(IntPtr processHandle, IntPtr baseAddress, int size, string processName, MemoryAnalysisResult analysisResult)
        {
            try
            {
                var buffer = new byte[Math.Min(size, 2048)]; // Reduced from 4096 to 2048 bytes
                var bytesRead = 0;

                if (!ReadProcessMemory(processHandle, baseAddress, buffer, buffer.Length, out bytesRead))
                    return false;

                if (bytesRead == 0) return false;

                // Check for suspicious byte patterns
                if (ContainsSuspiciousBytes(buffer, bytesRead))
                {
                    analysisResult.DetectedPatterns.Add("Suspicious byte pattern");
                    EnhancedLogger.LogWarning($"Suspicious byte pattern detected in {processName} at 0x{baseAddress:X8}");
                    return true;
                }

                // Check for suspicious strings
                var content = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                if (ContainsSuspiciousStrings(content))
                {
                    analysisResult.DetectedPatterns.Add("Suspicious string pattern");
                    EnhancedLogger.LogWarning($"Suspicious string pattern detected in {processName} at 0x{baseAddress:X8}");
                    return true;
                }

                // Check for high entropy (indicating packed/encrypted content)
                var entropy = CalculateEntropy(buffer, bytesRead);
                analysisResult.EntropyScore = entropy;
                if (entropy > 7.5)
                {
                    analysisResult.DetectedPatterns.Add($"High entropy ({entropy:F2})");
                    EnhancedLogger.LogWarning($"High entropy memory region detected in {processName} at 0x{baseAddress:X8}");
                    return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private static bool ContainsSuspiciousBytes(byte[] buffer, int length)
        {
            for (int i = 0; i <= length - SuspiciousBytes.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < SuspiciousBytes.Length; j++)
                {
                    if (buffer[i + j] != SuspiciousBytes[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return true;
            }
            return false;
        }

        private static bool ContainsSuspiciousStrings(string content)
        {
            var lowerContent = content.ToLower();
            foreach (var pattern in SuspiciousPatterns)
            {
                if (lowerContent.Contains(pattern.ToLower()))
                    return true;
            }
            return false;
        }

        private static double CalculateEntropy(byte[] buffer, int length)
        {
            var frequency = new int[256];
            
            for (int i = 0; i < length; i++)
                frequency[buffer[i]]++;

            double entropy = 0;
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

        private static void HandleSuspiciousMemory(Process process, List<string> suspiciousRegions)
        {
            try
            {
                // CRITICAL: Don't kill processes in VM environment or critical system processes
                if (IsVirtualMachine() || IsCriticalSystemProcess(process.ProcessName))
                {
                    EnhancedLogger.LogInfo($"Skipping aggressive action for {process.ProcessName} in VM environment");
                    return;
                }

                EnhancedLogger.LogWarning($"Handling suspicious memory in {process.ProcessName} (PID: {process.Id})");
                
                // Check for reflective DLL injection
                if (DetectReflectiveDllInjection(process))
                {
                    EnhancedLogger.LogThreat($"Reflective DLL injection detected in {process.ProcessName} (PID: {process.Id})");
                    // Take immediate action for reflective DLL injection
                    process.Kill();
                    EnhancedLogger.LogSuccess($"Terminated process with reflective DLL injection: {process.ProcessName}");
                    return;
                }
                
                // Check for fileless malware patterns
                if (DetectFilelessMalware(process))
                {
                    EnhancedLogger.LogThreat($"Fileless malware detected in {process.ProcessName} (PID: {process.Id})");
                    // Take immediate action for fileless malware
                    process.Kill();
                    EnhancedLogger.LogSuccess($"Terminated process with fileless malware: {process.ProcessName}");
                    return;
                }
                
                // Option 1: Kill the process (aggressive) - DISABLED IN VM
                // process.Kill();
                // EnhancedLogger.LogSuccess($"Terminated process with suspicious memory: {process.ProcessName}");
                
                // Option 2: Overwrite suspicious memory regions (surgical) - DISABLED IN VM
                // OverwriteSuspiciousMemory(process, suspiciousRegions);
                
                // Send telemetry to cloud for memory analysis
                Task.Run(async () =>
                {
                    try
                    {
                        var memoryData = new
                        {
                            process_id = process.Id,
                            process_name = process.ProcessName,
                            suspicious_regions = suspiciousRegions,
                            memory_usage = process.WorkingSet64,
                            thread_count = process.Threads.Count,
                            handle_count = process.HandleCount,
                            threat_type = "suspicious_memory",
                            timestamp = DateTime.UtcNow
                        };

                        await CloudIntegration.SendTelemetryAsync("MemoryTrap", "suspicious_memory", memoryData, ThreatLevel.High);
                        
                        // Get cloud memory analysis
                        var analysis = await CloudIntegration.GetCloudAnalysisAsync("MemoryTrap", memoryData);
                        if (analysis.Success)
                        {
                            EnhancedLogger.LogInfo($"Cloud memory analysis for {process.ProcessName}: {analysis.Analysis}");
                        }
                    }
                    catch (Exception ex)
                    {
                        EnhancedLogger.LogWarning($"Cloud memory analysis failed for {process.ProcessName}: {ex.Message}");
                    }
                });
                
                // Option 3: Log and monitor (passive) - SAFE FOR VM
                EnhancedLogger.LogInfo($"Suspicious memory regions logged for {process.ProcessName}: {string.Join(", ", suspiciousRegions)}");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to handle suspicious memory in {process.ProcessName}: {ex.Message}");
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

        private static bool DetectReflectiveDllInjection(Process process)
        {
            try
            {
                var processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)process.Id);
                if (processHandle == IntPtr.Zero) return false;

                try
                {
                    var currentAddress = IntPtr.Zero;
                    var reflectiveDllIndicators = 0;

                    while (true)
                    {
                        var mbi = new MEMORY_BASIC_INFORMATION();
                        var result = VirtualQueryEx(processHandle, currentAddress, out mbi, MEMORY_BASIC_INFORMATION_SIZE);
                        
                        if (result == 0) break;

                        // Check for executable memory regions that are not associated with loaded modules
                        if (mbi.State == MEM_COMMIT && 
                            (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ))
                        {
                            var regionSize = (int)mbi.RegionSize;
                            if (regionSize > 0 && regionSize <= 1024 * 1024) // Max 1MB per region
                            {
                                var buffer = new byte[Math.Min(regionSize, 4096)];
                                var bytesRead = 0;

                                if (ReadProcessMemory(processHandle, mbi.BaseAddress, buffer, buffer.Length, out bytesRead))
                                {
                                    var content = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                                    
                                    // Check for reflective DLL injection patterns
                                    if (content.Contains("LoadLibrary") && content.Contains("GetProcAddress"))
                                        reflectiveDllIndicators++;
                                    
                                    if (content.Contains("VirtualAlloc") && content.Contains("WriteProcessMemory"))
                                        reflectiveDllIndicators++;
                                    
                                    if (content.Contains("NtAllocateVirtualMemory") && content.Contains("NtWriteVirtualMemory"))
                                        reflectiveDllIndicators++;
                                    
                                    if (content.Contains("CreateRemoteThread") || content.Contains("NtCreateThreadEx"))
                                        reflectiveDllIndicators++;
                                    
                                    // Check for high entropy in executable regions (packed/encrypted DLLs)
                                    if (CalculateEntropy(buffer, bytesRead) > 7.8)
                                        reflectiveDllIndicators++;
                                }
                            }
                        }

                        currentAddress = IntPtr.Add(mbi.BaseAddress, (int)mbi.RegionSize);
                        if (currentAddress.ToInt64() <= mbi.BaseAddress.ToInt64())
                            break;
                    }

                    // If multiple indicators are found, it's likely reflective DLL injection
                    return reflectiveDllIndicators >= 3;
                }
                finally
                {
                    CloseHandle(processHandle);
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Reflective DLL injection detection failed for {process.ProcessName}: {ex.Message}");
                return false;
            }
        }

        private static bool DetectFilelessMalware(Process process)
        {
            try
            {
                var processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)process.Id);
                if (processHandle == IntPtr.Zero) return false;

                try
                {
                    var currentAddress = IntPtr.Zero;
                    var filelessIndicators = 0;

                    while (true)
                    {
                        var mbi = new MEMORY_BASIC_INFORMATION();
                        var result = VirtualQueryEx(processHandle, currentAddress, out mbi, MEMORY_BASIC_INFORMATION_SIZE);
                        
                        if (result == 0) break;

                        if (mbi.State == MEM_COMMIT && 
                            (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ))
                        {
                            var regionSize = (int)mbi.RegionSize;
                            if (regionSize > 0 && regionSize <= 1024 * 1024)
                            {
                                var buffer = new byte[Math.Min(regionSize, 4096)];
                                var bytesRead = 0;

                                if (ReadProcessMemory(processHandle, mbi.BaseAddress, buffer, buffer.Length, out bytesRead))
                                {
                                    var content = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                                    
                                    // Check for fileless malware patterns
                                    if (content.Contains("System.Reflection") && content.Contains("Assembly.Load"))
                                        filelessIndicators++;
                                    
                                    if (content.Contains("Add-Type") && content.Contains("Invoke-Expression"))
                                        filelessIndicators++;
                                    
                                    if (content.Contains("PowerShell") && content.Contains("IEX"))
                                        filelessIndicators++;
                                    
                                    if (content.Contains("WMI") && content.Contains("process call create"))
                                        filelessIndicators++;
                                    
                                    if (content.Contains("Registry") && content.Contains("HKCU\\Run"))
                                        filelessIndicators++;
                                    
                                    // Check for high entropy (encrypted/packed content)
                                    if (CalculateEntropy(buffer, bytesRead) > 7.5)
                                        filelessIndicators++;
                                }
                            }
                        }

                        currentAddress = IntPtr.Add(mbi.BaseAddress, (int)mbi.RegionSize);
                        if (currentAddress.ToInt64() <= mbi.BaseAddress.ToInt64())
                            break;
                    }

                    return filelessIndicators >= 2;
                }
                finally
                {
                    CloseHandle(processHandle);
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Fileless malware detection failed for {process.ProcessName}: {ex.Message}");
                return false;
            }
        }

        private static void OverwriteSuspiciousMemory(Process process, List<string> suspiciousRegions)
        {
            try
            {
                var processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)process.Id);
                if (processHandle == IntPtr.Zero) return;

                try
                {
                    foreach (var region in suspiciousRegions)
                    {
                        // Parse region address and size
                        var parts = region.Split(' ');
                        if (parts.Length >= 2)
                        {
                            var addressStr = parts[0].Replace("0x", "");
                            if (long.TryParse(addressStr, System.Globalization.NumberStyles.HexNumber, null, out long address))
                            {
                                var baseAddress = new IntPtr(address);
                                
                                // Overwrite with zeros
                                var zeroBuffer = new byte[1024]; // 1KB of zeros
                                var bytesWritten = 0;
                                
                                if (WriteProcessMemory(processHandle, baseAddress, zeroBuffer, zeroBuffer.Length, out bytesWritten))
                                {
                                    EnhancedLogger.LogSuccess($"Overwrote suspicious memory region at 0x{address:X8} in {process.ProcessName}");
                                }
                            }
                        }
                    }
                }
                finally
                {
                    CloseHandle(processHandle);
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to overwrite suspicious memory: {ex.Message}");
            }
        }

        public static void InjectMemoryTrap(Process targetProcess)
        {
            try
            {
                EnhancedLogger.LogInfo($"Injecting memory trap into {targetProcess.ProcessName} (PID: {targetProcess.Id})");
                
                var processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)targetProcess.Id);
                if (processHandle == IntPtr.Zero)
                {
                    EnhancedLogger.LogError($"Failed to open process {targetProcess.ProcessName}");
                    return;
                }

                try
                {
                    // Allocate memory in target process
                    var trapCode = CreateTrapCode();
                    var allocatedMemory = VirtualAllocEx(processHandle, IntPtr.Zero, trapCode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    
                    if (allocatedMemory == IntPtr.Zero)
                    {
                        EnhancedLogger.LogError("Failed to allocate memory in target process");
                        return;
                    }

                    // Write trap code to allocated memory
                    var bytesWritten = 0;
                    if (!WriteProcessMemory(processHandle, allocatedMemory, trapCode, trapCode.Length, out bytesWritten))
                    {
                        EnhancedLogger.LogError("Failed to write trap code to target process");
                        return;
                    }

                    // Create remote thread to execute trap
                    var threadId = 0u;
                    var threadHandle = CreateRemoteThread(processHandle, IntPtr.Zero, 0, allocatedMemory, IntPtr.Zero, 0, out threadId);
                    
                    if (threadHandle != IntPtr.Zero)
                    {
                        EnhancedLogger.LogSuccess($"Memory trap injected into {targetProcess.ProcessName} (Thread ID: {threadId})");
                        CloseHandle(threadHandle);
                    }
                    else
                    {
                        EnhancedLogger.LogError("Failed to create remote thread for memory trap");
                    }
                }
                finally
                {
                    CloseHandle(processHandle);
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to inject memory trap: {ex.Message}");
            }
        }

        private static byte[] CreateTrapCode()
        {
            // Simple trap code that logs when executed
            // In a real implementation, this would be more sophisticated
            var trapCode = new List<byte>();
            
            // Add some harmless instructions that can be detected
            trapCode.AddRange(new byte[] { 0x90, 0x90, 0x90 }); // NOP sled
            trapCode.AddRange(new byte[] { 0xCC }); // INT3 (breakpoint)
            trapCode.AddRange(new byte[] { 0x90, 0x90, 0x90 }); // More NOPs
            
            return trapCode.ToArray();
        }

        private static void CleanupMemoryCache()
        {
            var expiredKeys = memoryCache.Keys.Where(key => 
                DateTime.Now - memoryCache[key].Timestamp > cacheExpiration).ToList();
            
            foreach (var key in expiredKeys)
            {
                memoryCache.Remove(key);
            }
            
            // Limit cache size
            if (memoryCache.Count > 50) // Reduced from unlimited
            {
                var oldestKeys = memoryCache.OrderBy(kvp => kvp.Value.Timestamp)
                                          .Take(memoryCache.Count - 50)
                                          .Select(kvp => kvp.Key)
                                          .ToList();
                foreach (var key in oldestKeys)
                {
                    memoryCache.Remove(key);
                }
            }
        }

        public static bool IsMonitoring => isMonitoring;
    }
} 

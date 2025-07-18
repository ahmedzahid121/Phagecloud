using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace PhageVirus.Modules
{
    public class ProcessWatcher
    {
        private static readonly Dictionary<string, ThreatPattern> ThreatPatterns = new()
        {
            // PowerShell attack patterns
            { "powershell.*-enc", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "PowerShell encoded command" } },
            { "powershell.*-e", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "PowerShell encoded command" } },
            { "powershell.*Invoke-Expression", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "PowerShell expression execution" } },
            { "powershell.*IEX", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "PowerShell expression execution" } },
            { "powershell.*Invoke-Mimikatz", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "Mimikatz execution" } },
            { "powershell.*Invoke-ReflectivePEInjection", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "Reflective PE injection" } },
            { "powershell.*-ExecutionPolicy.*Bypass", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "PowerShell execution policy bypass" } },
            { "powershell.*-WindowStyle.*Hidden", new ThreatPattern { Action = "block", Level = ThreatLevel.High, Description = "PowerShell hidden window" } },
            { "powershell.*-NoProfile", new ThreatPattern { Action = "log", Level = ThreatLevel.Medium, Description = "PowerShell no profile execution" } },
            
            // Fileless malware patterns
            { "powershell.*-Command.*\\$env:", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "Fileless PowerShell execution" } },
            { "powershell.*-Command.*\\[System\\.Reflection", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "PowerShell reflection loading" } },
            { "powershell.*-Command.*Add-Type", new ThreatPattern { Action = "log", Level = ThreatLevel.High, Description = "PowerShell dynamic type loading" } },
            { "wmic.*process.*call.*create", new ThreatPattern { Action = "block", Level = ThreatLevel.High, Description = "WMIC process creation" } },
            { "wmic.*process.*call.*create.*powershell", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "WMIC PowerShell execution" } },
            
            // Script execution patterns
            { "mshta.*http", new ThreatPattern { Action = "kill", Level = ThreatLevel.High, Description = "MSHTA remote script execution" } },
            { "mshta.*javascript", new ThreatPattern { Action = "kill", Level = ThreatLevel.High, Description = "MSHTA JavaScript execution" } },
            { "wscript.*http", new ThreatPattern { Action = "kill", Level = ThreatLevel.High, Description = "WScript remote execution" } },
            { "cscript.*http", new ThreatPattern { Action = "kill", Level = ThreatLevel.High, Description = "CScript remote execution" } },
            { "rundll32.*javascript", new ThreatPattern { Action = "block", Level = ThreatLevel.High, Description = "Rundll32 JavaScript execution" } },
            { "rundll32.*vbscript", new ThreatPattern { Action = "block", Level = ThreatLevel.High, Description = "Rundll32 VBScript execution" } },
            
            // Network tools and RATs
            { "nc\\.exe.*-e", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "Netcat reverse shell" } },
            { "ncat.*-e", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "Ncat reverse shell" } },
            { "telnet.*-e", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "Telnet reverse shell" } },
            { "plink.*-R", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "PuTTY reverse tunnel" } },
            { "socat.*EXEC", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "Socat reverse shell" } },
            { "chisel.*client", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "Chisel tunneling tool" } },
            { "ngrok.*tcp", new ThreatPattern { Action = "block", Level = ThreatLevel.High, Description = "Ngrok tunneling" } },
            
            // Registry manipulation and persistence
            { "regsvr32.*/s.*http", new ThreatPattern { Action = "block", Level = ThreatLevel.High, Description = "Regsvr32 remote DLL loading" } },
            { "regsvr32.*/s.*\\\\", new ThreatPattern { Action = "block", Level = ThreatLevel.High, Description = "Regsvr32 remote DLL loading" } },
            { "reg.*add.*HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", new ThreatPattern { Action = "block", Level = ThreatLevel.High, Description = "Registry persistence" } },
            { "reg.*add.*HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", new ThreatPattern { Action = "block", Level = ThreatLevel.High, Description = "Registry persistence" } },
            { "schtasks.*/create.*/tn.*/tr.*powershell", new ThreatPattern { Action = "block", Level = ThreatLevel.High, Description = "Scheduled task with PowerShell" } },
            { "schtasks.*/create.*/tn.*/tr.*cmd", new ThreatPattern { Action = "log", Level = ThreatLevel.Medium, Description = "Scheduled task with CMD" } },
            
            // Command execution chains
            { "cmd.*powershell", new ThreatPattern { Action = "log", Level = ThreatLevel.Medium, Description = "CMD to PowerShell chain" } },
            { "word.*powershell", new ThreatPattern { Action = "log", Level = ThreatLevel.Medium, Description = "Word to PowerShell chain" } },
            { "excel.*powershell", new ThreatPattern { Action = "log", Level = ThreatLevel.Medium, Description = "Excel to PowerShell chain" } },
            { "outlook.*powershell", new ThreatPattern { Action = "log", Level = ThreatLevel.Medium, Description = "Outlook to PowerShell chain" } },
            { "chrome.*powershell", new ThreatPattern { Action = "log", Level = ThreatLevel.Medium, Description = "Chrome to PowerShell chain" } },
            { "firefox.*powershell", new ThreatPattern { Action = "log", Level = ThreatLevel.Medium, Description = "Firefox to PowerShell chain" } },
            
            // Suspicious executables
            { "mimikatz", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "Mimikatz credential dumper" } },
            { "procdump", new ThreatPattern { Action = "log", Level = ThreatLevel.High, Description = "Process dump tool" } },
            { "wce", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "Windows Credential Editor" } },
            { "pwdump", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "Password dump tool" } },
            { "laZagne", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "LaZagne credential dumper" } },
            { "hashcat", new ThreatPattern { Action = "log", Level = ThreatLevel.High, Description = "Hashcat password cracking" } },
            { "john", new ThreatPattern { Action = "log", Level = ThreatLevel.High, Description = "John the Ripper" } },
            
            // Lateral movement tools
            { "psexec", new ThreatPattern { Action = "log", Level = ThreatLevel.High, Description = "PsExec lateral movement" } },
            { "wmic.*process.*call", new ThreatPattern { Action = "log", Level = ThreatLevel.High, Description = "WMIC process execution" } },
            { "wmic.*/node:", new ThreatPattern { Action = "log", Level = ThreatLevel.High, Description = "WMIC remote execution" } },
            { "psexec.*\\\\", new ThreatPattern { Action = "log", Level = ThreatLevel.High, Description = "PsExec remote execution" } },
            { "smbexec", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "SMBExec lateral movement" } },
            { "wmiexec", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "WMIExec lateral movement" } },
            
            // LOLBins (Living off the Land Binaries)
            { "certutil.*-urlcache", new ThreatPattern { Action = "log", Level = ThreatLevel.Medium, Description = "Certutil URL cache" } },
            { "certutil.*-decode", new ThreatPattern { Action = "log", Level = ThreatLevel.Medium, Description = "Certutil decode" } },
            { "bitsadmin.*/transfer", new ThreatPattern { Action = "log", Level = ThreatLevel.Medium, Description = "BITSAdmin file transfer" } },
            { "bitsadmin.*/create", new ThreatPattern { Action = "log", Level = ThreatLevel.Medium, Description = "BITSAdmin job creation" } },
            { "forfiles.*/p.*/c", new ThreatPattern { Action = "log", Level = ThreatLevel.Medium, Description = "ForFiles command execution" } },
            { "regsvr32.*/s.*/u", new ThreatPattern { Action = "log", Level = ThreatLevel.Medium, Description = "Regsvr32 unregister" } },
            
            // Encoded payloads
            { "base64.*[A-Za-z0-9+/]{20,}", new ThreatPattern { Action = "log", Level = ThreatLevel.Medium, Description = "Base64 encoded payload" } },
            { "\\$enc.*=.*\\[Convert\\]", new ThreatPattern { Action = "block", Level = ThreatLevel.High, Description = "PowerShell encoded variable" } },
            { "\\[Convert\\]\\.FromBase64String", new ThreatPattern { Action = "log", Level = ThreatLevel.High, Description = "Base64 decoding" } },
            
            // Ransomware patterns
            { "cipher.*/w", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "Cipher secure deletion" } },
            { "fsutil.*usn.*deletejournal", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "USN journal deletion" } },
            { "vssadmin.*delete.*shadows", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "Volume shadow copy deletion" } },
            { "bcdedit.*/set.*recoveryenabled.*no", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical, Description = "Recovery disable" } },
            
            // Keylogging and screen capture
            { "GetAsyncKeyState", new ThreatPattern { Action = "log", Level = ThreatLevel.High, Description = "Keylogging attempt" } },
            { "BitBlt", new ThreatPattern { Action = "log", Level = ThreatLevel.High, Description = "Screen capture attempt" } },
            { "PrintWindow", new ThreatPattern { Action = "log", Level = ThreatLevel.High, Description = "Window capture attempt" } },
            
            // Process hollowing indicators
            { "svchost.*-k.*netsvcs", new ThreatPattern { Action = "log", Level = ThreatLevel.Medium, Description = "Suspicious svchost execution" } },
            { "lsass.*-k.*DcomLaunch", new ThreatPattern { Action = "log", Level = ThreatLevel.Medium, Description = "Suspicious lsass execution" } },
            
            // Reflective DLL injection
            { "LoadLibrary.*kernel32", new ThreatPattern { Action = "log", Level = ThreatLevel.High, Description = "Dynamic library loading" } },
            { "GetProcAddress", new ThreatPattern { Action = "log", Level = ThreatLevel.Medium, Description = "Dynamic function resolution" } },
            { "VirtualAlloc.*PAGE_EXECUTE", new ThreatPattern { Action = "log", Level = ThreatLevel.High, Description = "Executable memory allocation" } }
        };

        private static readonly string[] HighRiskExecutables = {
            "powershell.exe", "powershell_ise.exe", "mshta.exe", "wscript.exe", "cscript.exe",
            "regsvr32.exe", "rundll32.exe", "nc.exe", "ncat.exe", "telnet.exe", "mimikatz.exe",
            "procdump.exe", "wce.exe", "pwdump.exe", "psexec.exe", "wmic.exe"
        };

        private static readonly string[] HighRiskFolders = {
            @"C:\Users\Public\Downloads",
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            @"C:\Windows\Temp"
        };

        private static ManagementEventWatcher? processWatcher;
        private static bool isWatching = false;
        private static readonly object watchLock = new object();
        
        // Optimization: Process whitelist and filtering
        private static readonly string[] ProcessWhitelist = { 
            "svchost", "explorer", "csrss", "winlogon", "services", "spoolsv", 
            "taskhostw", "dwm", "rundll32", "wuauclt", "searchindexer" 
        };
        
        // Optimization: Reduced monitoring scope
        private static readonly HashSet<int> monitoredProcessIds = new();
        private static readonly TimeSpan processCleanupInterval = TimeSpan.FromMinutes(5);
        private static DateTime lastCleanupTime = DateTime.Now;

        public static void StartWatching()
        {
            if (isWatching) return;

            lock (watchLock)
            {
                if (isWatching) return;

                try
                {
                    EnhancedLogger.LogInfo("Starting optimized real-time process watching...");
                    
                    // Start WMI event watcher for new processes (event-driven)
                    StartWmiEventWatcher();
                    
                    // Start optimized background monitoring with reduced frequency
                    Task.Run(() => MonitorExistingProcessesOptimized());
                    
                    isWatching = true;
                    EnhancedLogger.LogSuccess("Optimized process watching activated");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to start process watching: {ex.Message}");
                }
            }
        }

        public static void StopWatching()
        {
            lock (watchLock)
            {
                if (!isWatching) return;

                try
                {
                    processWatcher?.Stop();
                    processWatcher?.Dispose();
                    processWatcher = null;
                    isWatching = false;
                    EnhancedLogger.LogInfo("Process watching stopped");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to stop process watching: {ex.Message}");
                }
            }
        }

        private static void StartWmiEventWatcher()
        {
            try
            {
                // Optimized WMI query with event-driven monitoring
                var query = new WqlEventQuery("SELECT * FROM __InstanceCreationEvent WITHIN 3 WHERE TargetInstance ISA 'Win32_Process'");
                var scope = new ManagementScope(@"\\.\root\CIMV2");
                processWatcher = new ManagementEventWatcher(scope, query);
                
                processWatcher.EventArrived += ProcessWatcher_EventArrived;
                processWatcher.Start();
                
                EnhancedLogger.LogInfo("Optimized WMI event watcher started");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start WMI event watcher: {ex.Message}");
            }
        }

        private static void ProcessWatcher_EventArrived(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var targetInstance = e.NewEvent["TargetInstance"] as ManagementBaseObject;
                if (targetInstance == null) return;

                var processId = Convert.ToInt32(targetInstance["ProcessId"]);
                var processName = targetInstance["Name"]?.ToString() ?? "";
                var commandLine = targetInstance["CommandLine"]?.ToString() ?? "";

                // Skip whitelisted processes immediately
                if (IsWhitelistedProcess(processName))
                    return;

                // Analyze only high-risk processes
                if (IsHighRiskProcess(processName, commandLine))
                {
                    AnalyzeProcess(processId, processName, commandLine);
                    monitoredProcessIds.Add(processId);
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Process watcher event error: {ex.Message}");
            }
        }

        private static void AnalyzeProcess(int processId, string processName, string commandLine)
        {
            try
            {
                var threatLevel = ThreatLevel.Low;
                var detectedPatterns = new List<string>();
                var action = "monitor";

                // Check if it's a high-risk executable
                if (Array.Exists(HighRiskExecutables, exe => processName.Equals(exe, StringComparison.OrdinalIgnoreCase)))
                {
                    threatLevel = ThreatLevel.Medium;
                    detectedPatterns.Add($"High-risk executable: {processName}");
                }

                // Check command line against threat patterns
                foreach (var pattern in ThreatPatterns)
                {
                    if (Regex.IsMatch(commandLine, pattern.Key, RegexOptions.IgnoreCase))
                    {
                        var threatPattern = pattern.Value;
                        threatLevel = (ThreatLevel)Math.Max((byte)threatLevel, (byte)threatPattern.Level);
                        detectedPatterns.Add(threatPattern.Description);
                        action = threatPattern.Action;
                    }
                }

                // Check for suspicious process ancestry
                var ancestry = GetProcessAncestry(processId);
                if (IsSuspiciousAncestry(ancestry))
                {
                    threatLevel = (ThreatLevel)Math.Max((byte)threatLevel, (byte)ThreatLevel.Medium);
                    detectedPatterns.Add($"Suspicious ancestry: {string.Join(" > ", ancestry)}");
                }

                // Check for process hollowing
                if (DetectProcessHollowing(processId, processName))
                {
                    threatLevel = (ThreatLevel)Math.Max((byte)threatLevel, (byte)ThreatLevel.Critical);
                    detectedPatterns.Add("Process hollowing detected");
                }

                // Take action based on threat level
                if (detectedPatterns.Count > 0)
                {
                    EnhancedLogger.LogThreat($"Process detected: {processName} (PID: {processId}) - {string.Join(", ", detectedPatterns)}");
                    
                    switch (action)
                    {
                        case "block":
                            BlockProcess(processId, processName);
                            break;
                        case "kill":
                            KillProcess(processId, processName);
                            break;
                        case "log":
                            LogSuspiciousProcess(processId, processName, commandLine, detectedPatterns);
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Process analysis failed for {processName}: {ex.Message}");
            }
        }

        private static void BlockProcess(int processId, string processName)
        {
            try
            {
                EnhancedLogger.LogWarning($"Blocking suspicious process: {processName} (PID: {processId})");
                
                // Try to terminate the process
                KillProcess(processId, processName);
                
                // Log the block action
                EnhancedLogger.LogSuccess($"Successfully blocked {processName}");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to block process {processName}: {ex.Message}");
            }
        }

        private static void KillProcess(int processId, string processName)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                process.Kill();
                process.WaitForExit(5000);
                EnhancedLogger.LogSuccess($"Terminated suspicious process: {processName} (PID: {processId})");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to kill process {processName}: {ex.Message}");
            }
        }

        private static void LogSuspiciousProcess(int processId, string processName, string commandLine, List<string> patterns)
        {
            EnhancedLogger.LogWarning($"Suspicious process logged: {processName} (PID: {processId})");
            EnhancedLogger.LogInfo($"Command line: {commandLine}");
            EnhancedLogger.LogInfo($"Patterns: {string.Join(", ", patterns)}");
            
            // Send telemetry to cloud for analysis
            Task.Run(async () =>
            {
                try
                {
                    var threatData = new
                    {
                        process_id = processId,
                        process_name = processName,
                        command_line = commandLine,
                        patterns = patterns,
                        timestamp = DateTime.UtcNow
                    };

                    await CloudIntegration.SendTelemetryAsync("ProcessWatcher", "suspicious_process", threatData, ThreatLevel.High);
                    
                    // Get cloud analysis
                    var analysis = await CloudIntegration.GetCloudAnalysisAsync("ProcessWatcher", threatData);
                    if (analysis.Success)
                    {
                        EnhancedLogger.LogInfo($"Cloud analysis for {processName}: {analysis.Analysis}");
                    }
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogWarning($"Cloud analysis failed for {processName}: {ex.Message}");
                }
            });
        }

        private static List<string> GetProcessAncestry(int processId)
        {
            var ancestry = new List<string>();
            
            try
            {
                var currentProcess = Process.GetProcessById(processId);
                ancestry.Add(currentProcess.ProcessName);

                // Get parent process (simplified - in real implementation you'd use WMI)
                // This is a basic implementation
                try
                {
                    var parentProcess = GetParentProcess(currentProcess);
                    if (parentProcess != null)
                    {
                        ancestry.Insert(0, parentProcess.ProcessName);
                    }
                }
                catch
                {
                    // Ignore parent process errors
                }
            }
            catch
            {
                // Process might have already terminated
            }

            return ancestry;
        }

        private static Process? GetParentProcess(Process process)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {process.Id}");
                
                foreach (ManagementObject obj in searcher.Get())
                {
                    var parentId = Convert.ToInt32(obj["ParentProcessId"]);
                    return Process.GetProcessById(parentId);
                }
            }
            catch
            {
                // Ignore errors
            }
            
            return null;
        }

        private static bool IsSuspiciousAncestry(List<string> ancestry)
        {
            if (ancestry.Count < 2) return false;

            var suspiciousChains = new[]
            {
                new[] { "WINWORD", "powershell" },
                new[] { "EXCEL", "powershell" },
                new[] { "OUTLOOK", "powershell" },
                new[] { "chrome", "powershell" },
                new[] { "firefox", "powershell" },
                new[] { "iexplore", "powershell" },
                new[] { "cmd", "powershell" },
                new[] { "cmd", "mshta" },
                new[] { "cmd", "wscript" },
                new[] { "explorer", "cmd", "powershell" },
                new[] { "explorer", "rundll32" },
                new[] { "svchost", "powershell" },
                new[] { "lsass", "cmd" },
                new[] { "winlogon", "powershell" },
                new[] { "csrss", "powershell" },
                new[] { "wininit", "cmd" },
                new[] { "services", "powershell" },
                new[] { "spoolsv", "cmd" },
                new[] { "taskmgr", "powershell" },
                new[] { "regedit", "cmd" }
            };

            foreach (var chain in suspiciousChains)
            {
                if (ancestry.Count >= chain.Length)
                {
                    bool matches = true;
                    for (int i = 0; i < chain.Length; i++)
                    {
                        if (!ancestry[i].Equals(chain[i], StringComparison.OrdinalIgnoreCase))
                        {
                            matches = false;
                            break;
                        }
                    }
                    if (matches) return true;
                }
            }

            return false;
        }

        // Advanced process hollowing detection
        private static bool DetectProcessHollowing(int processId, string processName)
        {
            try
            {
                // Check if process still exists before analyzing
                if (!ProcessExists(processId))
                {
                    return false;
                }
                
                var process = Process.GetProcessById(processId);
                
                // Check for suspicious parent-child relationships
                var parent = GetParentProcess(process);
                if (parent != null)
                {
                    var parentName = parent.ProcessName.ToLower();
                    var childName = processName.ToLower();
                    
                    // Suspicious parent-child pairs for process hollowing
                    var suspiciousPairs = new[]
                    {
                        ("svchost", "cmd"),
                        ("svchost", "powershell"),
                        ("lsass", "cmd"),
                        ("lsass", "powershell"),
                        ("winlogon", "cmd"),
                        ("winlogon", "powershell"),
                        ("csrss", "cmd"),
                        ("csrss", "powershell"),
                        ("wininit", "cmd"),
                        ("wininit", "powershell"),
                        ("services", "cmd"),
                        ("services", "powershell"),
                        ("spoolsv", "cmd"),
                        ("spoolsv", "powershell"),
                        ("taskmgr", "cmd"),
                        ("taskmgr", "powershell"),
                        ("regedit", "cmd"),
                        ("regedit", "powershell")
                    };

                    foreach (var pair in suspiciousPairs)
                    {
                        if (parentName.Contains(pair.Item1) && childName.Contains(pair.Item2))
                        {
                            EnhancedLogger.LogThreat($"Process hollowing detected: {parent.ProcessName} -> {processName}");
                            return true;
                        }
                    }
                }

                // Check for unmapped code regions (process hollowing indicator)
                if (HasUnmappedCodeRegions(process))
                {
                    EnhancedLogger.LogThreat($"Unmapped code regions detected in {processName} - possible process hollowing");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Process hollowing detection failed for {processName}: {ex.Message}");
                return false;
            }
        }
        
        private static bool ProcessExists(int processId)
        {
            try
            {
                Process.GetProcessById(processId);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool HasUnmappedCodeRegions(Process process)
        {
            try
            {
                // This is a simplified check - in a real implementation you'd use Windows APIs
                // to check memory regions for unmapped executable code
                var modules = process.Modules;
                var moduleCount = modules.Count;
                
                // If a legitimate process has very few modules, it might be hollowed
                if (process.ProcessName.ToLower().Contains("svchost") && moduleCount < 10)
                {
                    return true;
                }
                
                if (process.ProcessName.ToLower().Contains("lsass") && moduleCount < 15)
                {
                    return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private static bool IsWhitelistedProcess(string processName)
        {
            return ProcessWhitelist.Any(p => 
                processName.Equals(p, StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsHighRiskProcess(string processName, string commandLine)
        {
            // Check for high-risk process names
            var highRiskNames = new[] { 
                "powershell", "cmd", "mshta", "wscript", "cscript", "rundll32", 
                "regsvr32", "nc", "ncat", "telnet", "mimikatz", "procdump" 
            };
            
            if (highRiskNames.Any(p => processName.Contains(p, StringComparison.OrdinalIgnoreCase)))
                return true;

            // Check command line for suspicious patterns
            var lowerCommandLine = commandLine.ToLower();
            if (ThreatPatterns.Any(pattern => 
                Regex.IsMatch(lowerCommandLine, pattern.Key, RegexOptions.IgnoreCase)))
                return true;

            return false;
        }

        private static void MonitorExistingProcessesOptimized()
        {
            while (isWatching)
            {
                try
                {
                    // Clean up monitored processes list periodically
                    if (DateTime.Now - lastCleanupTime > processCleanupInterval)
                    {
                        CleanupMonitoredProcesses();
                        lastCleanupTime = DateTime.Now;
                    }

                    // Only scan a small subset of existing processes
                    var processes = Process.GetProcesses();
                    var highRiskProcesses = processes.Where(p => 
                        IsHighRiskProcess(p.ProcessName, GetProcessCommandLine(p.Id)) &&
                        !monitoredProcessIds.Contains(p.Id)
                    ).Take(3); // Limit to 3 processes per cycle

                    foreach (var process in highRiskProcesses)
                    {
                        try
                        {
                            var commandLine = GetProcessCommandLine(process.Id);
                            AnalyzeProcess(process.Id, process.ProcessName, commandLine);
                            monitoredProcessIds.Add(process.Id);
                        }
                        catch
                        {
                            // Skip processes we can't access
                        }
                    }

                    // Sleep longer to reduce CPU usage
                    Thread.Sleep(30000); // 30 seconds instead of continuous monitoring
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogWarning($"Process monitoring error: {ex.Message}");
                    Thread.Sleep(60000); // Longer sleep on error
                }
            }
        }

        private static void CleanupMonitoredProcesses()
        {
            try
            {
                var currentProcesses = Process.GetProcesses().Select(p => p.Id).ToHashSet();
                var expiredProcessIds = monitoredProcessIds.Where(id => !currentProcesses.Contains(id)).ToList();
                
                foreach (var processId in expiredProcessIds)
                {
                    monitoredProcessIds.Remove(processId);
                }

                // Limit the size of monitored processes list
                if (monitoredProcessIds.Count > 100)
                {
                    var excessCount = monitoredProcessIds.Count - 100;
                    var processesToRemove = monitoredProcessIds.Take(excessCount).ToList();
                    foreach (var processId in processesToRemove)
                    {
                        monitoredProcessIds.Remove(processId);
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Process cleanup error: {ex.Message}");
            }
        }

        private static string GetProcessCommandLine(int processId)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}");
                
                foreach (ManagementObject obj in searcher.Get())
                {
                    return obj["CommandLine"]?.ToString() ?? "";
                }
            }
            catch
            {
                // Ignore errors - might not have permission
            }
            
            return "";
        }

        public static bool IsWatching => isWatching;
    }

    public class ThreatPattern
    {
        public string Action { get; set; } = "log";
        public ThreatLevel Level { get; set; } = ThreatLevel.Low;
        public string Description { get; set; } = "";
    }
} 

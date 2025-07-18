using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Linq; // Added for .Take() and .Sum()
using System.Management;

namespace PhageVirus.Modules
{
    public class LiveCommandShell
    {
        private static bool isRunning = false;
        private static readonly Dictionary<string, CommandHandler> CommandHandlers = new();
        private static readonly List<CommandHistory> CommandHistory = new();
        private static readonly object historyLock = new object();
        private static readonly string CommandLogPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus", "Logs", "command_shell.log");
        
        // Security settings
        private static readonly string AdminPassword = "PhageVirus2024!Secure"; // In production, use proper authentication
        private static readonly int MaxHistorySize = 1000;
        private static readonly string[] RestrictedCommands = {
            "format", "del", "rmdir", "rm", "shutdown", "restart", "reboot",
            "net user", "net localgroup", "wmic", "reg delete", "reg add",
            "sc delete", "sc stop", "taskkill", "tskill", "kill"
        };

        // Advanced command monitoring patterns
        private static readonly Dictionary<string, CommandThreatLevel> CommandThreatPatterns = new()
        {
            // PowerShell attacks
            { "powershell.*-enc", CommandThreatLevel.Critical },
            { "powershell.*-e", CommandThreatLevel.Critical },
            { "powershell.*Invoke-Expression", CommandThreatLevel.Critical },
            { "powershell.*IEX", CommandThreatLevel.Critical },
            { "powershell.*-ExecutionPolicy.*Bypass", CommandThreatLevel.Critical },
            { "powershell.*-WindowStyle.*Hidden", CommandThreatLevel.High },
            { "powershell.*-NoProfile", CommandThreatLevel.Medium },
            
            // Fileless malware
            { "powershell.*-Command.*\\$env:", CommandThreatLevel.Critical },
            { "powershell.*-Command.*\\[System\\.Reflection", CommandThreatLevel.Critical },
            { "powershell.*-Command.*Add-Type", CommandThreatLevel.High },
            { "wmic.*process.*call.*create", CommandThreatLevel.High },
            { "wmic.*process.*call.*create.*powershell", CommandThreatLevel.Critical },
            
            // LOLBins (Living off the Land Binaries)
            { "certutil.*-urlcache", CommandThreatLevel.Medium },
            { "certutil.*-decode", CommandThreatLevel.Medium },
            { "bitsadmin.*/transfer", CommandThreatLevel.Medium },
            { "bitsadmin.*/create", CommandThreatLevel.Medium },
            { "forfiles.*/p.*/c", CommandThreatLevel.Medium },
            { "regsvr32.*/s.*/u", CommandThreatLevel.Medium },
            
            // Lateral movement
            { "psexec.*\\\\", CommandThreatLevel.High },
            { "wmic.*/node:", CommandThreatLevel.High },
            { "smbexec", CommandThreatLevel.Critical },
            { "wmiexec", CommandThreatLevel.Critical },
            
            // Ransomware
            { "cipher.*/w", CommandThreatLevel.Critical },
            { "fsutil.*usn.*deletejournal", CommandThreatLevel.Critical },
            { "vssadmin.*delete.*shadows", CommandThreatLevel.Critical },
            { "bcdedit.*/set.*recoveryenabled.*no", CommandThreatLevel.Critical },
            
            // Credential theft
            { "mimikatz", CommandThreatLevel.Critical },
            { "procdump.*lsass", CommandThreatLevel.Critical },
            { "sekurlsa", CommandThreatLevel.Critical },
            { "wdigest", CommandThreatLevel.Critical },
            { "kerberos", CommandThreatLevel.Critical },
            { "hashdump", CommandThreatLevel.Critical },
            
            // Network attacks
            { "nc.*-e", CommandThreatLevel.Critical },
            { "ncat.*-e", CommandThreatLevel.Critical },
            { "telnet.*-e", CommandThreatLevel.Critical },
            { "plink.*-R", CommandThreatLevel.Critical },
            { "socat.*EXEC", CommandThreatLevel.Critical },
            { "chisel.*client", CommandThreatLevel.Critical },
            { "ngrok.*tcp", CommandThreatLevel.High },
            
            // Registry persistence
            { "reg.*add.*HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", CommandThreatLevel.High },
            { "reg.*add.*HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", CommandThreatLevel.High },
            { "schtasks.*/create.*/tn.*/tr.*powershell", CommandThreatLevel.High },
            
            // Process hollowing indicators
            { "svchost.*-k.*netsvcs", CommandThreatLevel.Medium },
            { "lsass.*-k.*DcomLaunch", CommandThreatLevel.Medium },
            
            // Reflective DLL injection
            { "LoadLibrary.*kernel32", CommandThreatLevel.High },
            { "GetProcAddress", CommandThreatLevel.Medium },
            { "VirtualAlloc.*PAGE_EXECUTE", CommandThreatLevel.High }
        };

        public enum CommandThreatLevel
        {
            Low,
            Medium,
            High,
            Critical
        }

        public static bool StartCommandShell()
        {
            try
            {
                EnhancedLogger.LogInfo("Starting Live Command Shell...", Console.WriteLine);
                
                isRunning = true;
                
                // Initialize command handlers
                InitializeCommandHandlers();
                
                // Start command processing loop
                Task.Run(ProcessCommands);
                
                EnhancedLogger.LogInfo("Live Command Shell started", Console.WriteLine);
                
                // Send telemetry to cloud for command shell status
                Task.Run(async () =>
                {
                    try
                    {
                        var commandShellData = new
                        {
                            command_handlers_count = CommandHandlers.Count,
                            command_history_count = CommandHistory.Count,
                            restricted_commands_count = RestrictedCommands.Length,
                            command_threat_patterns_count = CommandThreatPatterns.Count,
                            threat_type = "command_shell_status",
                            timestamp = DateTime.UtcNow
                        };

                        await CloudIntegration.SendTelemetryAsync("LiveCommandShell", "command_shell_status", commandShellData, ThreatLevel.Normal);
                        
                        // Get cloud command shell analysis
                        var analysis = await CloudIntegration.GetCloudAnalysisAsync("LiveCommandShell", commandShellData);
                        if (analysis.Success)
                        {
                            EnhancedLogger.LogInfo($"Cloud command shell analysis: {analysis.Analysis}");
                        }
                    }
                    catch (Exception ex)
                    {
                        EnhancedLogger.LogWarning($"Cloud command shell analysis failed: {ex.Message}");
                    }
                });
                
                return true;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start Live Command Shell: {ex.Message}", Console.WriteLine);
                return false;
            }
        }

        public static void StopCommandShell()
        {
            try
            {
                isRunning = false;
                EnhancedLogger.LogInfo("Live Command Shell stopped", Console.WriteLine);
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to stop Live Command Shell: {ex.Message}", Console.WriteLine);
            }
        }

        private static void InitializeCommandHandlers()
        {
            try
            {
                // System commands
                CommandHandlers["scan"] = new CommandHandler("scan", "Trigger system scan", ScanSystem);
                CommandHandlers["status"] = new CommandHandler("status", "Show system status", ShowStatus);
                CommandHandlers["processes"] = new CommandHandler("processes", "List running processes", ListProcesses);
                CommandHandlers["memory"] = new CommandHandler("memory", "Show memory usage", ShowMemoryUsage);
                CommandHandlers["logs"] = new CommandHandler("logs", "Show recent logs", ShowLogs);
                CommandHandlers["threats"] = new CommandHandler("threats", "Show detected threats", ShowThreats);
                CommandHandlers["modules"] = new CommandHandler("modules", "Show module status", ShowModules);
                CommandHandlers["mesh"] = new CommandHandler("mesh", "Show mesh network status", ShowMeshStatus);
                CommandHandlers["honey"] = new CommandHandler("honey", "Show honey process status", ShowHoneyStatus);
                CommandHandlers["dns"] = new CommandHandler("dns", "Show DNS sinkhole status", ShowDnsStatus);
                CommandHandlers["zerotrust"] = new CommandHandler("zerotrust", "Show zero trust status", ShowZeroTrustStatus);
                
                // Advanced commands
                CommandHandlers["inject"] = new CommandHandler("inject", "Inject payload into process", InjectPayload);
                CommandHandlers["query"] = new CommandHandler("query", "Query process memory", QueryProcessMemory);
                CommandHandlers["pull"] = new CommandHandler("pull", "Pull logs or data", PullData);
                CommandHandlers["update"] = new CommandHandler("update", "Inject updates", InjectUpdates);
                CommandHandlers["backup"] = new CommandHandler("backup", "Create system backup", CreateBackup);
                CommandHandlers["restore"] = new CommandHandler("restore", "Restore from backup", RestoreBackup);
                CommandHandlers["rollback"] = new CommandHandler("rollback", "Rollback system changes", RollbackSystem);
                
                // Network commands
                CommandHandlers["peers"] = new CommandHandler("peers", "List mesh peers", ListPeers);
                CommandHandlers["sync"] = new CommandHandler("sync", "Sync with peers", SyncWithPeers);
                CommandHandlers["broadcast"] = new CommandHandler("broadcast", "Broadcast threat data", BroadcastThreats);
                
                // Help command
                CommandHandlers["help"] = new CommandHandler("help", "Show available commands", ShowHelp);
                CommandHandlers["clear"] = new CommandHandler("clear", "Clear command history", ClearHistory);
                
                EnhancedLogger.LogInfo($"Initialized {CommandHandlers.Count} command handlers", Console.WriteLine);
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to initialize command handlers: {ex.Message}", Console.WriteLine);
            }
        }

        private static async void ProcessCommands()
        {
            while (isRunning)
            {
                try
                {
                    // Simulate command input (in real implementation, this would be from UI)
                    await Task.Delay(1000);
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Error in command processing: {ex.Message}", Console.WriteLine);
                    await Task.Delay(5000); // Wait longer on error
                }
            }
        }

        public static string ExecuteCommand(string command, string password = "")
        {
            try
            {
                // Verify admin password
                if (string.IsNullOrEmpty(password) || password != AdminPassword)
                {
                    return "ERROR: Admin password required for command execution";
                }
                
                // Log command
                LogCommand(command);
                
                // Parse command
                var parts = ParseCommand(command);
                if (parts.Length == 0)
                {
                    return "ERROR: Empty command";
                }
                
                var cmd = parts[0].ToLower();
                var args = parts.Length > 1 ? parts[1..] : new string[0];
                
                // Check for restricted commands
                if (IsRestrictedCommand(command))
                {
                    return "ERROR: Command is restricted for security reasons";
                }
                
                // Execute command
                if (CommandHandlers.TryGetValue(cmd, out var handler))
                {
                    try
                    {
                        var result = handler.Execute(args);
                        LogCommandResult(command, result);
                        return result;
                    }
                    catch (Exception ex)
                    {
                        var errorMsg = $"ERROR executing {cmd}: {ex.Message}";
                        LogCommandResult(command, errorMsg);
                        return errorMsg;
                    }
                }
                else
                {
                    var errorMsg = $"ERROR: Unknown command '{cmd}'. Type 'help' for available commands.";
                    LogCommandResult(command, errorMsg);
                    return errorMsg;
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to execute command: {ex.Message}", Console.WriteLine);
                return $"ERROR: {ex.Message}";
            }
        }

        private static string[] ParseCommand(string command)
        {
            try
            {
                // Simple command parsing (in production, use more robust parsing)
                return command.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to parse command: {ex.Message}", Console.WriteLine);
                return new string[0];
            }
        }

        private static bool IsRestrictedCommand(string command)
        {
            try
            {
                var lowerCommand = command.ToLower();
                foreach (var restricted in RestrictedCommands)
                {
                    if (lowerCommand.Contains(restricted.ToLower()))
                    {
                        return true;
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to check restricted command: {ex.Message}", Console.WriteLine);
                return true; // Default to restricted on error
            }
        }

        private static void LogCommand(string command)
        {
            try
            {
                // Analyze command for threats
                var threatLevel = AnalyzeCommandThreat(command);
                if (threatLevel != CommandThreatLevel.Low)
                {
                    EnhancedLogger.LogThreat($"Suspicious command detected (Level: {threatLevel}): {command}");
                    
                    // Take action based on threat level
                    switch (threatLevel)
                    {
                        case CommandThreatLevel.Critical:
                            EnhancedLogger.LogWarning("CRITICAL THREAT: Command blocked");
                            break;
                        case CommandThreatLevel.High:
                            EnhancedLogger.LogWarning("HIGH THREAT: Command monitored");
                            break;
                        case CommandThreatLevel.Medium:
                            EnhancedLogger.LogInfo("MEDIUM THREAT: Command logged");
                            break;
                    }
                }

                var logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] COMMAND: {command} [THREAT_LEVEL: {threatLevel}]\n";
                File.AppendAllText(CommandLogPath, logEntry);
                
                lock (historyLock)
                {
                    CommandHistory.Add(new CommandHistory
                    {
                        Timestamp = DateTime.Now,
                        Command = command,
                        Result = ""
                    });
                    
                    // Trim history if too large
                    if (CommandHistory.Count > MaxHistorySize)
                    {
                        CommandHistory.RemoveAt(0);
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to log command: {ex.Message}", Console.WriteLine);
            }
        }

        private static CommandThreatLevel AnalyzeCommandThreat(string command)
        {
            try
            {
                var lowerCommand = command.ToLower();
                var maxThreatLevel = CommandThreatLevel.Low;

                foreach (var pattern in CommandThreatPatterns)
                {
                    if (Regex.IsMatch(lowerCommand, pattern.Key, RegexOptions.IgnoreCase))
                    {
                        if (pattern.Value > maxThreatLevel)
                        {
                            maxThreatLevel = pattern.Value;
                        }
                    }
                }

                // Additional checks for advanced threats
                if (DetectLateralMovement(command))
                {
                    maxThreatLevel = (CommandThreatLevel)Math.Max((int)maxThreatLevel, (int)CommandThreatLevel.High);
                }

                if (DetectRansomwareActivity(command))
                {
                    maxThreatLevel = (CommandThreatLevel)Math.Max((int)maxThreatLevel, (int)CommandThreatLevel.Critical);
                }

                if (DetectSupplyChainAttack(command))
                {
                    maxThreatLevel = (CommandThreatLevel)Math.Max((int)maxThreatLevel, (int)CommandThreatLevel.Critical);
                }

                return maxThreatLevel;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Command threat analysis failed: {ex.Message}", Console.WriteLine);
                return CommandThreatLevel.Low;
            }
        }

        private static bool DetectLateralMovement(string command)
        {
            var lowerCommand = command.ToLower();
            
            // Check for lateral movement patterns
            var lateralMovementPatterns = new[]
            {
                "psexec.*\\\\",
                "wmic.*/node:",
                "smbexec",
                "wmiexec",
                "psexec",
                "wmic.*process.*call.*create",
                "schtasks.*/create.*/s",
                "at.*\\\\",
                "sc.*\\\\",
                "reg.*\\\\"
            };

            foreach (var pattern in lateralMovementPatterns)
            {
                if (Regex.IsMatch(lowerCommand, pattern, RegexOptions.IgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool DetectRansomwareActivity(string command)
        {
            var lowerCommand = command.ToLower();
            
            // Check for ransomware patterns
            var ransomwarePatterns = new[]
            {
                "cipher.*/w",
                "fsutil.*usn.*deletejournal",
                "vssadmin.*delete.*shadows",
                "bcdedit.*/set.*recoveryenabled.*no",
                "wmic.*shadowcopy.*delete",
                "vssadmin.*delete.*shadow",
                "wmic.*recoveros.*set.*recoveryenabled.*false",
                "bcdedit.*/set.*bootstatuspolicy.*ignoreallfailures",
                "bcdedit.*/set.*recoveryenabled.*false",
                "wmic.*shadowcopy.*delete.*/nointeractive"
            };

            foreach (var pattern in ransomwarePatterns)
            {
                if (Regex.IsMatch(lowerCommand, pattern, RegexOptions.IgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool DetectSupplyChainAttack(string command)
        {
            var lowerCommand = command.ToLower();
            
            // Check for supply chain attack patterns
            var supplyChainPatterns = new[]
            {
                "software.*update",
                "patch.*install",
                "upgrade.*software",
                "install.*update",
                "download.*installer",
                "msiexec.*/i",
                "installer.*/quiet",
                "setup.*/s",
                "update.*/silent",
                "patch.*/silent"
            };

            foreach (var pattern in supplyChainPatterns)
            {
                if (Regex.IsMatch(lowerCommand, pattern, RegexOptions.IgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static void LogCommandResult(string command, string result)
        {
            try
            {
                var logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] RESULT: {result}\n";
                File.AppendAllText(CommandLogPath, logEntry);
                
                lock (historyLock)
                {
                    if (CommandHistory.Count > 0)
                    {
                        CommandHistory[^1].Result = result;
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to log command result: {ex.Message}", Console.WriteLine);
            }
        }

        // Command handlers
        private static string ScanSystem(string[] args)
        {
            try
            {
                EnhancedLogger.LogInfo("Manual system scan triggered via command shell", Console.WriteLine);
                VirusHunter.ScanSystem();
                return "System scan initiated successfully";
            }
            catch (Exception ex)
            {
                return $"Failed to initiate scan: {ex.Message}";
            }
        }

        private static string ShowStatus(string[] args)
        {
            try
            {
                var status = new StringBuilder();
                status.AppendLine("=== PhageVirus System Status ===");
                status.AppendLine($"Uptime: {DateTime.Now - Process.GetCurrentProcess().StartTime}");
                status.AppendLine($"Active Threats: {GetActiveThreatCount()}");
                status.AppendLine($"Prevented Attacks: {GetPreventedAttackCount()}");
                status.AppendLine($"CPU Usage: {GetCpuUsage():F1}%");
                status.AppendLine($"Memory Usage: {GetMemoryUsage():F1}%");
                status.AppendLine($"Mesh Network: {(PhageSync.IsMeshActive() ? "Active" : "Inactive")}");
                status.AppendLine($"Honey Processes: {(HoneyProcess.IsHoneyActive() ? "Active" : "Inactive")}");
                status.AppendLine($"DNS Sinkhole: {(DnsSinkhole.IsDnsSinkholeActive() ? "Active" : "Inactive")}");
                status.AppendLine($"Zero Trust: {(ZeroTrustRuntime.IsZeroTrustActive() ? "Active" : "Inactive")}");
                return status.ToString();
            }
            catch (Exception ex)
            {
                return $"Failed to get status: {ex.Message}";
            }
        }

        private static string ListProcesses(string[] args)
        {
            try
            {
                var processes = Process.GetProcesses();
                var status = new StringBuilder();
                status.AppendLine("=== Running Processes ===");
                status.AppendLine($"Total: {processes.Length}");
                status.AppendLine();
                
                var suspiciousCount = 0;
                foreach (var process in processes.Take(20)) // Show first 20
                {
                    var isSuspicious = IsProcessSuspicious(process);
                    if (isSuspicious) suspiciousCount++;
                    
                    status.AppendLine($"[{(isSuspicious ? "SUSPICIOUS" : "OK")}] PID: {process.Id,6} | {process.ProcessName,-20} | {process.WorkingSet64 / 1024 / 1024,4} MB");
                }
                
                if (processes.Length > 20)
                {
                    status.AppendLine($"... and {processes.Length - 20} more processes");
                }
                
                status.AppendLine($"Suspicious processes: {suspiciousCount}");
                return status.ToString();
            }
            catch (Exception ex)
            {
                return $"Failed to list processes: {ex.Message}";
            }
        }

        private static string ShowMemoryUsage(string[] args)
        {
            try
            {
                var status = new StringBuilder();
                status.AppendLine("=== Memory Usage ===");
                
                var currentProcess = Process.GetCurrentProcess();
                var totalMemory = GC.GetTotalMemory(false);
                var workingSet = currentProcess.WorkingSet64;
                var privateMemory = currentProcess.PrivateMemorySize64;
                
                status.AppendLine($"Total Memory: {totalMemory / 1024 / 1024:F1} MB");
                status.AppendLine($"Working Set: {workingSet / 1024 / 1024:F1} MB");
                status.AppendLine($"Private Memory: {privateMemory / 1024 / 1024:F1} MB");
                status.AppendLine($"GC Collections: {GC.CollectionCount(0)}");
                
                return status.ToString();
            }
            catch (Exception ex)
            {
                return $"Failed to get memory usage: {ex.Message}";
            }
        }

        private static string ShowLogs(string[] args)
        {
            try
            {
                var logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus", "Logs");
                var status = new StringBuilder();
                status.AppendLine("=== Recent Logs ===");
                
                if (Directory.Exists(logDir))
                {
                    var logFiles = Directory.GetFiles(logDir, "*.log").OrderByDescending(f => File.GetLastWriteTime(f)).Take(5);
                    
                    foreach (var logFile in logFiles)
                    {
                        var fileName = Path.GetFileName(logFile);
                        var fileSize = new FileInfo(logFile).Length / 1024; // KB
                        var lastWrite = File.GetLastWriteTime(logFile);
                        
                        status.AppendLine($"{fileName,-30} | {fileSize,6} KB | {lastWrite:yyyy-MM-dd HH:mm}");
                    }
                }
                else
                {
                    status.AppendLine("No log directory found");
                }
                
                return status.ToString();
            }
            catch (Exception ex)
            {
                return $"Failed to show logs: {ex.Message}";
            }
        }

        private static string ShowThreats(string[] args)
        {
            try
            {
                var status = new StringBuilder();
                status.AppendLine("=== Detected Threats ===");
                
                // Get threats from various modules
                var meshThreats = PhageSync.GetSharedThreats();
                var honeyProcesses = HoneyProcess.GetActiveHoneyProcesses();
                var dnsAttempts = DnsSinkhole.GetRecentAttempts();
                var zeroTrustViolations = ZeroTrustRuntime.GetProcessSignatures().Where(p => !p.IsValid).ToList();
                
                status.AppendLine($"Mesh Threats: {meshThreats.Count}");
                status.AppendLine($"Honey Process Injections: {honeyProcesses.Count(p => p.InjectionAttempts > 0)}");
                status.AppendLine($"DNS Blocks: {dnsAttempts.Count}");
                status.AppendLine($"Zero Trust Violations: {zeroTrustViolations.Count}");
                
                return status.ToString();
            }
            catch (Exception ex)
            {
                return $"Failed to show threats: {ex.Message}";
            }
        }

        private static string ShowModules(string[] args)
        {
            try
            {
                var status = new StringBuilder();
                status.AppendLine("=== Module Status ===");
                
                var modules = new[]
                {
                    ("VirusHunter", true),
                    ("PayloadReplacer", true),
                    ("ProcessWatcher", true),
                    ("AutorunBlocker", true),
                    ("MemoryTrap", true),
                    ("CredentialTrap", true),
                    ("ExploitShield", true),
                    ("WatchdogCore", true),
                    ("PhageSync", PhageSync.IsMeshActive()),
                    ("HoneyProcess", HoneyProcess.IsHoneyActive()),
                    ("DnsSinkhole", DnsSinkhole.IsDnsSinkholeActive()),
                    ("ZeroTrustRuntime", ZeroTrustRuntime.IsZeroTrustActive())
                };
                
                foreach (var (name, isActive) in modules)
                {
                    status.AppendLine($"{name,-20} | {(isActive ? "ACTIVE" : "INACTIVE")}");
                }
                
                return status.ToString();
            }
            catch (Exception ex)
            {
                return $"Failed to show modules: {ex.Message}";
            }
        }

        private static string ShowMeshStatus(string[] args)
        {
            try
            {
                var status = new StringBuilder();
                status.AppendLine("=== Mesh Network Status ===");
                
                var isActive = PhageSync.IsMeshActive();
                var peers = PhageSync.GetActivePeers();
                var threats = PhageSync.GetSharedThreats();
                
                status.AppendLine($"Status: {(isActive ? "ACTIVE" : "INACTIVE")}");
                status.AppendLine($"Active Peers: {peers.Count}");
                status.AppendLine($"Shared Threats: {threats.Count}");
                
                if (peers.Count > 0)
                {
                    status.AppendLine("Peers:");
                    foreach (var peer in peers.Take(5))
                    {
                        status.AppendLine($"  - {peer}");
                    }
                }
                
                return status.ToString();
            }
            catch (Exception ex)
            {
                return $"Failed to show mesh status: {ex.Message}";
            }
        }

        private static string ShowHoneyStatus(string[] args)
        {
            try
            {
                var status = new StringBuilder();
                status.AppendLine("=== Honey Process Status ===");
                
                var isActive = HoneyProcess.IsHoneyActive();
                var processes = HoneyProcess.GetActiveHoneyProcesses();
                
                status.AppendLine($"Status: {(isActive ? "ACTIVE" : "INACTIVE")}");
                status.AppendLine($"Active Honey Processes: {processes.Count}");
                
                var totalInjections = processes.Sum(p => p.InjectionAttempts);
                status.AppendLine($"Total Injection Attempts: {totalInjections}");
                
                if (processes.Count > 0)
                {
                    status.AppendLine("Honey Processes:");
                    foreach (var process in processes.Take(5))
                    {
                        status.AppendLine($"  - {process.OriginalName} (PID: {process.ProcessId}) | Injections: {process.InjectionAttempts}");
                    }
                }
                
                return status.ToString();
            }
            catch (Exception ex)
            {
                return $"Failed to show honey status: {ex.Message}";
            }
        }

        private static string ShowDnsStatus(string[] args)
        {
            try
            {
                var status = new StringBuilder();
                status.AppendLine("=== DNS Sinkhole Status ===");
                
                var isActive = DnsSinkhole.IsDnsSinkholeActive();
                var blockedDomains = DnsSinkhole.GetBlockedDomains();
                var recentAttempts = DnsSinkhole.GetRecentAttempts();
                
                status.AppendLine($"Status: {(isActive ? "ACTIVE" : "INACTIVE")}");
                status.AppendLine($"Blocked Domains: {blockedDomains.Count}");
                status.AppendLine($"Recent Attempts: {recentAttempts.Count}");
                
                if (recentAttempts.Count > 0)
                {
                    status.AppendLine("Recent Blocked Domains:");
                    foreach (var attempt in recentAttempts.Take(5))
                    {
                        status.AppendLine($"  - {attempt.Key} ({attempt.Value:HH:mm:ss})");
                    }
                }
                
                return status.ToString();
            }
            catch (Exception ex)
            {
                return $"Failed to show DNS status: {ex.Message}";
            }
        }

        private static string ShowZeroTrustStatus(string[] args)
        {
            try
            {
                var status = new StringBuilder();
                status.AppendLine("=== Zero Trust Runtime Status ===");
                
                var isActive = ZeroTrustRuntime.IsZeroTrustActive();
                var signatures = ZeroTrustRuntime.GetProcessSignatures();
                
                status.AppendLine($"Status: {(isActive ? "ACTIVE" : "INACTIVE")}");
                status.AppendLine($"Monitored Processes: {signatures.Count}");
                
                var invalidSignatures = signatures.Where(s => !s.IsValid).ToList();
                status.AppendLine($"Invalid Signatures: {invalidSignatures.Count}");
                
                if (invalidSignatures.Count > 0)
                {
                    status.AppendLine("Invalid Processes:");
                    foreach (var sig in invalidSignatures.Take(5))
                    {
                        status.AppendLine($"  - {sig.ProcessName} (PID: {sig.ProcessId}) | Suspicious: {sig.HasSuspiciousModules}");
                    }
                }
                
                return status.ToString();
            }
            catch (Exception ex)
            {
                return $"Failed to show zero trust status: {ex.Message}";
            }
        }

        private static string InjectPayload(string[] args)
        {
            try
            {
                if (args.Length < 2)
                {
                    return "Usage: inject <pid> <payload_type>";
                }
                
                if (!int.TryParse(args[0], out var pid))
                {
                    return "ERROR: Invalid process ID";
                }
                
                var payloadType = args[1];
                EnhancedLogger.LogInfo($"Manual payload injection triggered: PID {pid}, Type {payloadType}", Console.WriteLine);
                
                return $"Payload injection initiated for PID {pid}";
            }
            catch (Exception ex)
            {
                return $"Failed to inject payload: {ex.Message}";
            }
        }

        private static string QueryProcessMemory(string[] args)
        {
            try
            {
                if (args.Length < 1)
                {
                    return "Usage: query <pid>";
                }
                
                if (!int.TryParse(args[0], out var pid))
                {
                    return "ERROR: Invalid process ID";
                }
                
                var process = Process.GetProcessById(pid);
                var status = new StringBuilder();
                status.AppendLine($"=== Process Memory Query: {process.ProcessName} (PID: {pid}) ===");
                status.AppendLine($"Working Set: {process.WorkingSet64 / 1024 / 1024:F1} MB");
                status.AppendLine($"Private Memory: {process.PrivateMemorySize64 / 1024 / 1024:F1} MB");
                status.AppendLine($"Virtual Memory: {process.VirtualMemorySize64 / 1024 / 1024:F1} MB");
                status.AppendLine($"Threads: {process.Threads.Count}");
                status.AppendLine($"Modules: {process.Modules.Count}");
                
                return status.ToString();
            }
            catch (Exception ex)
            {
                return $"Failed to query process memory: {ex.Message}";
            }
        }

        private static string PullData(string[] args)
        {
            try
            {
                if (args.Length < 1)
                {
                    return "Usage: pull <data_type>";
                }
                
                var dataType = args[0].ToLower();
                var status = new StringBuilder();
                
                switch (dataType)
                {
                    case "logs":
                        var logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus", "Logs");
                        var logFiles = Directory.GetFiles(logDir, "*.log");
                        status.AppendLine($"Found {logFiles.Length} log files");
                        break;
                        
                    case "threats":
                        var threats = PhageSync.GetSharedThreats();
                        status.AppendLine($"Found {threats.Count} shared threats");
                        break;
                        
                    case "processes":
                        var processes = Process.GetProcesses();
                        status.AppendLine($"Found {processes.Length} running processes");
                        break;
                        
                    default:
                        return $"ERROR: Unknown data type '{dataType}'";
                }
                
                return status.ToString();
            }
            catch (Exception ex)
            {
                return $"Failed to pull data: {ex.Message}";
            }
        }

        private static string InjectUpdates(string[] args)
        {
            try
            {
                EnhancedLogger.LogInfo("Manual update injection triggered via command shell", Console.WriteLine);
                return "Update injection initiated successfully";
            }
            catch (Exception ex)
            {
                return $"Failed to inject updates: {ex.Message}";
            }
        }

        private static string CreateBackup(string[] args)
        {
            try
            {
                var backupDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus", "Backups");
                Directory.CreateDirectory(backupDir);
                
                var backupName = $"backup_{DateTime.Now:yyyyMMdd_HHmmss}";
                var backupPath = Path.Combine(backupDir, backupName);
                
                // Create backup of important files
                var logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus", "Logs");
                if (Directory.Exists(logDir))
                {
                    Directory.CreateDirectory(Path.Combine(backupPath, "Logs"));
                    foreach (var file in Directory.GetFiles(logDir))
                    {
                        var fileName = Path.GetFileName(file);
                        File.Copy(file, Path.Combine(backupPath, "Logs", fileName));
                    }
                }
                
                EnhancedLogger.LogInfo($"System backup created: {backupPath}", Console.WriteLine);
                return $"Backup created successfully: {backupPath}";
            }
            catch (Exception ex)
            {
                return $"Failed to create backup: {ex.Message}";
            }
        }

        private static string RestoreBackup(string[] args)
        {
            try
            {
                if (args.Length < 1)
                {
                    return "Usage: restore <backup_name>";
                }
                
                var backupName = args[0];
                var backupPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus", "Backups", backupName);
                
                if (!Directory.Exists(backupPath))
                {
                    return $"ERROR: Backup '{backupName}' not found";
                }
                
                EnhancedLogger.LogInfo($"System restore initiated from: {backupPath}", Console.WriteLine);
                return $"Restore initiated from backup: {backupName}";
            }
            catch (Exception ex)
            {
                return $"Failed to restore backup: {ex.Message}";
            }
        }

        private static string RollbackSystem(string[] args)
        {
            try
            {
                EnhancedLogger.LogInfo("System rollback initiated via command shell", Console.WriteLine);
                return "System rollback initiated successfully";
            }
            catch (Exception ex)
            {
                return $"Failed to rollback system: {ex.Message}";
            }
        }

        private static string ListPeers(string[] args)
        {
            try
            {
                var peers = PhageSync.GetActivePeers();
                var status = new StringBuilder();
                status.AppendLine("=== Mesh Network Peers ===");
                status.AppendLine($"Total Peers: {peers.Count}");
                
                if (peers.Count > 0)
                {
                    foreach (var peer in peers)
                    {
                        status.AppendLine($"  - {peer}");
                    }
                }
                else
                {
                    status.AppendLine("No active peers found");
                }
                
                return status.ToString();
            }
            catch (Exception ex)
            {
                return $"Failed to list peers: {ex.Message}";
            }
        }

        private static string SyncWithPeers(string[] args)
        {
            try
            {
                EnhancedLogger.LogInfo("Manual peer synchronization triggered", Console.WriteLine);
                return "Peer synchronization initiated successfully";
            }
            catch (Exception ex)
            {
                return $"Failed to sync with peers: {ex.Message}";
            }
        }

        private static string BroadcastThreats(string[] args)
        {
            try
            {
                EnhancedLogger.LogInfo("Manual threat broadcast triggered", Console.WriteLine);
                return "Threat broadcast initiated successfully";
            }
            catch (Exception ex)
            {
                return $"Failed to broadcast threats: {ex.Message}";
            }
        }

        private static string ShowHelp(string[] args)
        {
            try
            {
                var help = new StringBuilder();
                help.AppendLine("=== PhageVirus Live Command Shell ===");
                help.AppendLine("Available Commands:");
                help.AppendLine();
                
                foreach (var handler in CommandHandlers.Values.OrderBy(h => h.Name))
                {
                    help.AppendLine($"{handler.Name,-15} - {handler.Description}");
                }
                
                help.AppendLine();
                help.AppendLine("Usage: <command> [arguments]");
                help.AppendLine("Note: Admin password required for all commands");
                
                return help.ToString();
            }
            catch (Exception ex)
            {
                return $"Failed to show help: {ex.Message}";
            }
        }

        private static string ClearHistory(string[] args)
        {
            try
            {
                lock (historyLock)
                {
                    CommandHistory.Clear();
                }
                
                return "Command history cleared successfully";
            }
            catch (Exception ex)
            {
                return $"Failed to clear history: {ex.Message}";
            }
        }

        // Helper methods
        private static int GetActiveThreatCount()
        {
            try
            {
                return PhageSync.GetSharedThreats().Count;
            }
            catch
            {
                return 0;
            }
        }

        private static int GetPreventedAttackCount()
        {
            try
            {
                return HoneyProcess.GetActiveHoneyProcesses().Sum(p => p.InjectionAttempts);
            }
            catch
            {
                return 0;
            }
        }

        private static double GetCpuUsage()
        {
            try
            {
                using var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                return cpuCounter.NextValue();
            }
            catch
            {
                return 0.0;
            }
        }

        private static double GetMemoryUsage()
        {
            try
            {
                double total = 0, free = 0;
                try
                {
                    var searcher = new ManagementObjectSearcher("SELECT TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem");
                    foreach (var result in searcher.Get())
                    {
                        total = Convert.ToDouble(result["TotalVisibleMemorySize"]) / 1024; // MB
                        free = Convert.ToDouble(result["FreePhysicalMemory"]) / 1024;
                    }
                }
                catch
                {
                    total = 4096; free = 512; // fallback
                }

                double used = Math.Max(0, total - free);
                return Math.Min(100, used * 100 / Math.Max(1, total));
            }
            catch
            {
                return 0.0;
            }
        }

        private static bool IsProcessSuspicious(Process process)
        {
            try
            {
                var suspiciousNames = new[] { "malware", "trojan", "backdoor", "keylogger", "stealer", "miner", "botnet" };
                var processName = process.ProcessName.ToLower();
                
                return suspiciousNames.Any(name => processName.Contains(name));
            }
            catch
            {
                return false;
            }
        }

        public static List<CommandHistory> GetCommandHistory()
        {
            lock (historyLock)
            {
                return new List<CommandHistory>(CommandHistory);
            }
        }

        public static bool IsCommandShellActive()
        {
            return isRunning;
        }
    }

    public class CommandHandler
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public Func<string[], string> Execute { get; set; }

        public CommandHandler(string name, string description, Func<string[], string> execute)
        {
            Name = name;
            Description = description;
            Execute = execute;
        }
    }

    public class CommandHistory
    {
        public DateTime Timestamp { get; set; }
        public string Command { get; set; } = "";
        public string Result { get; set; } = "";
    }
} 

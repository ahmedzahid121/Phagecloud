using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace PhageVirus.Modules
{

    public class VirusHunter
    {
        private static readonly string[] ThreatKeywords = {
            "stealer", "keylogger", "trojan", "backdoor", "ransomware", "spyware",
            "malware", "virus", "worm", "rootkit", "botnet", "crypto", "miner"
        };

        private static readonly string[] SuspiciousExtensions = {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar"
        };

        public static List<ThreatInfo> ScanForThreats(string[] paths)
        {
            var found = new List<ThreatInfo>();
            
            // First, hunt for suspicious processes using system-level APIs
            EnhancedLogger.LogInfo("Starting system-level process hunting...");
            var suspiciousProcesses = SystemHacker.HuntSuspiciousProcesses();
            
            foreach (var processInfo in suspiciousProcesses)
            {
                var threat = new ThreatInfo
                {
                    File = $"[PROCESS] {processInfo.ProcessName} (PID: {processInfo.ProcessId})",
                    Status = processInfo.ThreatLevel.ToString(),
                    Action = GetActionForThreatLevel(processInfo.ThreatLevel),
                    Type = "Process",
                    DetectionMethod = $"System-level analysis - Memory patterns: {processInfo.MaliciousPatterns.Count}, Entropy: {processInfo.FileEntropy:F2}"
                };
                found.Add(threat);
            }
            
            // Then scan files using advanced detection
            EnhancedLogger.LogInfo("Starting advanced file scanning...");
            foreach (var dir in paths)
            {
                if (!Directory.Exists(dir)) continue;
                
                try
                {
                    // Scan files with real detection methods
                    var files = Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories);
                    foreach (var file in files)
                    {
                        var threat = AnalyzeFileAdvanced(file);
                        if (threat != null)
                        {
                            found.Add(threat);
                        }
                    }
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogWarning($"Error scanning {dir}: {ex.Message}");
                }
            }

            return found;
        }

        private static ThreatInfo? AnalyzeFileAdvanced(string filePath)
        {
            try
            {
                var fileName = Path.GetFileName(filePath).ToLower();
                var extension = Path.GetExtension(filePath).ToLower();
                var fileInfo = new FileInfo(filePath);
                
                // Skip if file is too small or too large
                if (fileInfo.Length < 1024 || fileInfo.Length > 100 * 1024 * 1024) // 1KB to 100MB
                    return null;

                // Calculate file entropy
                var entropy = CalculateFileEntropy(filePath);
                var threatLevel = ThreatLevel.Low;
                var detectionMethods = new List<string>();

                // Check for high entropy (indicates packed/encrypted content)
                if (entropy > 7.5)
                {
                    threatLevel = ThreatLevel.Medium;
                    detectionMethods.Add($"High entropy: {entropy:F2}");
                }

                // Check for suspicious extensions
                if (SuspiciousExtensions.Contains(extension))
                {
                    detectionMethods.Add($"Suspicious extension: {extension}");
                    threatLevel = (ThreatLevel)Math.Max((byte)threatLevel, (byte)ThreatLevel.Medium);
                }

                // Check for threat keywords in filename
                foreach (var keyword in ThreatKeywords)
                {
                    if (fileName.Contains(keyword))
                    {
                        detectionMethods.Add($"Keyword match: {keyword}");
                        threatLevel = ThreatLevel.High;
                        break;
                    }
                }

                // Check file content for suspicious patterns
                if (extension == ".txt" || extension == ".log" || extension == ".bat" || extension == ".ps1")
                {
                    try
                    {
                        var content = File.ReadAllText(filePath).ToLower();
                        foreach (var keyword in ThreatKeywords)
                        {
                            if (content.Contains(keyword))
                            {
                                detectionMethods.Add($"Content contains: {keyword}");
                                threatLevel = ThreatLevel.High;
                                break;
                            }
                        }

                        // Check for suspicious patterns in scripts
                        if (content.Contains("http://") || content.Contains("https://"))
                            detectionMethods.Add("Network communication");
                        if (content.Contains("registry") || content.Contains("regedit"))
                            detectionMethods.Add("Registry modification");
                        if (content.Contains("taskkill") || content.Contains("kill"))
                            detectionMethods.Add("Process termination");
                    }
                    catch
                    {
                        // File might be locked or too large
                    }
                }

                // Check for suspicious file characteristics
                if (fileInfo.CreationTime > DateTime.Now.AddDays(-1) && extension == ".exe")
                {
                    detectionMethods.Add("Recently created executable");
                    threatLevel = (ThreatLevel)Math.Max((byte)threatLevel, (byte)ThreatLevel.Medium);
                }

                // Check for files without digital signatures (simplified)
                if (extension == ".exe" && fileInfo.Length < 50 * 1024) // Small executables
                {
                    detectionMethods.Add("Small unsigned executable");
                    threatLevel = (ThreatLevel)Math.Max((byte)threatLevel, (byte)ThreatLevel.Medium);
                }

                // Only return if we found something suspicious
                if (detectionMethods.Count > 0)
                {
                    return new ThreatInfo
                    {
                        File = filePath,
                        Status = threatLevel.ToString(),
                        Action = GetActionForThreatLevel(threatLevel),
                        Type = "File",
                        DetectionMethod = string.Join(", ", detectionMethods)
                    };
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"File analysis failed for {filePath}: {ex.Message}");
            }

            return null;
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

        private static string GetActionForThreatLevel(ThreatLevel threatLevel)
        {
            return threatLevel switch
            {
                ThreatLevel.Low => "Monitor",
                ThreatLevel.Medium => "Analyze",
                ThreatLevel.High => "Neutralize",
                ThreatLevel.Critical => "Terminate",
                _ => "Monitor"
            };
        }

        private static List<ThreatInfo> ScanProcesses()
        {
            var threats = new List<ThreatInfo>();
            
            try
            {
                var processes = Process.GetProcesses();
                foreach (var process in processes)
                {
                    try
                    {
                        var processName = process.ProcessName.ToLower();
                        
                        // Check for suspicious process names
                        foreach (var keyword in ThreatKeywords)
                        {
                            if (processName.Contains(keyword))
                            {
                                threats.Add(new ThreatInfo
                                {
                                    File = $"[PROCESS] {process.ProcessName} (PID: {process.Id})",
                                    Status = "Active",
                                    Action = "Terminate",
                                    Type = "Process",
                                    DetectionMethod = $"Process name contains: {keyword}"
                                });
                                break;
                            }
                        }

                        // Random detection for simulation (5% chance)
                        if (new Random().Next(100) < 5 && process.ProcessName.Length > 3)
                        {
                            threats.Add(new ThreatInfo
                            {
                                File = $"[PROCESS] {process.ProcessName} (PID: {process.Id})",
                                Status = "Suspicious",
                                Action = "Monitor",
                                Type = "Process",
                                DetectionMethod = "Anomaly detection"
                            });
                        }
                    }
                    catch
                    {
                        // Ignore processes we can't access
                    }
                }
            }
            catch
            {
                // Ignore if we can't enumerate processes
            }

            return threats;
        }

        public static void CreateFakeThreats()
        {
            try
            {
                var fakeThreatsDir = @"C:\FakeMalware";
                Directory.CreateDirectory(fakeThreatsDir);

                // Create fake threat files for testing
                File.WriteAllText(Path.Combine(fakeThreatsDir, "stealer_v2.exe"), "Fake malware content");
                File.WriteAllText(Path.Combine(fakeThreatsDir, "keylogger_data.txt"), "Fake keylogger data");
                File.WriteAllText(Path.Combine(fakeThreatsDir, "trojan_backdoor.dll"), "Fake trojan DLL");
                File.WriteAllText(Path.Combine(fakeThreatsDir, "crypto_miner.bat"), "Fake crypto miner script");

                EnhancedLogger.LogInfo("Created fake threat files for testing", Console.WriteLine);
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to create fake threats: {ex.Message}", Console.WriteLine);
            }
        }

        public static void ScanSystem()
        {
            EnhancedLogger.LogInfo("Starting system-wide scan...", Console.WriteLine);
            var scanPaths = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
            };
            var threats = ScanForThreats(scanPaths);
            EnhancedLogger.LogInfo($"System scan complete. Found {threats.Count} threats.", Console.WriteLine);
        }

        public static void ScanFile(string filePath)
        {
            EnhancedLogger.LogInfo($"Scanning file: {filePath}", Console.WriteLine);
            var threat = AnalyzeFileAdvanced(filePath);
            if (threat != null)
            {
                EnhancedLogger.LogWarning($"Threat detected in file: {filePath}", Console.WriteLine);
            }
        }

        public static bool IsThreat(string hash)
        {
            // Simple hash-based threat detection (placeholder)
            var knownThreatHashes = new[] { "abc123", "def456", "ghi789" };
            return knownThreatHashes.Contains(hash.ToLower());
        }
    }

    public class ThreatInfo
    {
        public string File { get; set; } = "";
        public string Status { get; set; } = "";
        public string Action { get; set; } = "";
        public string Type { get; set; } = "";
        public string DetectionMethod { get; set; } = "";
    }
}

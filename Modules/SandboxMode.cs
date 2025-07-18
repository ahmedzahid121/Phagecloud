using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace PhageVirus.Modules
{
    public class SandboxMode
    {
        private static readonly string[] WatchedFolders = {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Temp"),
            @"C:\Users\Public\Downloads",
            @"C:\Windows\Temp"
        };

        private static readonly string[] BlockedExtensions = {
            ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".jar", ".msi", ".scr", ".pif", ".com"
        };

        private static readonly string[] AllowedExtensions = {
            ".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
            ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".zip", ".rar", ".7z", ".tar", ".gz"
        };

        private static readonly HashSet<string> WhitelistedFiles = new(StringComparer.OrdinalIgnoreCase)
        {
            // Common legitimate executables
            "notepad.exe", "calc.exe", "mspaint.exe", "wordpad.exe", "explorer.exe", "cmd.exe",
            "powershell.exe", "powershell_ise.exe", "regedit.exe", "msconfig.exe", "taskmgr.exe",
            "control.exe", "appwiz.cpl", "sysdm.cpl", "firewall.cpl", "ncpa.cpl", "inetcpl.cpl",
            
            // PhageVirus replica files
            "phagevirus.exe", "systemmonitor.exe", "replicaclient.exe", "securityservice.exe",
            "phagenode.exe", "phage_sync.exe", "phage_hunter.exe", "phage_defender.exe"
        };

        private static readonly HashSet<string> WhitelistedPaths = new(StringComparer.OrdinalIgnoreCase)
        {
            @"C:\Windows\System32",
            @"C:\Windows\SysWOW64",
            @"C:\Program Files",
            @"C:\Program Files (x86)",
            @"C:\Windows\System32\WindowsPowerShell\v1.0"
        };

        private static readonly Dictionary<string, string> FileSignatures = new()
        {
            // Common file signatures (magic numbers)
            { "MZ", ".exe" },           // DOS executable
            { "PK", ".zip" },           // ZIP archive
            { "Rar!", ".rar" },         // RAR archive
            { "7F454C46", ".elf" },     // ELF executable
            { "C0DECAFE", ".class" },   // Java class
            { "504B0304", ".docx" },    // Office Open XML
            { "D0CF11E0", ".doc" },     // Office document
            { "25504446", ".pdf" },     // PDF document
            { "FFFE", ".txt" },         // UTF-16 text
            { "FFFE0000", ".txt" }      // UTF-32 text
        };

        private static bool isActive = false;
        private static readonly object sandboxLock = new object();
        private static FileSystemWatcher? fileWatcher;

        public static void EnableSandboxMode()
        {
            if (isActive) return;

            lock (sandboxLock)
            {
                if (isActive) return;

                try
                {
                    EnhancedLogger.LogInfo("Enabling sandbox mode...");
                    
                    // Start file system monitoring
                    StartFileMonitoring();
                    
                    // Perform initial scan of watched folders
                    Task.Run(() => ScanWatchedFolders());
                    
                    isActive = true;
                    EnhancedLogger.LogSuccess("Sandbox mode activated - monitoring high-risk folders");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to enable sandbox mode: {ex.Message}");
                }
            }
        }

        public static void DisableSandboxMode()
        {
            lock (sandboxLock)
            {
                if (!isActive) return;

                try
                {
                    fileWatcher?.Dispose();
                    fileWatcher = null;
                    isActive = false;
                    EnhancedLogger.LogInfo("Sandbox mode disabled");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to disable sandbox mode: {ex.Message}");
                }
            }
        }

        private static void StartFileMonitoring()
        {
            try
            {
                foreach (var folder in WatchedFolders)
                {
                    if (!Directory.Exists(folder)) continue;

                    fileWatcher = new FileSystemWatcher(folder)
                    {
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime | NotifyFilters.LastWrite,
                        Filter = "*.*",
                        EnableRaisingEvents = true
                    };

                    fileWatcher.Created += OnFileCreated;
                    fileWatcher.Changed += OnFileChanged;
                    fileWatcher.Renamed += OnFileRenamed;
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"File monitoring setup failed: {ex.Message}");
            }
        }

        private static void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            Task.Run(() => AnalyzeFile(e.FullPath));
        }

        private static void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            Task.Run(() => AnalyzeFile(e.FullPath));
        }

        private static void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            Task.Run(() => AnalyzeFile(e.FullPath));
        }

        private static void AnalyzeFile(string filePath)
        {
            try
            {
                // Skip legitimate files
                if (IsLegitimateFile(filePath))
                {
                    EnhancedLogger.LogInfo($"File {Path.GetFileName(filePath)} passed sandbox analysis");
                    return;
                }

                var fileName = Path.GetFileName(filePath).ToLower();
                var extension = Path.GetExtension(filePath).ToLower();
                var fileInfo = new FileInfo(filePath);
                
                // Skip if file is too small or too large
                if (fileInfo.Length < 1024 || fileInfo.Length > 100 *124 * 124) // 1KB to 100MB
                    return;

                var threatLevel = ThreatLevel.Low;
                var reasons = new List<string>();

                // Check for high entropy (indicates packed/encrypted content)
                var entropy = CalculateFileEntropy(filePath);
                if (entropy > 7.5)
                {
                    threatLevel = ThreatLevel.Medium;
                    reasons.Add($"high entropy ({entropy:F2})");
                }

                // Check for suspicious extensions
                if (Array.IndexOf(BlockedExtensions, extension) >= 0)
                {
                    reasons.Add($"suspicious extension ({extension})");
                    threatLevel = (ThreatLevel)Math.Max((byte)threatLevel, (byte)ThreatLevel.Medium);
                }

                // Check for threat keywords in filename
                foreach (var keyword in WhitelistedFiles)
                {
                    if (fileName.Contains(keyword))
                    {
                        reasons.Add($"keyword match ({keyword})");
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
                        foreach (var keyword in WhitelistedFiles)
                        {
                            if (content.Contains(keyword))
                            {
                                reasons.Add($"content contains {keyword}");
                                threatLevel = ThreatLevel.High;
                                break;
                            }
                        }

                        // Check for suspicious patterns in scripts
                        if (content.Contains("http://") || content.Contains("https://"))
                            reasons.Add("network communication");
                        if (content.Contains("registry") || content.Contains("regedit"))
                            reasons.Add("registry modification");
                        if (content.Contains("taskkill") || content.Contains("kill"))
                            reasons.Add("process termination");
                    }
                    catch
                    {
                        // File might be locked or too large
                    }
                }

                // Check for suspicious file characteristics
                if (fileInfo.CreationTime > DateTime.Now.AddDays(-1) && extension == ".exe")
                {
                    reasons.Add("recently created executable");
                    threatLevel = (ThreatLevel)Math.Max((byte)threatLevel, (byte)ThreatLevel.Medium);
                }

                // Check for files without digital signatures (simplified)
                if (extension == ".exe" && fileInfo.Length < 504) // Small executables
                {
                    reasons.Add("small unsigned executable");
                    threatLevel = (ThreatLevel)Math.Max((byte)threatLevel, (byte)ThreatLevel.Medium);
                }

                // Only quarantine if we found something suspicious
                if (reasons.Count > 0)
                {
                    var reason = string.Join(", ", reasons);
                    EnhancedLogger.LogThreat($"High entropy file detected: {Path.GetFileName(filePath)} (Entropy: {entropy:F2})");
                    EnhancedLogger.LogWarning($"Blocking file: {Path.GetFileName(filePath)} - Reason: {reason}");
                    BlockFile(filePath, reason);
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"File analysis failed for {filePath}: {ex.Message}");
            }
        }

        private static bool ShouldBlockFile(string filePath)
        {
            try
            {
                var fileName = Path.GetFileName(filePath).ToLower();
                var directory = Path.GetDirectoryName(filePath)?.ToLower() ?? "";

                // Check whitelist
                if (WhitelistedFiles.Contains(fileName))
                    return false;

                // Check if file is in a whitelisted path
                foreach (var whitelistedPath in WhitelistedPaths)
                {
                    if (directory.StartsWith(whitelistedPath.ToLower()))
                        return false;
                }

                // Check if file is digitally signed (simplified check)
                if (IsDigitallySigned(filePath))
                    return false;

                // Check file age (newer files are more suspicious)
                var fileInfo = new FileInfo(filePath);
                var age = DateTime.Now - fileInfo.CreationTime;
                if (age.TotalMinutes < 5) // Very new file
                    return true;

                return true; // Block by default
            }
            catch
            {
                return true; // Block if we can't analyze
            }
        }

        private static bool IsLegitimateFile(string filePath)
        {
            try
            {
                var fileName = Path.GetFileName(filePath).ToLower();
                var extension = Path.GetExtension(filePath).ToLower();
                
                // Don't quarantine PhageVirus own files
                if (fileName.Contains("phagevirus") || fileName.Contains("phage_virus"))
                {
                    return true;
                }
                
                // Whitelist PhageVirus replicas
                if (fileName.Contains("phagenode") && fileName.EndsWith(".exe"))
                    return true;
                
                if (fileName.Contains("replicaclient") && fileName.EndsWith(".exe"))
                    return true;
                
                if (fileName.Contains("systemmonitor") && fileName.EndsWith(".exe"))
                    return true;
                
                if (fileName.Contains("securityservice") && fileName.EndsWith(".exe"))
                    return true;
                
                if (fileName.Contains("phage") && fileName.EndsWith(".exe"))
                    return true;

                // Don't quarantine log files
                if (extension == ".log" || extension == ".txt")
                {
                    if (fileName.Contains("log") || fileName.Contains("report") || fileName.Contains("diagnostic"))
                    {
                        return true;
                    }
                }

                // Don't quarantine temporary files that are likely legitimate
                if (fileName.StartsWith("vmware-") || fileName.StartsWith("temp_") || fileName.Contains(".tmp"))
                {
                    return true;
                }

                // Don't quarantine system files
                if (filePath.Contains("\\Windows\\") || filePath.Contains("\\System32\\"))
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

        private static bool IsDigitallySigned(string filePath)
        {
            try
            {
                // Simplified digital signature check
                // In a real implementation, you'd use Win32 APIs to verify signatures
                var fileInfo = new FileInfo(filePath);
                
                // Check file size (signed files are typically larger)
                if (fileInfo.Length < 1024) // Very small files are suspicious
                    return false;

                // Check if file is in system directories (likely signed)
                var directory = Path.GetDirectoryName(filePath)?.ToLower() ?? "";
                if (directory.Contains("windows") || directory.Contains("program files"))
                    return true;

                return false; // Assume not signed for safety
            }
            catch
            {
                return false;
            }
        }

        private static bool HasSuspiciousSignature(string filePath)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                var buffer = new byte[8];
                var bytesRead = stream.Read(buffer, 0, buffer.Length);

                if (bytesRead < 4) return false;

                // Check for executable signatures
                var signature = BitConverter.ToString(buffer, 0, Math.Min(bytesRead, 4)).Replace("-", "");
                
                // Check for MZ header (DOS executable)
                if (buffer[0] == 0x4D && buffer[1] == 0x5A) // "MZ"
                {
                    // Additional check for PE header
                    stream.Position = 0x3C;
                    var peOffsetBytes = new byte[4];
                    if (stream.Read(peOffsetBytes, 0, 4) == 4)
                    {
                        var peOffset = BitConverter.ToInt32(peOffsetBytes, 0);
                        if (peOffset > 0 && peOffset < stream.Length - 4)
                        {
                            stream.Position = peOffset;
                            var peBytes = new byte[4];
                            if (stream.Read(peBytes, 0, 4) == 4)
                            {
                                if (peBytes[0] == 0x50 && peBytes[1] == 0x45) // "PE"
                                {
                                    return true; // Confirmed executable
                                }
                            }
                        }
                    }
                }

                // Check for other suspicious signatures
                var suspiciousSignatures = new[] { "7F454C46", "C0DECAFE", "FEEDFACE" };
                foreach (var sig in suspiciousSignatures)
                {
                    if (signature.StartsWith(sig))
                        return true;
                }

                return false;
            }
            catch
            {
                return false;
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

        private static bool ContainsSuspiciousContent(string filePath)
        {
            try
            {
                var extension = Path.GetExtension(filePath).ToLower();
                
                // Only check text-based files
                if (extension == ".txt" || extension == ".bat" || extension == ".cmd" || 
                    extension == ".ps1" || extension == ".vbs" || extension == ".js" || 
                    extension == ".hta" || extension == ".xml" || extension == ".json")
                {
                    var content = File.ReadAllText(filePath).ToLower();
                    
                    // Check for suspicious patterns
                    var suspiciousPatterns = new[]
                    {
                        @"powershell.*-enc",
                        @"Invoke-Expression",
                        @"IEX\s*\(",
                        @"http://",
                        @"https://",
                        @"\\\\",
                        @"base64",
                        @"[A-Za-z0-9+/]{20,}", // Base64-like
                        @"cmd\s+/c",
                        @"rundll32",
                        @"regsvr32",
                        @"mshta",
                        @"wscript",
                        @"cscript"
                    };

                    foreach (var pattern in suspiciousPatterns)
                    {
                        if (Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase))
                            return true;
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private static void BlockFile(string filePath, string reason)
        {
            try
            {
                EnhancedLogger.LogWarning($"Blocking file: {Path.GetFileName(filePath)} - Reason: {reason}");
                
                // Create backup
                var backupPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 
                    "PhageVirus", "Backups", $"sandbox_backup_{DateTime.Now:yyyyMMdd_HHmmss}_{Path.GetFileName(filePath)}");
                
                Directory.CreateDirectory(Path.GetDirectoryName(backupPath)!);
                File.Copy(filePath, backupPath);
                
                // Quarantine the file
                var quarantinePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 
                    "PhageVirus", "Quarantine", $"sandbox_quarantined_{DateTime.Now:yyyyMMdd_HHmmss}_{Path.GetFileName(filePath)}");
                
                Directory.CreateDirectory(Path.GetDirectoryName(quarantinePath)!);
                File.Move(filePath, quarantinePath);
                
                EnhancedLogger.LogSuccess($"Quarantined suspicious file: {Path.GetFileName(filePath)}");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to block file {filePath}: {ex.Message}");
            }
        }

        private static void ScanWatchedFolders()
        {
            try
            {
                EnhancedLogger.LogInfo("Performing initial scan of watched folders...");
                var scanCount = 0;

                foreach (var folder in WatchedFolders)
                {
                    if (!Directory.Exists(folder)) continue;

                    var files = Directory.GetFiles(folder, "*.*", SearchOption.AllDirectories);
                    foreach (var file in files)
                    {
                        scanCount++;
                        AnalyzeFile(file);
                        
                        // Limit scan to prevent overwhelming
                        if (scanCount > 1000) break;
                    }
                }

                EnhancedLogger.LogSuccess($"Initial scan complete. Scanned {scanCount} files.");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Initial folder scan failed: {ex.Message}");
            }
        }

        public static bool IsActive => isActive;
    }
} 

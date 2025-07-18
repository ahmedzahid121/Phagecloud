using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace PhageVirus.Modules
{
    public class AutorunBlocker
    {
        private static readonly string[] SuspiciousKeywords = {
            "powershell", "cmd", "mshta", "wscript", "cscript", "regsvr32", "rundll32",
            "nc.exe", "ncat", "telnet", "mimikatz", "procdump", "wce", "pwdump",
            "http://", "https://", "\\\\", "base64", "encoded", "encrypted"
        };

        private static readonly string[] SuspiciousExtensions = {
            ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".jar"
        };

        private static readonly string[] StartupLocations = {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"
        };

        private static readonly string[] StartupFolders = {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft\\Windows\\Start Menu\\Programs\\Startup")
        };

        public static void StartMonitoring()
        {
            try
            {
                EnhancedLogger.LogInfo("Starting autorun monitoring...");
                
                // Monitor registry autorun entries
                MonitorRegistryAutorun();
                
                // Monitor startup folders
                MonitorStartupFolders();
                
                // Monitor scheduled tasks
                MonitorScheduledTasks();
                
                EnhancedLogger.LogSuccess("Autorun monitoring activated");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start autorun monitoring: {ex.Message}");
            }
        }

        private static void MonitorRegistryAutorun()
        {
            try
            {
                foreach (var location in StartupLocations)
                {
                    CheckRegistryAutorun(location, Registry.CurrentUser);
                    CheckRegistryAutorun(location, Registry.LocalMachine);
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Registry autorun monitoring failed: {ex.Message}");
            }
        }

        private static void CheckRegistryAutorun(string location, RegistryKey baseKey)
        {
            try
            {
                using var key = baseKey.OpenSubKey(location);
                if (key == null) return;

                foreach (var valueName in key.GetValueNames())
                {
                    var value = key.GetValue(valueName)?.ToString() ?? "";
                    if (IsSuspiciousAutorun(value))
                    {
                        EnhancedLogger.LogThreat($"Suspicious autorun detected in registry: {location}\\{valueName} = {value}");
                        
                        // Block the suspicious autorun
                        BlockRegistryAutorun(baseKey, location, valueName, value);
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to check registry autorun {location}: {ex.Message}");
            }
        }

        private static void MonitorStartupFolders()
        {
            try
            {
                foreach (var folder in StartupFolders)
                {
                    if (!Directory.Exists(folder)) continue;

                    var files = Directory.GetFiles(folder, "*.*", SearchOption.TopDirectoryOnly);
                    foreach (var file in files)
                    {
                        if (IsSuspiciousStartupFile(file))
                        {
                            EnhancedLogger.LogThreat($"Suspicious startup file detected: {file}");
                            BlockStartupFile(file);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Startup folder monitoring failed: {ex.Message}");
            }
        }

        private static void MonitorScheduledTasks()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ScheduledJob");
                foreach (ManagementObject task in searcher.Get())
                {
                    var command = task["Command"]?.ToString() ?? "";
                    if (IsSuspiciousScheduledTask(command))
                    {
                        var taskName = task["Name"]?.ToString() ?? "Unknown";
                        EnhancedLogger.LogThreat($"Suspicious scheduled task detected: {taskName} = {command}");
                        BlockScheduledTask(task);
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Scheduled task monitoring failed: {ex.Message}");
            }
        }

        private static bool IsSuspiciousAutorun(string value)
        {
            if (string.IsNullOrEmpty(value)) return false;

            var lowerValue = value.ToLower();
            
            // Check for suspicious keywords
            foreach (var keyword in SuspiciousKeywords)
            {
                if (lowerValue.Contains(keyword.ToLower()))
                    return true;
            }

            // Check for suspicious extensions
            foreach (var ext in SuspiciousExtensions)
            {
                if (lowerValue.Contains(ext))
                {
                    // Additional check for suspicious patterns
                    if (lowerValue.Contains("http") || lowerValue.Contains("\\\\") || lowerValue.Contains("base64"))
                        return true;
                }
            }

            // Check for encoded/encrypted patterns
            if (Regex.IsMatch(value, @"[A-Za-z0-9+/]{20,}")) // Base64-like pattern
                return true;

            if (Regex.IsMatch(value, @"powershell.*-enc")) // PowerShell encoded
                return true;

            return false;
        }

        private static bool IsSuspiciousStartupFile(string filePath)
        {
            try
            {
                var fileName = Path.GetFileName(filePath).ToLower();
                var extension = Path.GetExtension(filePath).ToLower();

                // Check file extension
                if (!Array.Exists(SuspiciousExtensions, ext => ext.Equals(extension, StringComparison.OrdinalIgnoreCase)))
                    return false;

                // Check file content for suspicious patterns
                if (extension == ".lnk")
                {
                    // For shortcuts, we'd need to parse the .lnk file
                    // Simplified check for now
                    return false;
                }
                else if (extension == ".bat" || extension == ".cmd" || extension == ".ps1" || extension == ".vbs" || extension == ".js")
                {
                    // Check script content
                    var content = File.ReadAllText(filePath).ToLower();
                    foreach (var keyword in SuspiciousKeywords)
                    {
                        if (content.Contains(keyword.ToLower()))
                            return true;
                    }
                }

                // Check file entropy (for executables)
                if (extension == ".exe")
                {
                    var entropy = CalculateFileEntropy(filePath);
                    if (entropy > 7.5) // High entropy indicates packed/encrypted
                        return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private static bool IsSuspiciousScheduledTask(string command)
        {
            if (string.IsNullOrEmpty(command)) return false;

            var lowerCommand = command.ToLower();
            
            // Check for suspicious patterns in scheduled tasks
            foreach (var keyword in SuspiciousKeywords)
            {
                if (lowerCommand.Contains(keyword.ToLower()))
                    return true;
            }

            // Check for encoded commands
            if (Regex.IsMatch(command, @"powershell.*-enc"))
                return true;

            if (Regex.IsMatch(command, @"[A-Za-z0-9+/]{20,}"))
                return true;

            return false;
        }

        private static void BlockRegistryAutorun(RegistryKey baseKey, string location, string valueName, string value)
        {
            try
            {
                EnhancedLogger.LogWarning($"Blocking suspicious registry autorun: {location}\\{valueName}");
                
                // Create backup before removal
                var backupPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 
                    "PhageVirus", "Backups", $"autorun_backup_{DateTime.Now:yyyyMMdd_HHmmss}.reg");
                
                Directory.CreateDirectory(Path.GetDirectoryName(backupPath)!);
                File.WriteAllText(backupPath, $"Windows Registry Editor Version 5.00\n\n[{baseKey.Name}\\{location}]\n\"{valueName}\"=\"{value}\"");
                
                // Remove the suspicious autorun
                using var key = baseKey.OpenSubKey(location, true);
                if (key != null)
                {
                    key.DeleteValue(valueName, false);
                    EnhancedLogger.LogSuccess($"Removed suspicious registry autorun: {valueName}");
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to block registry autorun {valueName}: {ex.Message}");
            }
        }

        private static void BlockStartupFile(string filePath)
        {
            try
            {
                EnhancedLogger.LogWarning($"Blocking suspicious startup file: {filePath}");
                
                // Create backup
                var backupPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 
                    "PhageVirus", "Backups", $"startup_backup_{DateTime.Now:yyyyMMdd_HHmmss}_{Path.GetFileName(filePath)}");
                
                Directory.CreateDirectory(Path.GetDirectoryName(backupPath)!);
                File.Copy(filePath, backupPath);
                
                // Quarantine the file
                var quarantinePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 
                    "PhageVirus", "Quarantine", $"quarantined_{DateTime.Now:yyyyMMdd_HHmmss}_{Path.GetFileName(filePath)}");
                
                Directory.CreateDirectory(Path.GetDirectoryName(quarantinePath)!);
                File.Move(filePath, quarantinePath);
                
                EnhancedLogger.LogSuccess($"Quarantined suspicious startup file: {Path.GetFileName(filePath)}");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to block startup file {filePath}: {ex.Message}");
            }
        }

        private static void BlockScheduledTask(ManagementObject task)
        {
            try
            {
                var taskName = task["Name"]?.ToString() ?? "Unknown";
                EnhancedLogger.LogWarning($"Blocking suspicious scheduled task: {taskName}");
                
                // Delete the scheduled task
                task.Delete();
                EnhancedLogger.LogSuccess($"Deleted suspicious scheduled task: {taskName}");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to block scheduled task: {ex.Message}");
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

        public static void CleanupAutorun()
        {
            try
            {
                EnhancedLogger.LogInfo("Cleaning up autorun entries...");
                
                var cleanupCount = 0;
                
                // Clean registry autorun
                foreach (var location in StartupLocations)
                {
                    cleanupCount += CleanupRegistryAutorun(location, Registry.CurrentUser);
                    cleanupCount += CleanupRegistryAutorun(location, Registry.LocalMachine);
                }
                
                // Clean startup folders
                foreach (var folder in StartupFolders)
                {
                    cleanupCount += CleanupStartupFolder(folder);
                }
                
                EnhancedLogger.LogSuccess($"Autorun cleanup complete. Removed {cleanupCount} suspicious entries.");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Autorun cleanup failed: {ex.Message}");
            }
        }

        private static int CleanupRegistryAutorun(string location, RegistryKey baseKey)
        {
            var cleanupCount = 0;
            
            try
            {
                using var key = baseKey.OpenSubKey(location, true);
                if (key == null) return 0;

                var valueNames = key.GetValueNames();
                foreach (var valueName in valueNames)
                {
                    var value = key.GetValue(valueName)?.ToString() ?? "";
                    if (IsSuspiciousAutorun(value))
                    {
                        try
                        {
                            key.DeleteValue(valueName, false);
                            cleanupCount++;
                            EnhancedLogger.LogInfo($"Cleaned up registry autorun: {location}\\{valueName}");
                        }
                        catch
                        {
                            // Ignore errors for individual entries
                        }
                    }
                }
            }
            catch
            {
                // Ignore errors for registry access
            }
            
            return cleanupCount;
        }

        private static int CleanupStartupFolder(string folder)
        {
            var cleanupCount = 0;
            
            try
            {
                if (!Directory.Exists(folder)) return 0;

                var files = Directory.GetFiles(folder, "*.*", SearchOption.TopDirectoryOnly);
                foreach (var file in files)
                {
                    if (IsSuspiciousStartupFile(file))
                    {
                        try
                        {
                            BlockStartupFile(file);
                            cleanupCount++;
                        }
                        catch
                        {
                            // Ignore errors for individual files
                        }
                    }
                }
            }
            catch
            {
                // Ignore errors for folder access
            }
            
            return cleanupCount;
        }
    }
} 

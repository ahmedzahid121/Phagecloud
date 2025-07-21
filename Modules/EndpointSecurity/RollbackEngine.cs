using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace PhageVirus.Modules
{
    public class RollbackEngine
    {
        private static bool isRunning = false;
        private static readonly string BackupDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus", "Backups");
        private static readonly List<string> KeyPaths = new()
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus", "Logs")
        };
        private static readonly List<string> KeyRegistryPaths = new()
        {
            @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        };
        private static string lastBackupPath = string.Empty;

        public static bool StartRollbackEngine()
        {
            try
            {
                isRunning = true;
                EnhancedLogger.LogInfo("Rollback Engine started", Console.WriteLine);
                
                // Send telemetry to cloud for rollback engine status
                Task.Run(async () =>
                {
                    try
                    {
                        var rollbackData = new
                        {
                            backup_dir = BackupDir,
                            key_paths_count = KeyPaths.Count,
                            key_registry_paths_count = KeyRegistryPaths.Count,
                            last_backup_path = lastBackupPath,
                            threat_type = "rollback_engine_status",
                            timestamp = DateTime.UtcNow
                        };

                        await CloudIntegration.SendTelemetryAsync("RollbackEngine", "rollback_engine_status", rollbackData, ThreatLevel.Normal);
                        
                        // Get cloud rollback engine analysis
                        var analysis = await CloudIntegration.GetCloudAnalysisAsync("RollbackEngine", rollbackData);
                        if (analysis.Success)
                        {
                            EnhancedLogger.LogInfo($"Cloud rollback engine analysis: {analysis.Analysis}");
                        }
                    }
                    catch (Exception ex)
                    {
                        EnhancedLogger.LogWarning($"Cloud rollback engine analysis failed: {ex.Message}");
                    }
                });
                
                return true;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start Rollback Engine: {ex.Message}", Console.WriteLine);
                return false;
            }
        }

        public static void StopRollbackEngine()
        {
            isRunning = false;
            EnhancedLogger.LogInfo("Rollback Engine stopped", Console.WriteLine);
        }

        public static string CreateBackup()
        {
            try
            {
                Directory.CreateDirectory(BackupDir);
                var backupName = $"backup_{DateTime.Now:yyyyMMdd_HHmmss}";
                var backupPath = Path.Combine(BackupDir, backupName);
                Directory.CreateDirectory(backupPath);

                // Backup files
                foreach (var path in KeyPaths)
                {
                    if (Directory.Exists(path))
                    {
                        var dest = Path.Combine(backupPath, Path.GetFileName(path));
                        CopyDirectory(path, dest);
                    }
                }

                // Backup registry
                var regBackupPath = Path.Combine(backupPath, "registry.reg");
                using (var sw = new StreamWriter(regBackupPath))
                {
                    foreach (var regPath in KeyRegistryPaths)
                    {
                        try
                        {
                            var regExport = ExportRegistry(regPath);
                            sw.WriteLine(regExport);
                        }
                        catch (Exception rex)
                        {
                            EnhancedLogger.LogError($"Failed to export registry {regPath}: {rex.Message}", Console.WriteLine);
                        }
                    }
                }

                lastBackupPath = backupPath;
                EnhancedLogger.LogInfo($"Backup created at {backupPath}", Console.WriteLine);
                return backupPath;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to create backup: {ex.Message}", Console.WriteLine);
                return string.Empty;
            }
        }

        public static bool RestoreBackup(string backupPath)
        {
            try
            {
                if (!Directory.Exists(backupPath)) return false;

                // Restore files
                foreach (var dir in Directory.GetDirectories(backupPath))
                {
                    var dest = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), Path.GetFileName(dir));
                    CopyDirectory(dir, dest, overwrite: true);
                }

                // Restore registry
                var regBackupPath = Path.Combine(backupPath, "registry.reg");
                if (File.Exists(regBackupPath))
                {
                    ImportRegistry(regBackupPath);
                }

                EnhancedLogger.LogInfo($"Backup restored from {backupPath}", Console.WriteLine);
                return true;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to restore backup: {ex.Message}", Console.WriteLine);
                return false;
            }
        }

        public static bool TriggerRollback()
        {
            try
            {
                if (!string.IsNullOrEmpty(lastBackupPath))
                {
                    return RestoreBackup(lastBackupPath);
                }
                EnhancedLogger.LogWarning("No backup available for rollback", Console.WriteLine);
                return false;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to trigger rollback: {ex.Message}", Console.WriteLine);
                return false;
            }
        }

        private static void CopyDirectory(string sourceDir, string destDir, bool overwrite = false)
        {
            Directory.CreateDirectory(destDir);
            foreach (var file in Directory.GetFiles(sourceDir))
            {
                var dest = Path.Combine(destDir, Path.GetFileName(file));
                File.Copy(file, dest, overwrite);
            }
            foreach (var dir in Directory.GetDirectories(sourceDir))
            {
                CopyDirectory(dir, Path.Combine(destDir, Path.GetFileName(dir)), overwrite);
            }
        }

        private static string ExportRegistry(string regPath)
        {
            // Simulate registry export (in production, use reg.exe or RegistryKey APIs)
            return $"REG EXPORT {regPath}";
        }

        private static void ImportRegistry(string regFilePath)
        {
            // Simulate registry import (in production, use reg.exe or RegistryKey APIs)
            EnhancedLogger.LogInfo($"Simulated registry import from {regFilePath}", Console.WriteLine);
        }

        public static bool IsRollbackActive() => isRunning;
    }
} 

using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace PhageVirus.Modules
{
    public class SelfDestruct
    {
        public static void Execute()
        {
            try
            {
                EnhancedLogger.LogSelfDestruct("Manual self-destruct initiated", true);
                
                // Send telemetry to cloud for self-destruct event
                Task.Run(async () =>
                {
                    try
                    {
                        var selfDestructData = new
                        {
                            exe_path = System.Reflection.Assembly.GetExecutingAssembly().Location,
                            temp_dir = Path.GetTempPath(),
                            log_dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus"),
                            quarantine_dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus", "Quarantine"),
                            threat_type = "self_destruct",
                            timestamp = DateTime.UtcNow
                        };

                        await CloudIntegration.SendTelemetryAsync("SelfDestruct", "self_destruct", selfDestructData, ThreatLevel.Critical);
                        
                        // Get cloud self-destruct analysis
                        var analysis = await CloudIntegration.GetCloudAnalysisAsync("SelfDestruct", selfDestructData);
                        if (analysis.Success)
                        {
                            EnhancedLogger.LogInfo($"Cloud self-destruct analysis: {analysis.Analysis}");
                        }
                    }
                    catch (Exception ex)
                    {
                        EnhancedLogger.LogWarning($"Cloud self-destruct analysis failed: {ex.Message}");
                    }
                });
                
                // Get the current executable path
                string exePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                
                // Create a batch file to delete the executable after a delay
                string batPath = CreateDestructionScript(exePath);
                
                // Start the destruction process
                StartDestructionProcess(batPath);
                
                // Exit the application
                Environment.Exit(0);
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Self-destruct failed: {ex.Message}");
                // Fallback: try to delete directly
                try
                {
                    string exePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                    File.Delete(exePath);
                }
                catch
                {
                    // If all else fails, just exit
                }
                Environment.Exit(1);
            }
        }

        private static string CreateDestructionScript(string exePath)
        {
            var tempDir = Path.GetTempPath();
            var batFileName = $"phage_destruct_{DateTime.Now:yyyyMMdd_HHmmss}.bat";
            var batPath = Path.Combine(tempDir, batFileName);
            
            var script = $@"@echo off
echo PhageVirus - Self-Destruction Sequence Initiated
echo.
echo Waiting for application to close...
timeout /t 2 /nobreak >nul

echo Cleaning up executable...
del ""{exePath}"" /f /q

echo Cleaning up temporary files...
del ""{batPath}"" /f /q

echo Cleaning up logs...
rmdir /s /q ""{Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus")}"" 2>nul

echo Self-destruction complete.
echo PhageVirus has been removed from the system.
timeout /t 3 /nobreak >nul

del ""%~f0"" /f /q
";
            
            File.WriteAllText(batPath, script);
            return batPath;
        }

        private static void StartDestructionProcess(string batPath)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c \"{batPath}\"",
                WindowStyle = ProcessWindowStyle.Hidden,
                CreateNoWindow = true,
                UseShellExecute = false
            };
            
            Process.Start(startInfo);
        }

        public static void ScheduleDestruction(int delaySeconds = 30)
        {
            try
            {
                EnhancedLogger.LogInfo($"Self-destruction scheduled in {delaySeconds} seconds");
                
                var timer = new Timer(_ =>
                {
                    Execute();
                }, null, delaySeconds * 1000, Timeout.Infinite);
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to schedule self-destruction: {ex.Message}");
            }
        }

        public static void CleanupArtifacts()
        {
            try
            {
                // Clean up log files
                var logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus");
                if (Directory.Exists(logDir))
                {
                    Directory.Delete(logDir, true);
                }
                
                // Clean up quarantine
                var quarantineDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus", "Quarantine");
                if (Directory.Exists(quarantineDir))
                {
                    Directory.Delete(quarantineDir, true);
                }
                
                // Clean up temporary files
                var tempFiles = Directory.GetFiles(Path.GetTempPath(), "phage*");
                foreach (var file in tempFiles)
                {
                    try
                    {
                        File.Delete(file);
                    }
                    catch
                    {
                        // Ignore files we can't delete
                    }
                }
                
                EnhancedLogger.LogInfo("Artifacts cleanup completed");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Artifacts cleanup failed: {ex.Message}");
            }
        }

        public static bool IsDestructionScheduled()
        {
            try
            {
                var tempFiles = Directory.GetFiles(Path.GetTempPath(), "phage_destruct_*.bat");
                return tempFiles.Length > 0;
            }
            catch
            {
                return false;
            }
        }

        public static void CancelDestruction()
        {
            try
            {
                var tempFiles = Directory.GetFiles(Path.GetTempPath(), "phage_destruct_*.bat");
                foreach (var file in tempFiles)
                {
                    try
                    {
                        File.Delete(file);
                    }
                    catch
                    {
                        // Ignore files we can't delete
                    }
                }
                
                EnhancedLogger.LogInfo("Self-destruction cancelled");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to cancel self-destruction: {ex.Message}");
            }
        }

        public static void ExecuteSelfDestruct()
        {
            // Implementation or stub
        }
    }
} 

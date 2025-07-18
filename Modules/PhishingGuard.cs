using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;

namespace PhageVirus.Modules
{
    public class PhishingGuard
    {
        private static bool isRunning = false;
        private static readonly List<string> PhishingPatterns = new()
        {
            @"login\\.php",
            @"account\\.verify",
            @"secure\\.update",
            @"bank\\.login",
            @"password\\.reset",
            @"signin\\.html",
            @"webmail\\.auth",
            @"paypal\\.com",
            @"office365\\.com",
            @"credential|harvest|phish|fake|scam|verify|update|reset|confirm|security|alert"
        };
        private static readonly List<string> WatchedBrowsers = new() { "chrome", "firefox", "msedge", "iexplore" };
        private static readonly string DownloadsPath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads";
        private static string lastClipboard = string.Empty;
        private static DateTime lastScan = DateTime.MinValue;

        public static bool StartPhishingGuard()
        {
            try
            {
                isRunning = true;
                Task.Run(MonitorClipboard);
                Task.Run(MonitorDownloads);
                Task.Run(MonitorBrowsers);
                EnhancedLogger.LogInfo("Phishing Guard started", Console.WriteLine);
                return true;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start Phishing Guard: {ex.Message}", Console.WriteLine);
                return false;
            }
        }

        public static void StopPhishingGuard()
        {
            isRunning = false;
            EnhancedLogger.LogInfo("Phishing Guard stopped", Console.WriteLine);
        }

        private static async void MonitorClipboard()
        {
            while (isRunning)
            {
                try
                {
                    var clipboardText = Clipboard.GetText();
                    if (!string.IsNullOrEmpty(clipboardText) && clipboardText != lastClipboard)
                    {
                        lastClipboard = clipboardText;
                        if (IsPhishingText(clipboardText))
                        {
                            EnhancedLogger.LogWarning($"Phishing pattern detected in clipboard: {clipboardText}", Console.WriteLine);
                            HandlePhishingDetected("Clipboard", clipboardText);
                        }
                    }
                }
                catch { }
                await Task.Delay(2000);
            }
        }

        private static async void MonitorDownloads()
        {
            while (isRunning)
            {
                try
                {
                    if (Directory.Exists(DownloadsPath))
                    {
                        foreach (var file in Directory.GetFiles(DownloadsPath))
                        {
                            var name = Path.GetFileName(file).ToLower();
                            if (IsPhishingText(name))
                            {
                                EnhancedLogger.LogWarning($"Phishing pattern detected in download: {name}", Console.WriteLine);
                                HandlePhishingDetected("Download", name);
                            }
                        }
                    }
                }
                catch { }
                await Task.Delay(5000);
            }
        }

        private static async void MonitorBrowsers()
        {
            while (isRunning)
            {
                try
                {
                    foreach (var browser in WatchedBrowsers)
                    {
                        foreach (var proc in Process.GetProcessesByName(browser))
                        {
                            var title = proc.MainWindowTitle.ToLower();
                            if (IsPhishingText(title))
                            {
                                EnhancedLogger.LogWarning($"Phishing pattern detected in browser title: {title}", Console.WriteLine);
                                HandlePhishingDetected("Browser", title);
                            }
                        }
                    }
                }
                catch { }
                await Task.Delay(4000);
            }
        }

        private static bool IsPhishingText(string text)
        {
            foreach (var pattern in PhishingPatterns)
            {
                if (Regex.IsMatch(text, pattern, RegexOptions.IgnoreCase))
                    return true;
            }
            return false;
        }

        private static void HandlePhishingDetected(string source, string detail)
        {
            // Log, alert, and optionally trigger mesh sync or quarantine
            EnhancedLogger.LogWarning($"Phishing detected from {source}: {detail}", Console.WriteLine);
            // Optionally: PhageSync.ShareThreat(...)
        }

        public static bool IsPhishingGuardActive() => isRunning;
    }
} 

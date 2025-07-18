using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Collections.Generic; // Added for List

namespace PhageVirus.Modules
{
    public class PayloadReplacer
    {
        public static bool Neutralize(ThreatInfo threat)
        {
            try
            {
                // Send telemetry to cloud for payload neutralization
                Task.Run(async () =>
                {
                    try
                    {
                        var neutralizationData = new
                        {
                            threat_file = threat.File,
                            threat_type = threat.Type,
                            threat_level = threat.Level,
                            threat_description = threat.Description,
                            neutralization_action = "neutralize",
                            threat_type_telemetry = "payload_neutralization",
                            timestamp = DateTime.UtcNow
                        };

                        await CloudIntegration.SendTelemetryAsync("PayloadReplacer", "payload_neutralization", neutralizationData, ThreatLevel.High);
                        
                        // Get cloud neutralization analysis
                        var analysis = await CloudIntegration.GetCloudAnalysisAsync("PayloadReplacer", neutralizationData);
                        if (analysis.Success)
                        {
                            EnhancedLogger.LogInfo($"Cloud neutralization analysis: {analysis.Analysis}");
                        }
                    }
                    catch (Exception ex)
                    {
                        EnhancedLogger.LogWarning($"Cloud neutralization analysis failed: {ex.Message}");
                    }
                });

                if (threat.Type == "Process")
                {
                    return NeutralizeProcessAdvanced(threat);
                }
                else
                {
                    return NeutralizeFile(threat);
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Neutralization failed for {threat.File}: {ex.Message}");
                return false;
            }
        }

        private static bool NeutralizeFile(ThreatInfo threat)
        {
            var filePath = threat.File;
            
            if (!File.Exists(filePath))
                return false;

            try
            {
                var extension = Path.GetExtension(filePath).ToLower();
                
                switch (extension)
                {
                    case ".exe":
                    case ".dll":
                        // Replace executable content with harmless code
                        var neutralizedExe = CreateNeutralizedExecutable();
                        File.WriteAllBytes(filePath, neutralizedExe);
                        break;
                        
                    case ".bat":
                    case ".cmd":
                        // Replace batch file content
                        var neutralizedBatch = CreateNeutralizedBatch();
                        File.WriteAllText(filePath, neutralizedBatch, Encoding.UTF8);
                        break;
                        
                    case ".txt":
                    case ".log":
                        // Replace text content
                        var neutralizedText = CreateNeutralizedText();
                        File.WriteAllText(filePath, neutralizedText, Encoding.UTF8);
                        break;
                        
                    case ".ps1":
                        // Replace PowerShell script
                        var neutralizedPs1 = CreateNeutralizedPowerShell();
                        File.WriteAllText(filePath, neutralizedPs1, Encoding.UTF8);
                        break;
                        
                    default:
                        // Generic neutralization
                        var neutralizedGeneric = CreateNeutralizedGeneric();
                        File.WriteAllText(filePath, neutralizedGeneric, Encoding.UTF8);
                        break;
                }

                // Set file attributes to read-only to prevent re-infection
                File.SetAttributes(filePath, FileAttributes.ReadOnly);
                
                return true;
            }
            catch
            {
                // If we can't modify the file, try to delete it
                try
                {
                    File.Delete(filePath);
                    return true;
                }
                catch
                {
                    return false;
                }
            }
        }

        private static bool NeutralizeProcessAdvanced(ThreatInfo threat)
        {
            try
            {
                // Extract PID from the threat description
                var match = System.Text.RegularExpressions.Regex.Match(threat.File, @"PID: (\d+)");
                if (match.Success && int.TryParse(match.Groups[1].Value, out int pid))
                {
                    EnhancedLogger.LogInfo($"Advanced process neutralization for PID: {pid}");
                    
                    // First, try to inject neutralization code
                    var processInfo = new ProcessInfo { ProcessId = pid, ProcessName = "Unknown" };
                    if (SystemHacker.InjectNeutralizationCode(processInfo))
                    {
                        EnhancedLogger.LogSuccess($"Successfully injected neutralization code into process {pid}");
                        return true;
                    }
                    
                    // If injection fails, terminate the process
                    EnhancedLogger.LogWarning($"Injection failed, terminating process {pid}");
                    if (SystemHacker.TerminateProcess(processInfo))
                    {
                        EnhancedLogger.LogSuccess($"Successfully terminated process {pid}");
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Advanced process neutralization failed: {ex.Message}");
            }
            
            return false;
        }

        private static byte[] CreateNeutralizedExecutable()
        {
            // Create a harmless executable that just displays a message
            var harmlessCode = @"
using System;
class NeutralizedProgram
{
    static void Main()
    {
        Console.WriteLine(""This file has been neutralized by PhageVirus"");
        Console.WriteLine(""Original malicious content has been removed."");
        Console.WriteLine(""Press any key to exit..."");
        Console.ReadKey();
    }
}";
            
            // For simulation, we'll create a simple text file with .exe extension
            // In a real implementation, you'd compile this to actual executable bytes
            return Encoding.UTF8.GetBytes(harmlessCode);
        }

        private static string CreateNeutralizedBatch()
        {
            return @"@echo off
echo This batch file has been neutralized by PhageVirus
echo Original malicious content has been removed.
echo.
echo File: %0
echo Date: %date% %time%
echo Status: CLEAN
pause";
        }

        private static string CreateNeutralizedText()
        {
            return $@"=== NEUTRALIZED BY PHAGEVIRUS ===
Original file: {DateTime.Now:yyyy-MM-dd HH:mm:ss}
Status: CLEAN
Action: Content replaced with harmless text

This file contained potentially malicious content that has been 
neutralized by the PhageVirus system. The original content has 
been replaced with this harmless message.

PhageVirus - Futuristic Antivirus Simulation
=============================================";
        }

        private static string CreateNeutralizedPowerShell()
        {
            return @"# NEUTRALIZED BY PHAGEVIRUS
# Original malicious PowerShell script has been replaced

Write-Host ""This PowerShell script has been neutralized by PhageVirus"" -ForegroundColor Green
Write-Host ""Original malicious content has been removed."" -ForegroundColor Yellow
Write-Host ""File: $PSCommandPath"" -ForegroundColor Cyan
Write-Host ""Date: $(Get-Date)"" -ForegroundColor Cyan
Write-Host ""Status: CLEAN"" -ForegroundColor Green

# Harmless demonstration of PowerShell capabilities
Get-Process | Where-Object {$_.ProcessName -like ""*explorer*""} | 
    Select-Object ProcessName, Id, WorkingSet | 
    Format-Table -AutoSize";
        }

        private static string CreateNeutralizedGeneric()
        {
            return $@"NEUTRALIZED BY PHAGEVIRUS
===============================
File neutralized on: {DateTime.Now:yyyy-MM-dd HH:mm:ss}
Original content: REMOVED
Replacement: Harmless placeholder text

This file has been processed by the PhageVirus system and 
any potentially malicious content has been neutralized.

PhageVirus - Advanced Threat Neutralization System
==================================================";
        }

        public static bool Quarantine(ThreatInfo threat)
        {
            try
            {
                var quarantineDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus", "Quarantine");
                Directory.CreateDirectory(quarantineDir);
                
                var fileName = Path.GetFileName(threat.File);
                var quarantinePath = Path.Combine(quarantineDir, $"quarantined_{DateTime.Now:yyyyMMdd_HHmmss}_{fileName}");
                
                if (File.Exists(threat.File))
                {
                    File.Move(threat.File, quarantinePath);
                    return true;
                }
            }
            catch
            {
                // If quarantine fails, try neutralization
                return Neutralize(threat);
            }
            
            return false;
        }

        public static bool Analyze(ThreatInfo threat)
        {
            // Simulate deep analysis
            try
            {
                if (threat.Type == "File" && File.Exists(threat.File))
                {
                    var fileInfo = new FileInfo(threat.File);
                    var analysis = $@"
=== PHAGEVIRUS ANALYSIS REPORT ===
File: {threat.File}
Size: {fileInfo.Length} bytes
Created: {fileInfo.CreationTime}
Modified: {fileInfo.LastWriteTime}
Attributes: {fileInfo.Attributes}
Detection Method: {threat.DetectionMethod}

Analysis Results:
- File structure: {AnalyzeFileStructure(threat.File)}
- Content patterns: {AnalyzeContentPatterns(threat.File)}
- Risk level: {DetermineRiskLevel(threat)}
- Recommended action: {threat.Action}

Analysis completed: {DateTime.Now:yyyy-MM-dd HH:mm:ss}
===============================================";

                    // Write analysis to log
                    EnhancedLogger.LogInfo($"Analysis completed for {threat.File}: {analysis}");
                    return true;
                }
            }
            catch
            {
                // Analysis failed
            }
            
            return false;
        }

        private static string AnalyzeFileStructure(string filePath)
        {
            try
            {
                var extension = Path.GetExtension(filePath).ToLower();
                return extension switch
                {
                    ".exe" => "Executable binary - requires sandbox analysis",
                    ".dll" => "Dynamic link library - potential code injection",
                    ".bat" => "Batch script - command execution risk",
                    ".ps1" => "PowerShell script - high execution privileges",
                    ".txt" => "Text file - content-based threat",
                    _ => "Unknown format - proceed with caution"
                };
            }
            catch
            {
                return "Unable to analyze structure";
            }
        }

        private static string AnalyzeContentPatterns(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    var content = File.ReadAllText(filePath).ToLower();
                    var patterns = new List<string>();
                    
                    if (content.Contains("http://") || content.Contains("https://"))
                        patterns.Add("Network communication");
                    if (content.Contains("registry") || content.Contains("regedit"))
                        patterns.Add("Registry modification");
                    if (content.Contains("taskkill") || content.Contains("kill"))
                        patterns.Add("Process termination");
                    if (content.Contains("format") || content.Contains("del"))
                        patterns.Add("Data destruction");
                    
                    return patterns.Count > 0 ? string.Join(", ", patterns) : "No suspicious patterns detected";
                }
            }
            catch
            {
                // File might be locked or binary
            }
            
            return "Unable to analyze content";
        }

        private static string DetermineRiskLevel(ThreatInfo threat)
        {
            var riskFactors = new List<string>();
            
            if (threat.DetectionMethod.Contains("Keyword match"))
                riskFactors.Add("Known threat signature");
            if (threat.Type == "Process")
                riskFactors.Add("Active process");
            if (threat.Action == "Terminate")
                riskFactors.Add("Immediate action required");
                
            return riskFactors.Count switch
            {
                0 => "LOW",
                1 => "MEDIUM",
                2 => "HIGH",
                _ => "CRITICAL"
            };
        }
    }
} 

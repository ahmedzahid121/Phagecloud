using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace PhageVirus.Modules
{
    public class FirewallGuard
    {
        private static bool isActive = false;
        private static readonly object guardLock = new object();
        private static readonly HashSet<string> blockedIPs = new HashSet<string>();
        private static readonly HashSet<string> blockedDomains = new HashSet<string>();
        private static readonly List<FirewallRule> activeRules = new List<FirewallRule>();

        public class FirewallRule
        {
            public string Name { get; set; }
            public string Direction { get; set; }
            public string Action { get; set; }
            public string RemoteAddress { get; set; }
            public string Protocol { get; set; }
            public string LocalPort { get; set; }
            public string RemotePort { get; set; }
            public string Program { get; set; }
            public bool Enabled { get; set; }
            public DateTime Created { get; set; }
        }

        public static void ActivateFirewallGuard()
        {
            if (isActive) return;

            lock (guardLock)
            {
                if (isActive) return;

                try
                {
                    EnhancedLogger.LogInfo("Activating FirewallGuard...");
                    
                    // Load known malicious IPs and domains
                    LoadThreatIntelligence();
                    
                    // Create base firewall rules
                    CreateBaseFirewallRules();
                    
                    // Start monitoring network connections
                    Task.Run(() => MonitorNetworkConnections());
                    
                    // Start monitoring for new threats
                    Task.Run(() => MonitorForNewThreats());
                    
                    isActive = true;
                    EnhancedLogger.LogSuccess("FirewallGuard activated successfully");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to activate FirewallGuard: {ex.Message}");
                }
            }
        }

        public static void DeactivateFirewallGuard()
        {
            lock (guardLock)
            {
                if (!isActive) return;

                try
                {
                    // Remove all custom firewall rules
                    RemoveAllCustomRules();
                    
                    isActive = false;
                    EnhancedLogger.LogInfo("FirewallGuard deactivated");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to deactivate FirewallGuard: {ex.Message}");
                }
            }
        }

        private static void LoadThreatIntelligence()
        {
            try
            {
                // Load known malicious IPs
                var maliciousIPs = new[]
                {
                    "103.145.0.0/16",      // Known malicious range
                    "185.220.101.0/24",    // C2 infrastructure
                    "45.95.147.0/24",      // Malware distribution
                    "91.92.240.0/24",      // Ransomware C2
                    "194.26.192.0/24",     // Phishing infrastructure
                    "23.106.215.0/24",     // Botnet C2
                    "185.220.102.0/24",    // APT infrastructure
                    "45.95.146.0/24",      // Malware distribution
                    "91.92.241.0/24",      // Ransomware C2
                    "194.26.193.0/24"      // Phishing infrastructure
                };

                foreach (var ip in maliciousIPs)
                {
                    blockedIPs.Add(ip);
                }

                // Load known malicious domains
                var maliciousDomains = new[]
                {
                    "malware.example.com",
                    "c2.evil.com",
                    "phishing.fake.com",
                    "ransomware.pay.com",
                    "botnet.control.com",
                    "apt.steal.com",
                    "keylogger.spy.com",
                    "trojan.backdoor.com",
                    "worm.spread.com",
                    "virus.infect.com"
                };

                foreach (var domain in maliciousDomains)
                {
                    blockedDomains.Add(domain);
                }

                EnhancedLogger.LogInfo($"Loaded {blockedIPs.Count} malicious IPs and {blockedDomains.Count} malicious domains");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to load threat intelligence: {ex.Message}");
            }
        }

        private static void CreateBaseFirewallRules()
        {
            try
            {
                // Block known malicious IP ranges
                foreach (var ipRange in blockedIPs)
                {
                    CreateFirewallRule($"PhageBlock_{ipRange.Replace("/", "_")}", "Outbound", "Block", ipRange, "Any");
                }

                // Block suspicious outbound connections
                CreateFirewallRule("PhageBlock_SuspiciousOutbound", "Outbound", "Block", "Any", "Any", null, "445"); // SMB
                CreateFirewallRule("PhageBlock_SuspiciousOutbound2", "Outbound", "Block", "Any", "Any", null, "3389"); // RDP
                CreateFirewallRule("PhageBlock_SuspiciousOutbound3", "Outbound", "Block", "Any", "Any", null, "22"); // SSH

                // Block suspicious inbound connections
                CreateFirewallRule("PhageBlock_SuspiciousInbound", "Inbound", "Block", "Any", "Any", null, "4444"); // Metasploit
                CreateFirewallRule("PhageBlock_SuspiciousInbound2", "Inbound", "Block", "Any", "Any", null, "8080"); // Web shell
                CreateFirewallRule("PhageBlock_SuspiciousInbound3", "Inbound", "Block", "Any", "Any", null, "9999"); // Backdoor

                EnhancedLogger.LogInfo("Base firewall rules created successfully");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to create base firewall rules: {ex.Message}");
            }
        }

        public static bool CreateFirewallRule(string name, string direction, string action, string remoteAddress = "Any", 
            string protocol = "Any", string localPort = "Any", string remotePort = "Any", string program = "Any")
        {
            try
            {
                var rule = new FirewallRule
                {
                    Name = name,
                    Direction = direction,
                    Action = action,
                    RemoteAddress = remoteAddress,
                    Protocol = protocol,
                    LocalPort = localPort,
                    RemotePort = remotePort,
                    Program = program,
                    Enabled = true,
                    Created = DateTime.Now
                };

                var command = BuildFirewallCommand(rule);
                var result = ExecutePowerShellCommand(command);

                if (result)
                {
                    activeRules.Add(rule);
                    EnhancedLogger.LogSuccess($"Firewall rule created: {name}");
                    return true;
                }
                else
                {
                    EnhancedLogger.LogError($"Failed to create firewall rule: {name}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error creating firewall rule {name}: {ex.Message}");
                return false;
            }
        }

        private static string BuildFirewallCommand(FirewallRule rule)
        {
            var command = $"New-NetFirewallRule -DisplayName '{rule.Name}' -Direction {rule.Direction} -Action {rule.Action}";

            if (rule.RemoteAddress != "Any")
                command += $" -RemoteAddress {rule.RemoteAddress}";

            if (rule.Protocol != "Any")
                command += $" -Protocol {rule.Protocol}";

            if (rule.LocalPort != "Any")
                command += $" -LocalPort {rule.LocalPort}";

            if (rule.RemotePort != "Any")
                command += $" -RemotePort {rule.RemotePort}";

            if (rule.Program != "Any")
                command += $" -Program '{rule.Program}'";

            command += " -Enabled True";

            return command;
        }

        private static bool ExecutePowerShellCommand(string command)
        {
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-Command \"{command}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    Verb = "runas" // Run as administrator
                };

                using (var process = Process.Start(startInfo))
                {
                    process.WaitForExit();
                    return process.ExitCode == 0;
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"PowerShell command execution failed: {ex.Message}");
                return false;
            }
        }

        public static bool BlockIP(string ipAddress, string reason = "")
        {
            try
            {
                if (blockedIPs.Contains(ipAddress))
                {
                    EnhancedLogger.LogInfo($"IP {ipAddress} already blocked");
                    return true;
                }

                var ruleName = $"PhageBlock_IP_{ipAddress.Replace(".", "_")}";
                var success = CreateFirewallRule(ruleName, "Outbound", "Block", ipAddress);

                if (success)
                {
                    blockedIPs.Add(ipAddress);
                    EnhancedLogger.LogThreat($"Blocked malicious IP: {ipAddress} - {reason}");
                    
                    // Send telemetry to cloud for threat intelligence
                    Task.Run(async () =>
                    {
                        try
                        {
                            var firewallData = new
                            {
                                ip_address = ipAddress,
                                reason = reason,
                                action = "block",
                                timestamp = DateTime.UtcNow,
                                blocked_ips_count = blockedIPs.Count,
                                blocked_domains_count = blockedDomains.Count
                            };

                            await CloudIntegration.SendTelemetryAsync("FirewallGuard", "ip_blocked", firewallData, ThreatLevel.High);
                            
                            // Get cloud threat intelligence
                            var threatIntel = await CloudIntegration.GetThreatIntelligenceAsync(ipAddress, "malicious_ip");
                            if (threatIntel.Success)
                            {
                                EnhancedLogger.LogInfo($"Cloud threat intel for {ipAddress}: {threatIntel.ThreatName} - Confidence: {threatIntel.Confidence:P1}");
                            }
                        }
                        catch (Exception ex)
                        {
                            EnhancedLogger.LogWarning($"Cloud firewall analysis failed for {ipAddress}: {ex.Message}");
                        }
                    });
                }

                return success;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to block IP {ipAddress}: {ex.Message}");
                return false;
            }
        }

        public static bool BlockDomain(string domain, string reason = "")
        {
            try
            {
                if (blockedDomains.Contains(domain))
                {
                    EnhancedLogger.LogInfo($"Domain {domain} already blocked");
                    return true;
                }

                // Resolve domain to IP and block
                var ips = ResolveDomain(domain);
                var success = true;

                foreach (var ip in ips)
                {
                    if (!BlockIP(ip, $"Domain: {domain}"))
                    {
                        success = false;
                    }
                }

                if (success)
                {
                    blockedDomains.Add(domain);
                    EnhancedLogger.LogThreat($"Blocked malicious domain: {domain} - {reason}");
                }

                return success;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to block domain {domain}: {ex.Message}");
                return false;
            }
        }

        private static List<string> ResolveDomain(string domain)
        {
            var ips = new List<string>();
            try
            {
                var hostEntry = Dns.GetHostEntry(domain);
                foreach (var address in hostEntry.AddressList)
                {
                    ips.Add(address.ToString());
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to resolve domain {domain}: {ex.Message}");
            }
            return ips;
        }

        private static async Task MonitorNetworkConnections()
        {
            try
            {
                while (isActive)
                {
                    try
                    {
                        var connections = GetActiveNetworkConnections();
                        
                        foreach (var connection in connections)
                        {
                            // Check if connection is to a blocked IP
                            if (IsIPBlocked(connection.RemoteIP))
                            {
                                EnhancedLogger.LogThreat($"Blocked connection attempt to malicious IP: {connection.RemoteIP} from {connection.ProcessName}");
                                BlockIP(connection.RemoteIP, "Active connection detected");
                            }

                            // Check for suspicious connection patterns
                            if (IsSuspiciousConnection(connection))
                            {
                                EnhancedLogger.LogWarning($"Suspicious network connection: {connection.ProcessName} -> {connection.RemoteIP}:{connection.RemotePort}");
                                
                                // Block suspicious connections
                                if (!IsVirtualMachine())
                                {
                                    BlockIP(connection.RemoteIP, "Suspicious connection pattern");
                                }
                            }
                        }

                        await Task.Delay(10000); // Check every 10 seconds
                    }
                    catch (Exception ex)
                    {
                        EnhancedLogger.LogError($"Network monitoring error: {ex.Message}");
                        await Task.Delay(15000);
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Network monitoring failed: {ex.Message}");
            }
        }

        private static List<NetworkConnection> GetActiveNetworkConnections()
        {
            var connections = new List<NetworkConnection>();
            
            try
            {
                var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkConnection");
                foreach (ManagementObject obj in searcher.Get())
                {
                    try
                    {
                        var connection = new NetworkConnection
                        {
                            ProcessName = GetProcessNameByPID(Convert.ToInt32(obj["ProcessId"])),
                            RemoteIP = obj["RemoteName"]?.ToString() ?? "",
                            RemotePort = Convert.ToInt32(obj["RemotePort"] ?? 0),
                            LocalPort = Convert.ToInt32(obj["LocalPort"] ?? 0),
                            Protocol = obj["Protocol"]?.ToString() ?? ""
                        };
                        
                        if (!string.IsNullOrEmpty(connection.RemoteIP) && connection.RemoteIP != "0.0.0.0")
                        {
                            connections.Add(connection);
                        }
                    }
                    catch
                    {
                        // Skip invalid connections
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to get network connections: {ex.Message}");
            }
            
            return connections;
        }

        private static string GetProcessNameByPID(int pid)
        {
            try
            {
                var process = Process.GetProcessById(pid);
                return process.ProcessName;
            }
            catch
            {
                return "Unknown";
            }
        }

        private static bool IsIPBlocked(string ip)
        {
            return blockedIPs.Any(blockedIP => IsIPInRange(ip, blockedIP));
        }

        private static bool IsIPInRange(string ip, string ipRange)
        {
            try
            {
                if (!ipRange.Contains("/"))
                {
                    return ip == ipRange;
                }

                var parts = ipRange.Split('/');
                var networkIP = parts[0];
                var prefixLength = int.Parse(parts[1]);

                var networkAddress = IPAddress.Parse(networkIP);
                var testAddress = IPAddress.Parse(ip);

                var networkBytes = networkAddress.GetAddressBytes();
                var testBytes = testAddress.GetAddressBytes();

                if (networkBytes.Length != testBytes.Length)
                    return false;

                var mask = (uint)((1 << (32 - prefixLength)) - 1);
                var network = BitConverter.ToUInt32(networkBytes.Reverse().ToArray(), 0) & ~mask;
                var test = BitConverter.ToUInt32(testBytes.Reverse().ToArray(), 0) & ~mask;

                return network == test;
            }
            catch
            {
                return false;
            }
        }

        private static bool IsSuspiciousConnection(NetworkConnection connection)
        {
            // Check for suspicious ports
            var suspiciousPorts = new[] { 4444, 8080, 9999, 1337, 31337, 6667, 6666, 6665 };
            if (suspiciousPorts.Contains(connection.RemotePort))
                return true;

            // Check for suspicious processes
            var suspiciousProcesses = new[] { "powershell", "cmd", "mshta", "rundll32", "regsvr32" };
            if (suspiciousProcesses.Contains(connection.ProcessName.ToLower()))
                return true;

            // Check for high-frequency connections
            // This would require tracking connection frequency over time

            return false;
        }

        private static async Task MonitorForNewThreats()
        {
            try
            {
                while (isActive)
                {
                    try
                    {
                        // Monitor for new malicious IPs (simulated)
                        // In a real implementation, this would connect to threat feeds
                        
                        // Monitor for DNS queries to malicious domains
                        MonitorDNSQueries();
                        
                        await Task.Delay(30000); // Check every 30 seconds
                    }
                    catch (Exception ex)
                    {
                        EnhancedLogger.LogError($"Threat monitoring error: {ex.Message}");
                        await Task.Delay(45000);
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Threat monitoring failed: {ex.Message}");
            }
        }

        private static void MonitorDNSQueries()
        {
            try
            {
                // This would require ETW or WMI event monitoring
                // For now, we'll simulate by checking active connections
                var connections = GetActiveNetworkConnections();
                
                foreach (var connection in connections)
                {
                    // Check if any connection matches our blocked domains
                    foreach (var domain in blockedDomains)
                    {
                        if (connection.RemoteIP.Contains(domain) || 
                            IsDomainInConnection(connection, domain))
                        {
                            EnhancedLogger.LogThreat($"DNS query to malicious domain detected: {domain}");
                            BlockDomain(domain, "Active DNS query detected");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"DNS monitoring error: {ex.Message}");
            }
        }

        private static bool IsDomainInConnection(NetworkConnection connection, string domain)
        {
            try
            {
                // Try to reverse lookup the IP to see if it resolves to our blocked domain
                var hostEntry = Dns.GetHostEntry(connection.RemoteIP);
                return hostEntry.HostName.ToLower().Contains(domain.ToLower());
            }
            catch
            {
                return false;
            }
        }

        private static void RemoveAllCustomRules()
        {
            try
            {
                foreach (var rule in activeRules)
                {
                    var command = $"Remove-NetFirewallRule -DisplayName '{rule.Name}' -ErrorAction SilentlyContinue";
                    ExecutePowerShellCommand(command);
                }
                
                activeRules.Clear();
                EnhancedLogger.LogInfo("All custom firewall rules removed");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to remove firewall rules: {ex.Message}");
            }
        }

        private static bool IsVirtualMachine()
        {
            try
            {
                var computerSystem = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                foreach (ManagementObject obj in computerSystem.Get())
                {
                    var manufacturer = obj["Manufacturer"]?.ToString()?.ToLower() ?? "";
                    var model = obj["Model"]?.ToString()?.ToLower() ?? "";
                    
                    if (manufacturer.Contains("vmware") || manufacturer.Contains("virtual") ||
                        manufacturer.Contains("microsoft") || manufacturer.Contains("parallels") ||
                        model.Contains("vmware") || model.Contains("virtual") ||
                        model.Contains("vbox") || model.Contains("parallels"))
                    {
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

        public static bool IsActive => isActive;
        public static int BlockedIPCount => blockedIPs.Count;
        public static int BlockedDomainCount => blockedDomains.Count;
        public static int ActiveRuleCount => activeRules.Count;
    }

    public class NetworkConnection
    {
        public string ProcessName { get; set; }
        public string RemoteIP { get; set; }
        public int RemotePort { get; set; }
        public int LocalPort { get; set; }
        public string Protocol { get; set; }
    }
} 
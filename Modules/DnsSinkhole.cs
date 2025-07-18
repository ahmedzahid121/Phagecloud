using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using System.Linq;

namespace PhageVirus.Modules
{
    public class DnsSinkhole
    {
        private static bool isRunning = false;
        private static readonly Dictionary<string, string> BlockedDomains = new();
        private static readonly Dictionary<string, DateTime> DomainAttempts = new();
        private static readonly object domainLock = new();
        private static UdpClient? dnsServer;
        private static readonly string hostsFilePath = @"C:\Windows\System32\drivers\etc\hosts"; // CS8618: Already initialized
        private static readonly string backupHostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus", "hosts.backup"); // CS8618: Already initialized
        
        // DNS server configuration
        private static readonly int DnsPort =53535; // Changed from 53d system conflicts
        private static readonly string[] UpstreamDnsServers = { "8.8.8.8", "1.1.1.1", "28.67.222.222" }; // CS8618: Already initialized
        
        // Malicious domain patterns
        private static readonly string[] MaliciousPatterns = {
            @"\.(tk|ml|ga|cf|gq)$", // Free TLDs often used by malware
            @"(malware|virus|trojan|backdoor|keylogger|stealer|miner|botnet)",
            @"(c2|command|control|beacon|callback)",
            @"(phishing|scam|fake|spam)",
            @"(exploit|vulnerability|hack|crack)",
            @"(anonymous|proxy|vpn|tor)",
            @"(bitcoin|wallet|crypto|mining)",
            @"(ddos|attack|flood|bomb)",
            @"(warez|cracked|pirate|illegal)",
            @"(adult|porn|sex|xxx)",
            @"(gambling|casino|bet|poker)",
            @"(drugs|pharmacy|medication)",
            @"(weapon|gun|ammo|firearm)",
            @"(counterfeit|fake|replica)",
            @"(hack|hacker|hacking|hacktivist)"
        };
        
        // Known malicious domains
        private static readonly string[] KnownMaliciousDomains = {
            "malware.example.com",
            "c2.attacker.com",
            "phishing.scam.net",
            "botnet.control.org",
            "keyEnhancedLogger.steal.info",
            "ransomware.pay.me",
            "trojan.backdoor.biz",
            "miner.crypto.co",
            "ddos.attack.pro",
            "exploit.vuln.tech"
        };

        // DNS tunneling detection
        private static readonly Dictionary<string, DnsTunnelInfo> DnsTunnelSessions = new();
        private static readonly object tunnelLock = new object();
        
        // DNS tunneling thresholds
        private static readonly int MaxDnsQueryLength = 63; // Standard DNS label length
        private static readonly int MaxSubdomainLength = 253; // Total domain length
        private static readonly double HighEntropyThreshold = 7.0; // High entropy threshold
        private static readonly int MaxQueriesPerMinute = 100; // Max queries per minute per client
        private static readonly int MaxUniqueSubdomains = 50; // Max unique subdomains per client
        
        public class DnsTunnelInfo
        {
            public string ClientIp { get; set; } = "";
            public DateTime FirstSeen { get; set; }
            public DateTime LastSeen { get; set; }
            public int QueryCount { get; set; }
            public HashSet<string> UniqueSubdomains { get; set; } = new();
            public List<string> RecentQueries { get; set; } = new();
            public double AverageEntropy { get; set; }
            public bool IsTunneling { get; set; }
        }

        public static bool StartDnsSinkhole()
        {
            try
            {
                EnhancedLogger.LogInfo("Starting DNS Sinkhole protection...", Console.WriteLine);
                
                isRunning = true;
                
                // Initialize blocked domains
                InitializeBlockedDomains();
                
                // Backup original hosts file
                BackupHostsFile();
                
                // Start DNS server
                StartDnsServer();
                
                // Start domain monitoring
                Task.Run(MonitorDomainAttempts);
                
                // Start periodic domain updates
                Task.Run(UpdateMaliciousDomains);
                
                EnhancedLogger.LogInfo("DNS Sinkhole protection started", Console.WriteLine);
                return true;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start DNS Sinkhole: {ex.Message}", Console.WriteLine);
                return false;
            }
        }

        public static void StopDnsSinkhole()
        {
            try
            {
                isRunning = false;
                
                dnsServer?.Close();
                
                // Restore original hosts file
                RestoreHostsFile();
                
                EnhancedLogger.LogInfo("DNS Sinkhole protection stopped", Console.WriteLine);
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to stop DNS Sinkhole: {ex.Message}", Console.WriteLine);
            }
        }

        private static void InitializeBlockedDomains()
        {
            try
            {
                lock (domainLock)
                {
                    // Add known malicious domains
                    foreach (var domain in KnownMaliciousDomains)
                    {
                        BlockedDomains[domain.ToLower()] = "Known malicious domain";
                    }
                    
                    // Load additional domains from file if exists
                    var domainsFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus", "blocked_domains.txt");
                    if (File.Exists(domainsFile))
                    {
                        var domains = File.ReadAllLines(domainsFile);
                        foreach (var domain in domains)
                        {
                            if (!string.IsNullOrWhiteSpace(domain) && !domain.StartsWith("#"))
                            {
                                BlockedDomains[domain.Trim().ToLower()] = "From blocked domains file";
                            }
                        }
                    }
                    
                    EnhancedLogger.LogInfo($"Initialized {BlockedDomains.Count} blocked domains", Console.WriteLine);
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to initialize blocked domains: {ex.Message}", Console.WriteLine);
            }
        }

        private static void BackupHostsFile()
        {
            try
            {
                if (File.Exists(hostsFilePath))
                {
                    string? directory = Path.GetDirectoryName(backupHostsPath); // CS8604: Add null check
                    if (directory != null)
                    {
                        Directory.CreateDirectory(directory);
                        File.Copy(hostsFilePath, backupHostsPath, true);
                        EnhancedLogger.LogInfo("Hosts file backed up", Console.WriteLine);
                    }
                    else
                    {
                        EnhancedLogger.LogWarning("Backup hosts path directory is null. Skipping backup.", Console.WriteLine);
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to backup hosts file: {ex.Message}", Console.WriteLine);
            }
        }

        private static void RestoreHostsFile()
        {
            try
            {
                if (File.Exists(backupHostsPath))
                {
                    File.Copy(backupHostsPath, hostsFilePath, true);
                    EnhancedLogger.LogInfo("Hosts file restored", Console.WriteLine);
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to restore hosts file: {ex.Message}", Console.WriteLine);
            }
        }

        private static void StartDnsServer()
        {
            try
            {
                // Check if we're in a VM environment to avoid conflicts
                if (IsVirtualMachine())
                {
                    EnhancedLogger.LogWarning("Running in VM environment - DNS Sinkhole disabled for stability");
                    return;
                }

                dnsServer = new UdpClient(DnsPort);
                EnhancedLogger.LogInfo($"DNS server started on port {DnsPort}");
                
                // Start listening for DNS requests
                Task.Run(async () =>
                {
                    while (isRunning)
                    {
                        try
                        {
                            var result = await dnsServer.ReceiveAsync();
                            _ = Task.Run(() => HandleDnsRequest(result.Buffer, result.RemoteEndPoint));
                        }
                        catch (Exception ex)
                        {
                            if (isRunning) // Only log if were supposed to be running
                                EnhancedLogger.LogError($"DNS server error: {ex.Message}", Console.WriteLine);
                            break;
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start DNS server: {ex.Message}", Console.WriteLine);
                // Don't throw - just log the error and continue
            }
        }

        private static bool IsVirtualMachine()
        {
            try
            {
                // Check for common VM indicators
                var manufacturer = Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER") ?? "";
                var model = Environment.GetEnvironmentVariable("COMPUTERNAME") ?? "";
                
                return manufacturer.Contains("VMware") || 
                       manufacturer.Contains("Virtual") || 
                       model.Contains("VM") ||
                       model.Contains("Virtual");    
            }
            catch
            {
                return false;
            }
        }

        private static async void HandleDnsRequest(byte[] requestData, IPEndPoint clientEndPoint)
        {
            try
            {
                // Parse DNS request
                var dnsRequest = ParseDnsRequest(requestData);
                if (dnsRequest != null)
                {
                    var domain = dnsRequest.Domain;
                    var queryType = dnsRequest.QueryType;
                    var clientIp = clientEndPoint.Address.ToString();
                    
                    // Track DNS tunnel session
                    if (!string.IsNullOrEmpty(domain))
                    {
                        TrackDnsTunnelSession(clientIp, domain);
                    }
                    
                    // Check if domain is blocked
                    if (IsDomainBlocked(domain))
                    {
                        EnhancedLogger.LogWarning($"Blocked DNS request for domain: {domain}", Console.WriteLine);
                        
                        // Log the attempt
                        LogDomainAttempt(domain, clientIp);
                        
                        // Send sinkhole response
                        var sinkholeResponse = CreateSinkholeResponse(requestData);
                        await dnsServer.SendAsync(sinkholeResponse, sinkholeResponse.Length, clientEndPoint);
                        
                        // Trigger threat response
                        HandleBlockedDomain(domain, clientIp);
                    }
                    else
                    {
                        // Forward to upstream DNS server
                        var upstreamResponse = await ForwardToUpstreamDns(requestData);
                        if (upstreamResponse != null)
                        {
                            await dnsServer.SendAsync(upstreamResponse, upstreamResponse.Length, clientEndPoint);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error handling DNS request: {ex.Message}", Console.WriteLine);
            }
        }

        private static void TrackDnsTunnelSession(string clientIp, string domain)
        {
            try
            {
                lock (tunnelLock)
                {
                    if (!DnsTunnelSessions.ContainsKey(clientIp))
                    {
                        DnsTunnelSessions[clientIp] = new DnsTunnelInfo
                        {
                            ClientIp = clientIp,
                            FirstSeen = DateTime.Now,
                            LastSeen = DateTime.Now,
                            QueryCount = 0,
                            UniqueSubdomains = new HashSet<string>(),
                            RecentQueries = new List<string>(),
                            AverageEntropy = 0,
                            IsTunneling = false
                        };
                    }

                    var session = DnsTunnelSessions[clientIp];
                    session.LastSeen = DateTime.Now;
                    session.QueryCount++;
                    
                    // Extract subdomain
                    var subdomain = domain.Split('.')[0];
                    session.UniqueSubdomains.Add(subdomain);
                    session.RecentQueries.Add(domain);
                    
                    // Keep only recent queries
                    if (session.RecentQueries.Count > 100)
                    {
                        session.RecentQueries.RemoveAt(0);
                    }

                    // Calculate average entropy
                    var totalEntropy = 0.0;
                    var entropyCount = 0;
                    foreach (var query in session.RecentQueries.Take(10))
                    {
                        var subdomains = query.Split('.');
                        foreach (var sub in subdomains)
                        {
                            totalEntropy += CalculateEntropy(sub);
                            entropyCount++;
                        }
                    }
                    session.AverageEntropy = entropyCount > 0 ? totalEntropy / entropyCount : 0;

                    // Check for tunneling indicators
                    var isTunneling = false;
                    var reasons = new List<string>();

                    if (session.QueryCount > MaxQueriesPerMinute)
                    {
                        isTunneling = true;
                        reasons.Add($"High query rate: {session.QueryCount}");
                    }

                    if (session.UniqueSubdomains.Count > MaxUniqueSubdomains)
                    {
                        isTunneling = true;
                        reasons.Add($"Many unique subdomains: {session.UniqueSubdomains.Count}");
                    }

                    if (session.AverageEntropy > HighEntropyThreshold)
                    {
                        isTunneling = true;
                        reasons.Add($"High entropy: {session.AverageEntropy:F2}");
                    }

                    if (isTunneling && !session.IsTunneling)
                    {
                        session.IsTunneling = true;
                        EnhancedLogger.LogThreat($"DNS tunneling session detected from {clientIp}: {string.Join(", ", reasons)}");
                        
                        // Block the client
                        BlockDnsTunnelClient(clientIp);
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to track DNS tunnel session: {ex.Message}");
            }
        }

        private static void BlockDnsTunnelClient(string clientIp)
        {
            try
            {
                EnhancedLogger.LogWarning($"Blocking DNS tunneling client: {clientIp}");
                
                // Add to blocked clients list
                lock (domainLock)
                {
                    BlockedDomains[$"tunnel.{clientIp}.blocked"] = "DNS tunneling client";
                }
                
                // Log the incident
                var logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] DNS TUNNELING BLOCKED: {clientIp}";
                var logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus", "Logs", "dns_tunneling.log");
                File.AppendAllText(logPath, logEntry + Environment.NewLine);
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to block DNS tunneling client: {ex.Message}", Console.WriteLine);
            }
        }

        private static DnsRequest? ParseDnsRequest(byte[] data)
        {
            try
            {
                if (data.Length < 12) return null;
                
                var request = new DnsRequest();
                
                // Parse DNS header
                request.TransactionId = (data[0] << 8) | data[1];
                request.Flags = (data[2] << 8) | data[3];
                request.QuestionCount = (data[4] << 8) | data[5];
                
                // Parse domain name
                var domainParts = new List<string>();
                var position = 12;
                
                while (position < data.Length && data[position] != 0)
                {
                    var length = data[position];
                    position++;
                    
                    if (position + length <= data.Length)
                    {
                        var part = Encoding.ASCII.GetString(data, position, length);
                        domainParts.Add(part);
                        position += length;
                    }
                    else
                    {
                        break;
                    }
                }
                
                request.Domain = string.Join(".", domainParts);
                
                // Parse query type
                if (position + 4 <= data.Length)
                {
                    request.QueryType = (data[position] << 8) | data[position + 1];
                }
                
                return request;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to parse DNS request: {ex.Message}", Console.WriteLine);
                return null;
            }
        }

        private static bool IsDomainBlocked(string? domain)
        {
            try
            {
                if (string.IsNullOrEmpty(domain)) return false;
                
                var lowerDomain = domain.ToLower();
                
                lock (domainLock)
                {
                    // Check exact match
                    if (BlockedDomains.ContainsKey(lowerDomain))
                    {
                        return true;
                    }
                    
                    // Check pattern match
                    foreach (var pattern in MaliciousPatterns)
                    {
                        if (Regex.IsMatch(lowerDomain, pattern, RegexOptions.IgnoreCase))
                        {
                            // Add to blocked domains
                            BlockedDomains[lowerDomain] = $"Pattern match: {pattern}";
                            return true;
                        }
                    }
                }

                // Check for DNS tunneling
                if (DetectDnsTunneling(lowerDomain))
                {
                    return true;
                }
                
                return false;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to check if domain is blocked: {ex.Message}", Console.WriteLine);
                return false;
            }
        }

        private static bool DetectDnsTunneling(string domain)
        {
            try
            {
                // Check for excessive domain length
                if (domain.Length > MaxSubdomainLength)
                {
                    EnhancedLogger.LogThreat($"DNS tunneling detected: Excessive domain length ({domain.Length} chars): {domain}");
                    return true;
                }

                // Check for high entropy subdomains
                var subdomains = domain.Split('.');
                foreach (var subdomain in subdomains)
                {
                    if (subdomain.Length > MaxDnsQueryLength)
                    {
                        EnhancedLogger.LogThreat($"DNS tunneling detected: Excessive subdomain length ({subdomain.Length} chars): {subdomain}");
                        return true;
                    }

                    // Calculate entropy of subdomain
                    var entropy = CalculateEntropy(subdomain);
                    if (entropy > HighEntropyThreshold)
                    {
                        EnhancedLogger.LogThreat($"DNS tunneling detected: High entropy subdomain ({entropy:F2}): {subdomain}");
                        return true;
                    }

                    // Check for base64-like patterns
                    if (IsBase64Like(subdomain))
                    {
                        EnhancedLogger.LogThreat($"DNS tunneling detected: Base64-like subdomain: {subdomain}");
                        return true;
                    }

                    // Check for hex-like patterns
                    if (IsHexLike(subdomain))
                    {
                        EnhancedLogger.LogThreat($"DNS tunneling detected: Hex-like subdomain: {subdomain}");
                        return true;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"DNS tunneling detection failed: {ex.Message}");
                return false;
            }
        }

        private static double CalculateEntropy(string input)
        {
            try
            {
                var frequency = new Dictionary<char, int>();
                
                foreach (var c in input)
                {
                    if (frequency.ContainsKey(c))
                        frequency[c]++;
                    else
                        frequency[c] = 1;
                }

                double entropy = 0;
                var length = input.Length;
                
                foreach (var kvp in frequency)
                {
                    var probability = (double)kvp.Value / length;
                    entropy -= probability * Math.Log(probability, 2);
                }

                return entropy;
            }
            catch
            {
                return 0;
            }
        }

        private static bool IsBase64Like(string input)
        {
            try
            {
                // Check for base64-like patterns
                if (input.Length < 8) return false;
                
                var base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                var base64CharCount = 0;
                
                foreach (var c in input)
                {
                    if (base64Chars.Contains(c))
                        base64CharCount++;
                }
                
                var base64Ratio = (double)base64CharCount / input.Length;
                return base64Ratio > 0.8; // 80% of characters are base64-like
            }
            catch
            {
                return false;
            }
        }

        private static bool IsHexLike(string input)
        {
            try
            {
                // Check for hex-like patterns
                if (input.Length < 8) return false;
                
                var hexChars = "0123456789ABCDEFabcdef";
                var hexCharCount = 0;
                
                foreach (var c in input)
                {
                    if (hexChars.Contains(c))
                        hexCharCount++;
                }
                
                var hexRatio = (double)hexCharCount / input.Length;
                return hexRatio > 0.9; // 90% of characters are hex-like
            }
            catch
            {
                return false;
            }
        }

        private static void LogDomainAttempt(string? domain, string clientIp)
        {
            try
            {
                if (string.IsNullOrEmpty(domain)) return;
                
                lock (domainLock)
                {
                    DomainAttempts[domain] = DateTime.Now;
                }
                
                var logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] Blocked domain: {domain} from {clientIp}\n";
                var logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus", "Logs", "dns_blocked.log");
                string? directory = Path.GetDirectoryName(logPath); // CS8604: Add null check
                if (directory != null)
                {
                    Directory.CreateDirectory(directory);
                    File.AppendAllText(logPath, logEntry);
                }
                else
                {
                    EnhancedLogger.LogWarning("Log path directory is null. Skipping domain attempt logging.", Console.WriteLine);
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to log domain attempt: {ex.Message}", Console.WriteLine);
            }
        }

        private static byte[] CreateSinkholeResponse(byte[] requestData)
        {
            try
            {
                // Create a simple DNS response that points to localhost
                var response = new byte[requestData.Length];
                Array.Copy(requestData, response, requestData.Length);
                
                // Set response flags (QR=1, AA=1, RCODE=0)
                response[2] = 0x80; // QR=1, OPCODE=0
                response[3] = 0x80; // AA=1, TC=0, RD=0, RA=0, Z=0, RCODE=0
                
                // Set answer count to 1
                response[6] = 0x00;
                response[7] = 0x01;
                
                // Add answer section pointing to 127.0.0.1
                var answerSection = new byte[]
                {
                    0xC0, 0x0C, // Name pointer to question
                    0x00, 0x01, // Type A
                    0x00, 0x01, // Class IN
                    0x00, 0x00, 0x00, 0x3C, // TTL (60 seconds)
                    0x00, 0x04, // Data length
                    0x7F, 0x00, 0x00, 0x01  // 127.0.0.1
                };
                
                var finalResponse = new byte[response.Length + answerSection.Length];
                Array.Copy(response, finalResponse, response.Length);
                Array.Copy(answerSection, 0, finalResponse, response.Length, answerSection.Length);
                
                return finalResponse;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to create sinkhole response: {ex.Message}", Console.WriteLine);
                return requestData; // Return original request as fallback
            }
        }

        private static async Task<byte[]?> ForwardToUpstreamDns(byte[] requestData)
        {
            try
            {
                foreach (var upstreamServer in UpstreamDnsServers)
                {
                    try
                    {
                        using var client = new UdpClient();
                        client.Client.ReceiveTimeout = 5000;
                        client.Client.SendTimeout = 5000;
                        
                        await client.SendAsync(requestData, requestData.Length, upstreamServer, 53);
                        var response = await client.ReceiveAsync();
                        
                        return response.Buffer;
                    }
                    catch (Exception ex)
                    {
                        EnhancedLogger.LogError($"Failed to forward to {upstreamServer}: {ex.Message}", Console.WriteLine);
                        continue;
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to forward DNS request: {ex.Message}", Console.WriteLine);
            }
            
            return null;
        }

        private static void HandleBlockedDomain(string domain, string clientIp)
        {
            try
            {
                // Create threat data for mesh sharing
                var threatData = new ThreatData
                {
                    ThreatHash = $"dns_{DateTime.Now.Ticks}",
                    ThreatType = "DNS Sinkhole Block",
                    TargetPath = domain,
                    ThreatLevel = "High",
                    Description = $"Blocked malicious domain: {domain} from {clientIp}"
                };
                
                // Share with mesh network
                PhageSync.ShareThreat(threatData);
                
                // Add to hosts file for permanent blocking
                AddToHostsFile(domain);
                
                EnhancedLogger.LogWarning($"DNS sinkhole blocked domain: {domain} from {clientIp}", Console.WriteLine);
                
                // Send telemetry to cloud for DNS analysis
                Task.Run(async () =>
                {
                    try
                    {
                        var dnsData = new
                        {
                            domain = domain,
                            client_ip = clientIp,
                            blocked_domains_count = BlockedDomains.Count,
                            recent_attempts_count = DomainAttempts.Count,
                            dns_tunnel_sessions_count = DnsTunnelSessions.Count,
                            threat_type = "malicious_domain",
                            timestamp = DateTime.UtcNow
                        };

                        await CloudIntegration.SendTelemetryAsync("DnsSinkhole", "malicious_domain", dnsData, ThreatLevel.High);
                        
                        // Get cloud DNS threat intelligence
                        var threatIntel = await CloudIntegration.GetThreatIntelligenceAsync(domain, "malicious_domain");
                        if (threatIntel.Success)
                        {
                            EnhancedLogger.LogInfo($"Cloud DNS threat intel for {domain}: {threatIntel.ThreatName} - Confidence: {threatIntel.Confidence:P1}");
                        }
                    }
                    catch (Exception ex)
                    {
                        EnhancedLogger.LogWarning($"Cloud DNS analysis failed for {domain}: {ex.Message}");
                    }
                });
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to handle blocked domain: {ex.Message}", Console.WriteLine);
            }
        }

        private static void AddToHostsFile(string domain)
        {
            try
            {
                var hostsEntry = $"127.0.0.1 {domain}";
                var hostsContent = File.ReadAllText(hostsFilePath);
                
                if (!hostsContent.Contains(hostsEntry))
                {
                    File.AppendAllText(hostsFilePath, $"\n{hostsEntry}");
                    EnhancedLogger.LogInfo($"Added {domain} to hosts file", Console.WriteLine);
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to add domain to hosts file: {ex.Message}", Console.WriteLine);
            }
        }

        private static async Task MonitorDomainAttempts()
        {
            while (isRunning)
            {
                try
                {
                    lock (domainLock)
                    {
                        var cutoff = DateTime.Now.AddMinutes(-5);
                        var oldAttempts = DomainAttempts.Where(kvp => kvp.Value < cutoff).ToList();
                        
                        foreach (var attempt in oldAttempts)
                        {
                            DomainAttempts.Remove(attempt.Key);
                        }
                    }
                    
                    await Task.Delay(60000); // Check every minute
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Error in domain attempts monitoring: {ex.Message}", Console.WriteLine);
                    await Task.Delay(300000); // Wait longer on error
                }
            }
        }

        private static async Task UpdateMaliciousDomains()
        {
            while (isRunning)
            {
                try
                {
                    // Update from online threat feeds (simulated)
                    await UpdateFromThreatFeeds();
                    
                    // Update from local sources
                    UpdateFromLocalSources();
                    
                    await Task.Delay(3600000); // Update every hour
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Error updating malicious domains: {ex.Message}", Console.WriteLine);
                    await Task.Delay(7200000); // Wait longer on error
                }
            }
        }

        private static async Task UpdateFromThreatFeeds()
        {
            try
            {
                // Simulate updating from threat feeds
                var newDomains = new[]
                {
                    "newmalware.example.com",
                    "freshc2.attacker.net",
                    "latestphishing.scam.org"
                };
                
                lock (domainLock)
                {
                    foreach (var domain in newDomains)
                    {
                        if (!BlockedDomains.ContainsKey(domain.ToLower()))
                        {
                            BlockedDomains[domain.ToLower()] = "From threat feed";
                        }
                    }
                }
                
                EnhancedLogger.LogInfo($"Updated {newDomains.Length} domains from threat feeds", Console.WriteLine);
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to update from threat feeds: {ex.Message}", Console.WriteLine);
            }
        }

        private static void UpdateFromLocalSources()
        {
            try
            {
                // Check for new domains in local files
                var domainsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus", "Domains");
                string? directory = Path.GetDirectoryName(domainsDir); // CS8604: Add null check
                if (directory != null)
                {
                    Directory.CreateDirectory(domainsDir);
                    var domainFiles = Directory.GetFiles(domainsDir, "*.txt");
                    foreach (var file in domainFiles)
                    {
                        var domains = File.ReadAllLines(file);
                        lock (domainLock)
                        {
                            foreach (var domain in domains)
                            {
                                if (!string.IsNullOrWhiteSpace(domain) && !domain.StartsWith("#"))
                                {
                                    var cleanDomain = domain.Trim().ToLower();
                                    if (!BlockedDomains.ContainsKey(cleanDomain))
                                    {
                                        BlockedDomains[cleanDomain] = $"From {Path.GetFileName(file)}";
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    EnhancedLogger.LogWarning("Domains directory path is null. Skipping local sources update.", Console.WriteLine);
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to update from local sources: {ex.Message}", Console.WriteLine);
            }
        }

        public static void AddBlockedDomain(string domain, string reason = "Manual addition")
        {
            try
            {
                if (string.IsNullOrEmpty(domain)) return;
                
                lock (domainLock)
                {
                    BlockedDomains[domain.ToLower()] = reason;
                }
                
                AddToHostsFile(domain);
                EnhancedLogger.LogInfo($"Added domain to blocklist: {domain} ({reason})", Console.WriteLine);
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to add blocked domain: {ex.Message}", Console.WriteLine);
            }
        }

        public static void RemoveBlockedDomain(string domain)
        {
            try
            {
                if (string.IsNullOrEmpty(domain)) return;
                
                lock (domainLock)
                {
                    BlockedDomains.Remove(domain.ToLower());
                }
                
                EnhancedLogger.LogInfo($"Removed domain from blocklist: {domain}", Console.WriteLine);
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to remove blocked domain: {ex.Message}", Console.WriteLine);
            }
        }

        public static List<string> GetBlockedDomains()
        {
            lock (domainLock)
            {
                return BlockedDomains.Keys.ToList(); // CS8603: Non-null return
            }
        }

        public static Dictionary<string, DateTime> GetRecentAttempts()
        {
            lock (domainLock)
            {
                return new Dictionary<string, DateTime>(DomainAttempts); // CS8603: Non-null return
            }
        }

        public static bool IsDnsSinkholeActive()
        {
            return isRunning;
        }
    }

    public class DnsRequest
    {
        public int TransactionId { get; set; }
        public int Flags { get; set; }
        public int QuestionCount { get; set; }
        public string? Domain { get; set; } // CS8603: Allow nullable to match ParseDnsRequest
        public int QueryType { get; set; }
    }
}

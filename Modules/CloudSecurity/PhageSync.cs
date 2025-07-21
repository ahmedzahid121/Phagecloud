using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Linq;
using System.Globalization;

namespace PhageVirus.Modules
{
    public class PhageSync
    {
        private static readonly int SyncPort = 8443;
        private static readonly string SyncGroup = "239.255.255.250"; // Multicast group
        private static readonly string LocalNodeId;
        private static readonly Dictionary<string, ThreatData> SharedThreats = new();
        private static readonly Dictionary<string, DateTime> PeerLastSeen = new();
        
        private static UdpClient? multicastClient;
        private static TcpListener? tcpListener;
        private static bool isRunning = false;
        private static readonly object syncLock = new object();
        
        // Encryption key for secure communication
        private static readonly byte[] EncryptionKey = Encoding.UTF8.GetBytes("PhageVirus2024!SecureKey");
        
        static PhageSync()
        {
            LocalNodeId = Environment.MachineName + "_" + Guid.NewGuid().ToString("N")[..8];
        }

        public static bool StartMeshNetwork()
        {
            try
            {
                EnhancedLogger.LogInfo("Starting PhageVirus mesh network...", Console.WriteLine);
                
                // Start multicast listener for peer discovery
                StartMulticastListener();
                
                // Start TCP listener for threat data exchange
                StartTcpListener();
                
                // Start periodic peer discovery
                Task.Run(PeriodicPeerDiscovery);
                
                // Start periodic threat broadcast
                Task.Run(PeriodicThreatBroadcast);
                
                isRunning = true;
                EnhancedLogger.LogInfo($"PhageVirus mesh network started. Node ID: {LocalNodeId}", Console.WriteLine);
                
                // Send telemetry to cloud for mesh network status
                Task.Run(async () =>
                {
                    try
                    {
                        var meshData = new
                        {
                            local_node_id = LocalNodeId,
                            sync_port = SyncPort,
                            sync_group = SyncGroup,
                            shared_threats_count = SharedThreats.Count,
                            peer_last_seen_count = PeerLastSeen.Count,
                            threat_type = "mesh_network_status",
                            timestamp = DateTime.UtcNow
                        };

                        await CloudIntegration.SendTelemetryAsync("PhageSync", "mesh_network_status", meshData, ThreatLevel.Normal);
                        
                        // Get cloud mesh network analysis
                        var analysis = await CloudIntegration.GetCloudAnalysisAsync("PhageSync", meshData);
                        if (analysis.Success)
                        {
                            EnhancedLogger.LogInfo($"Cloud mesh network analysis: {analysis.Analysis}");
                        }
                    }
                    catch (Exception ex)
                    {
                        EnhancedLogger.LogWarning($"Cloud mesh network analysis failed: {ex.Message}");
                    }
                });
                
                return true;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start mesh network: {ex.Message}", Console.WriteLine);
                return false;
            }
        }

        public static void StopMeshNetwork()
        {
            isRunning = false;
            multicastClient?.Close();
            tcpListener?.Stop();
            EnhancedLogger.LogInfo("PhageVirus mesh network stopped", Console.WriteLine);
        }

        public static void ShareThreat(ThreatData threat)
        {
            try
            {
                lock (syncLock)
                {
                    if (!SharedThreats.ContainsKey(threat.ThreatHash))
                    {
                        threat.NodeId = LocalNodeId;
                        threat.Timestamp = DateTime.UtcNow.ToString("o");
                        SharedThreats[threat.ThreatHash] = threat;
                        
                        // Broadcast to all known peers
                        BroadcastThreat(threat);
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to share threat: {ex.Message}", Console.WriteLine);
            }
        }

        private static void StartMulticastListener()
        {
            try
            {
                multicastClient = new UdpClient();
                multicastClient.JoinMulticastGroup(IPAddress.Parse(SyncGroup));
                multicastClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                multicastClient.Client.Bind(new IPEndPoint(IPAddress.Any, SyncPort));
                
                Task.Run(async () =>
                {
                    while (isRunning)
                    {
                        try
                        {
                            var result = await multicastClient.ReceiveAsync();
                            var message = Encoding.UTF8.GetString(result.Buffer);
                            ProcessMulticastMessage(message, result.RemoteEndPoint);
                        }
                        catch (Exception ex)
                        {
                            if (isRunning)
                                EnhancedLogger.LogError($"Multicast receive error: {ex.Message}", Console.WriteLine);
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start multicast listener: {ex.Message}", Console.WriteLine);
            }
        }

        private static void StartTcpListener()
        {
            try
            {
                tcpListener = new TcpListener(IPAddress.Any, SyncPort);
                tcpListener.Start();
                
                Task.Run(async () =>
                {
                    while (isRunning)
                    {
                        try
                        {
                            var client = await tcpListener.AcceptTcpClientAsync();
                            _ = Task.Run(() => HandleTcpClient(client));
                        }
                        catch (Exception ex)
                        {
                            if (isRunning)
                                EnhancedLogger.LogError($"TCP listener error: {ex.Message}", Console.WriteLine);
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start TCP listener: {ex.Message}", Console.WriteLine);
            }
        }

        private static async void HandleTcpClient(TcpClient client)
        {
            try
            {
                using var stream = client.GetStream();
                var buffer = new byte[4096];
                var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                var message = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                
                var threatData = JsonSerializer.Deserialize<ThreatData>(message);
                if (threatData != null && threatData.NodeId != LocalNodeId)
                {
                    ProcessIncomingThreat(threatData);
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"TCP client handling error: {ex.Message}", Console.WriteLine);
            }
            finally
            {
                client.Close();
            }
        }

        private static void ProcessMulticastMessage(string message, IPEndPoint sender)
        {
            try
            {
                var parts = message.Split('|');
                if (parts.Length >= 2 && parts[0] == "PHAGE_DISCOVERY")
                {
                    var peerId = parts[1];
                    if (peerId != LocalNodeId)
                    {
                        lock (syncLock)
                        {
                            PeerLastSeen[peerId] = DateTime.UtcNow;
                        }
                        
                        // Send our threats to the new peer
                        SendThreatsToPeer(sender.Address);
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to process multicast message: {ex.Message}", Console.WriteLine);
            }
        }

        private static void ProcessIncomingThreat(ThreatData threat)
        {
            try
            {
                lock (syncLock)
                {
                    if (!SharedThreats.ContainsKey(threat.ThreatHash))
                    {
                        SharedThreats[threat.ThreatHash] = threat;
                        EnhancedLogger.LogInfo($"Received threat from peer {threat.NodeId}: {threat.ThreatType}", Console.WriteLine);
                        
                        // Trigger local threat response
                        TriggerLocalThreatResponse(threat);
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to process incoming threat: {ex.Message}", Console.WriteLine);
            }
        }

        private static void TriggerLocalThreatResponse(ThreatData threat)
        {
            try
            {
                // Add to local threat timeline
                var timelineItem = new ThreatTimelineItem
                {
                    Timestamp = DateTime.Now.ToString("o"),
                    ThreatType = $"Mesh: {threat.ThreatType}",
                    Target = threat.TargetPath,
                    Action = $"Received from {threat.NodeId}",
                    Status = "Shared"
                };
                
                // Trigger immediate scan if it's a critical threat
                if (threat.ThreatLevel == "Critical")
                {
                    EnhancedLogger.LogWarning($"Critical threat received from mesh: {threat.ThreatType}", Console.WriteLine);
                    // Trigger immediate scan of the reported path
                    if (File.Exists(threat.TargetPath))
                    {
                        VirusHunter.ScanFile(threat.TargetPath);
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to trigger local threat response: {ex.Message}", Console.WriteLine);
            }
        }

        private static async void PeriodicPeerDiscovery()
        {
            while (isRunning)
            {
                try
                {
                    var discoveryMessage = $"PHAGE_DISCOVERY|{LocalNodeId}|{DateTime.UtcNow:yyyyMMddHHmmss}";
                    var data = Encoding.UTF8.GetBytes(discoveryMessage);
                    
                    multicastClient?.Send(data, data.Length, SyncGroup, SyncPort);
                    
                    // Clean up old peers (not seen for 5 minutes)
                    lock (syncLock)
                    {
                        var cutoff = DateTime.UtcNow.AddMinutes(-5);
                        var oldPeers = PeerLastSeen.Where(p => p.Value < cutoff).ToList();
                        foreach (var peer in oldPeers)
                        {
                            PeerLastSeen.Remove(peer.Key);
                        }
                    }
                    
                    await Task.Delay(30000); // Every 30 seconds
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Peer discovery error: {ex.Message}", Console.WriteLine);
                    await Task.Delay(60000); // Wait longer on error
                }
            }
        }

        private static async void PeriodicThreatBroadcast()
        {
            while (isRunning)
            {
                try
                {
                    // Broadcast recent threats to all known peers
                    lock (syncLock)
                    {
                        var recentThreats = SharedThreats.Values
                            .Where(t => DateTime.TryParse(t.Timestamp, out var threatTime) && threatTime > DateTime.UtcNow.AddMinutes(-10))
                            .ToList();
                        
                        foreach (var threat in recentThreats)
                        {
                            BroadcastThreat(threat);
                        }
                    }
                    
                    await Task.Delay(60000); // Every minute
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Threat broadcast error: {ex.Message}", Console.WriteLine);
                    await Task.Delay(120000); // Wait longer on error
                }
            }
        }

        private static void BroadcastThreat(ThreatData threat)
        {
            try
            {
                var threatJson = JsonSerializer.Serialize(threat);
                var encryptedData = EncryptData(threatJson);
                
                // Send to all known peers
                lock (syncLock)
                {
                    foreach (var peer in PeerLastSeen.Keys)
                    {
                        // In a real implementation, you'd maintain peer IP addresses
                        // For now, we'll use multicast
                        var data = Encoding.UTF8.GetBytes($"PHAGE_THREAT|{encryptedData}");
                        multicastClient?.Send(data, data.Length, SyncGroup, SyncPort);
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to broadcast threat: {ex.Message}", Console.WriteLine);
            }
        }

        private static async void SendThreatsToPeer(IPAddress peerAddress)
        {
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(peerAddress, SyncPort);
                
                using var stream = client.GetStream();
                lock (syncLock)
                {
                    foreach (var threat in SharedThreats.Values)
                    {
                        var threatJson = JsonSerializer.Serialize(threat);
                        var data = Encoding.UTF8.GetBytes(threatJson);
                        stream.Write(data, 0, data.Length);
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to send threats to peer: {ex.Message}", Console.WriteLine);
            }
        }

        private static byte[] EncryptData(string data)
        {
            try
            {
                using var aes = Aes.Create();
                aes.Key = EncryptionKey;
                aes.GenerateIV();
                
                using var encryptor = aes.CreateEncryptor();
                var plainBytes = Encoding.UTF8.GetBytes(data);
                var encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                
                var result = new byte[aes.IV.Length + encryptedBytes.Length];
                Array.Copy(aes.IV, 0, result, 0, aes.IV.Length);
                Array.Copy(encryptedBytes, 0, result, aes.IV.Length, encryptedBytes.Length);
                
                return result;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Encryption failed: {ex.Message}", Console.WriteLine);
                return Encoding.UTF8.GetBytes(data); // Fallback to plain text
            }
        }

        public static List<ThreatData> GetSharedThreats()
        {
            lock (syncLock)
            {
                return SharedThreats.Values.ToList();
            }
        }

        public static List<string> GetActivePeers()
        {
            lock (syncLock)
            {
                return PeerLastSeen.Keys.ToList();
            }
        }

        public static bool IsMeshActive()
        {
            return isRunning;
        }
    }

    public class ThreatTimelineItem
    {
        public string Timestamp { get; set; } = "";
        public string ThreatType { get; set; } = "";
        public string Target { get; set; } = "";
        public string Action { get; set; } = "";
        public string Status { get; set; } = "";
    }
} 

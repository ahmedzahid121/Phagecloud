using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using PhageVirus.Agent.Shared;
using System.IO;

namespace PhageVirus.Agent.Cloud
{
    /// <summary>
    /// Telemetry collector that sends data to AWS services
    /// Primary cloud integration for PhageVirus agent telemetry
    /// </summary>
    public class TelemetryCollector
    {
        private readonly ILogger<TelemetryCollector> _logger;
        private readonly IConfiguration _configuration;
        private readonly AWSCommunicator _awsCommunicator;
        private readonly JsonSerializerOptions _jsonOptions;
        
        private readonly Queue<TelemetryData> _telemetryQueue = new();
        private readonly object _queueLock = new object();
        private readonly Timer _batchTimer;
        private readonly Timer _heartbeatTimer;
        
        private bool _isRunning = false;
        private int _batchSize;
        private int _uploadInterval;
        private int _heartbeatInterval;

        public TelemetryCollector(IConfiguration configuration, ILogger<TelemetryCollector> logger)
        {
            _configuration = configuration;
            _logger = logger;
            _awsCommunicator = new AWSCommunicator(configuration, logger);
            
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = false
            };

            // Load configuration - AWS-focused
            _batchSize = _configuration.GetValue<int>("cloud:aws:telemetry:batch_size", 50);
            _uploadInterval = _configuration.GetValue<int>("telemetry:log_upload_interval", 300);
            _heartbeatInterval = _configuration.GetValue<int>("telemetry:heartbeat_interval", 60);

            // Initialize timers
            _batchTimer = new Timer(ProcessBatchAsync, null, Timeout.Infinite, Timeout.Infinite);
            _heartbeatTimer = new Timer(CollectSystemMetricsAsync, null, Timeout.Infinite, Timeout.Infinite);
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            if (_isRunning)
            {
                _logger.LogWarning("Telemetry collector is already running");
                return;
            }

            _logger.LogInformation("Starting AWS telemetry collector");
            _isRunning = true;

            try
            {
                // Initialize AWS communicator
                await _awsCommunicator.InitializeAsync();

                // Start timers
                _batchTimer.Change(TimeSpan.FromSeconds(_uploadInterval), TimeSpan.FromSeconds(_uploadInterval));
                _heartbeatTimer.Change(TimeSpan.FromSeconds(_heartbeatInterval), TimeSpan.FromSeconds(_heartbeatInterval));

                // Start background processing
                _ = Task.Run(() => BackgroundProcessingAsync(cancellationToken), cancellationToken);

                _logger.LogInformation("AWS telemetry collector started successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to start AWS telemetry collector");
                throw;
            }
        }

        public async Task StopAsync()
        {
            if (!_isRunning)
            {
                return;
            }

            _logger.LogInformation("Stopping AWS telemetry collector");
            _isRunning = false;

            try
            {
                // Stop timers
                _batchTimer.Change(Timeout.Infinite, Timeout.Infinite);
                _heartbeatTimer.Change(Timeout.Infinite, Timeout.Infinite);

                // Process remaining telemetry
                await ProcessBatchAsync(null);

                _logger.LogInformation("AWS telemetry collector stopped successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error stopping AWS telemetry collector");
            }
        }

        public void AddTelemetry(TelemetryData telemetry)
        {
            if (!_isRunning)
            {
                return;
            }

            lock (_queueLock)
            {
                _telemetryQueue.Enqueue(telemetry);

                // If queue is getting too large, trigger immediate processing
                if (_telemetryQueue.Count >= _batchSize)
                {
                    _batchTimer.Change(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(_uploadInterval));
                }
            }
        }

        public void AddProcessTelemetry(List<ProcessInfo> processes)
        {
            if (!_isRunning || processes == null || processes.Count == 0)
            {
                return;
            }

            var telemetry = new TelemetryData
            {
                AgentId = Environment.MachineName + "_" + Environment.UserName,
                Timestamp = DateTime.UtcNow,
                DataType = TelemetryType.Process.ToString(),
                Data = new Dictionary<string, object>
                {
                    ["ProcessCount"] = processes.Count,
                    ["Processes"] = processes.Take(20).ToList(), // Limit to first 20 processes
                    ["HighMemoryProcesses"] = processes.Where(p => p.MemoryUsage > 100 * 1024 * 1024).Count(),
                    ["HighCpuProcesses"] = processes.Where(p => p.CpuUsage > 10.0).Count()
                },
                IsCompressed = false,
                IsEncrypted = false,
                Checksum = string.Empty
            };

            AddTelemetry(telemetry);
        }

        public void AddMemoryTelemetry(List<MemoryRegionInfo> memoryRegions)
        {
            if (!_isRunning || memoryRegions == null || memoryRegions.Count == 0)
            {
                return;
            }

            var telemetry = new TelemetryData
            {
                AgentId = Environment.MachineName + "_" + Environment.UserName,
                Timestamp = DateTime.UtcNow,
                DataType = TelemetryType.Memory.ToString(),
                Data = new Dictionary<string, object>
                {
                    ["RegionCount"] = memoryRegions.Count,
                    ["SuspiciousRegions"] = memoryRegions.Where(r => r.IsSuspicious).Count(),
                    ["HighEntropyRegions"] = memoryRegions.Where(r => r.Entropy > 7.5).Count(),
                    ["TotalSize"] = memoryRegions.Sum(r => r.RegionSize)
                },
                IsCompressed = false,
                IsEncrypted = false,
                Checksum = string.Empty
            };

            AddTelemetry(telemetry);
        }

        public void AddNetworkTelemetry(List<NetworkConnectionInfo> connections)
        {
            if (!_isRunning || connections == null || connections.Count == 0)
            {
                return;
            }

            var telemetry = new TelemetryData
            {
                AgentId = Environment.MachineName + "_" + Environment.UserName,
                Timestamp = DateTime.UtcNow,
                DataType = TelemetryType.Network.ToString(),
                Data = new Dictionary<string, object>
                {
                    ["ConnectionCount"] = connections.Count,
                    ["SuspiciousConnections"] = connections.Where(c => c.IsSuspicious).Count(),
                    ["TcpConnections"] = connections.Where(c => c.Protocol == "TCP").Count(),
                    ["UdpConnections"] = connections.Where(c => c.Protocol == "UDP").Count(),
                    ["EstablishedConnections"] = connections.Where(c => c.State == "ESTABLISHED").Count()
                },
                IsCompressed = false,
                IsEncrypted = false,
                Checksum = string.Empty
            };

            AddTelemetry(telemetry);
        }

        public void AddSystemTelemetry()
        {
            if (!_isRunning)
            {
                return;
            }

            var telemetry = new TelemetryData
            {
                AgentId = Environment.MachineName + "_" + Environment.UserName,
                Timestamp = DateTime.UtcNow,
                DataType = TelemetryType.System.ToString(),
                Data = new Dictionary<string, object>
                {
                    ["CpuUsage"] = GetCpuUsage(),
                    ["MemoryUsage"] = GetMemoryUsage(),
                    ["AvailableMemory"] = GetAvailableMemory(),
                    ["DiskSpace"] = GetDiskSpace(),
                    ["DiskUsage"] = GetDiskUsage(),
                    ["NetworkActivity"] = GetNetworkActivity(),
                    ["Uptime"] = Environment.TickCount / 1000.0 / 60.0, // Minutes
                    ["ProcessCount"] = Process.GetProcesses().Length
                },
                IsCompressed = false,
                IsEncrypted = false,
                Checksum = string.Empty
            };

            AddTelemetry(telemetry);
        }

        private async void ProcessBatchAsync(object? state)
        {
            if (!_isRunning)
            {
                return;
            }

            try
            {
                List<TelemetryData> batch;
                lock (_queueLock)
                {
                    batch = _telemetryQueue.Take(_batchSize).ToList();
                    foreach (var item in batch)
                    {
                        _telemetryQueue.Dequeue();
                    }
                }

                if (batch.Count > 0)
                {
                    await SendBatchAsync(batch);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing telemetry batch");
            }
        }

        private async void CollectSystemMetricsAsync(object? state)
        {
            if (!_isRunning)
            {
                return;
            }

            try
            {
                AddSystemTelemetry();
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error collecting system metrics");
            }
        }

        private async Task BackgroundProcessingAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested && _isRunning)
            {
                try
                {
                    // Collect process telemetry
                    await CollectProcessTelemetryAsync();

                    // Collect performance telemetry
                    await CollectPerformanceTelemetryAsync();

                    // Wait before next collection
                    await Task.Delay(TimeSpan.FromMinutes(5), cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in background telemetry processing");
                    await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken);
                }
            }
        }

        private async Task CollectProcessTelemetryAsync()
        {
            try
            {
                var processes = Process.GetProcesses()
                    .Take(50) // Limit to first 50 processes
                    .Select(p => new ProcessInfo
                    {
                        ProcessId = p.Id,
                        ProcessName = p.ProcessName,
                        MemoryUsage = p.WorkingSet64,
                        CpuUsage = 0.0, // Would need performance counters for accurate CPU
                        StartTime = p.StartTime,
                        IsSuspicious = false // Would need analysis logic
                    })
                    .ToList();

                AddProcessTelemetry(processes);
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error collecting process telemetry");
            }
        }

        private async Task CollectPerformanceTelemetryAsync()
        {
            try
            {
                // Add system telemetry
                AddSystemTelemetry();

                // Add memory telemetry (simplified)
                var memoryRegions = new List<MemoryRegionInfo>
                {
                    new MemoryRegionInfo
                    {
                        RegionSize = GetMemoryUsage(),
                        IsSuspicious = false,
                        Entropy = 0.0
                    }
                };

                AddMemoryTelemetry(memoryRegions);

                // Add network telemetry (simplified)
                var connections = new List<NetworkConnectionInfo>
                {
                    new NetworkConnectionInfo
                    {
                        Protocol = "TCP",
                        State = "ESTABLISHED",
                        IsSuspicious = false
                    }
                };

                AddNetworkTelemetry(connections);

                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error collecting performance telemetry");
            }
        }

        private async Task SendBatchAsync(List<TelemetryData> batch)
        {
            if (batch.Count == 0)
            {
                return;
            }

            try
            {
                // Send to AWS services
                var success = await _awsCommunicator.SendBatchTelemetryAsync(batch);

                if (success)
                {
                    _logger.LogDebug($"Successfully sent {batch.Count} telemetry items to AWS");
                }
                else
                {
                    _logger.LogWarning($"Failed to send {batch.Count} telemetry items to AWS");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending telemetry batch to AWS");
            }
        }

        private double GetCpuUsage()
        {
            try
            {
                using var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                return cpuCounter.NextValue();
            }
            catch
            {
                return 0.0;
            }
        }

        private long GetMemoryUsage()
        {
            try
            {
                using var memoryCounter = new PerformanceCounter("Memory", "Available MBytes");
                var availableMB = memoryCounter.NextValue();
                var totalMemory = GC.GetTotalMemory(false);
                return totalMemory - (long)(availableMB * 1024 * 1024);
            }
            catch
            {
                return GC.GetTotalMemory(false);
            }
        }

        private long GetAvailableMemory()
        {
            try
            {
                using var memoryCounter = new PerformanceCounter("Memory", "Available MBytes");
                return (long)(memoryCounter.NextValue() * 1024 * 1024);
            }
            catch
            {
                return 0;
            }
        }

        private long GetDiskSpace()
        {
            try
            {
                var drive = new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory) ?? "C:");
                return drive.TotalSize;
            }
            catch
            {
                return 0;
            }
        }

        private double GetDiskUsage()
        {
            try
            {
                var drive = new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory) ?? "C:");
                return (double)(drive.TotalSize - drive.AvailableFreeSpace) / drive.TotalSize * 100;
            }
            catch
            {
                return 0.0;
            }
        }

        private double GetNetworkActivity()
        {
            try
            {
                using var networkCounter = new PerformanceCounter("Network Interface", "Bytes Total/sec", "_Total");
                return networkCounter.NextValue();
            }
            catch
            {
                return 0.0;
            }
        }
    }
} 
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

namespace PhageVirus.Agent.Cloud
{
    public class TelemetryCollector
    {
        private readonly ILogger<TelemetryCollector> _logger;
        private readonly IConfiguration _configuration;
        private readonly AzureCommunicator _azureCommunicator;
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
            _azureCommunicator = new AzureCommunicator(configuration, logger);
            _awsCommunicator = new AWSCommunicator(configuration, logger);
            
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = false
            };

            // Load configuration
            _batchSize = _configuration.GetValue<int>("cloud:azure:telemetry:batch_size", 100);
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

            _logger.LogInformation("Starting telemetry collector");
            _isRunning = true;

            try
            {
                // Start timers
                _batchTimer.Change(TimeSpan.FromSeconds(_uploadInterval), TimeSpan.FromSeconds(_uploadInterval));
                _heartbeatTimer.Change(TimeSpan.FromSeconds(_heartbeatInterval), TimeSpan.FromSeconds(_heartbeatInterval));

                // Start background processing
                _ = Task.Run(() => BackgroundProcessingAsync(cancellationToken), cancellationToken);

                _logger.LogInformation("Telemetry collector started successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to start telemetry collector");
                throw;
            }
        }

        public async Task StopAsync()
        {
            if (!_isRunning)
            {
                return;
            }

            _logger.LogInformation("Stopping telemetry collector");
            _isRunning = false;

            try
            {
                // Stop timers
                _batchTimer.Change(Timeout.Infinite, Timeout.Infinite);
                _heartbeatTimer.Change(Timeout.Infinite, Timeout.Infinite);

                // Process remaining telemetry
                await ProcessBatchAsync(null);

                _logger.LogInformation("Telemetry collector stopped successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error stopping telemetry collector");
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
                    ["UdpConnections"] = connections.Where(c => c.Protocol == "UDP").Count()
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

            try
            {
                var process = Process.GetCurrentProcess();
                var telemetry = new TelemetryData
                {
                    AgentId = Environment.MachineName + "_" + Environment.UserName,
                    Timestamp = DateTime.UtcNow,
                    DataType = TelemetryType.System.ToString(),
                    Data = new Dictionary<string, object>
                    {
                        ["CpuUsage"] = GetCpuUsage(),
                        ["MemoryUsage"] = process.WorkingSet64,
                        ["AvailableMemory"] = GetAvailableMemory(),
                        ["DiskSpace"] = GetDiskSpace(),
                        ["ProcessCount"] = Process.GetProcesses().Length,
                        ["Uptime"] = Environment.TickCount64
                    },
                    IsCompressed = false,
                    IsEncrypted = false,
                    Checksum = string.Empty
                };

                AddTelemetry(telemetry);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error collecting system telemetry");
            }
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
                    batch = new List<TelemetryData>();
                    while (batch.Count < _batchSize && _telemetryQueue.Count > 0)
                    {
                        batch.Add(_telemetryQueue.Dequeue());
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
                    // Collect various telemetry types
                    await CollectProcessTelemetryAsync();
                    await CollectPerformanceTelemetryAsync();

                    // Wait before next collection cycle
                    await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in background telemetry processing");
                    await Task.Delay(TimeSpan.FromSeconds(60), cancellationToken);
                }
            }
        }

        private async Task CollectProcessTelemetryAsync()
        {
            try
            {
                var processes = Process.GetProcesses().Take(50).Select(p => new ProcessInfo
                {
                    ProcessId = p.Id,
                    ProcessName = p.ProcessName,
                    MemoryUsage = p.WorkingSet64,
                    CpuUsage = 0.0, // Would need performance counters for accurate CPU
                    ThreadCount = p.Threads.Count,
                    StartTime = p.StartTime,
                    ThreatLevel = ThreatSeverity.Low
                }).ToList();

                AddProcessTelemetry(processes);
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
                var telemetry = new TelemetryData
                {
                    AgentId = Environment.MachineName + "_" + Environment.UserName,
                    Timestamp = DateTime.UtcNow,
                    DataType = TelemetryType.Performance.ToString(),
                    Data = new Dictionary<string, object>
                    {
                        ["CpuUsage"] = GetCpuUsage(),
                        ["MemoryUsage"] = GetMemoryUsage(),
                        ["DiskUsage"] = GetDiskUsage(),
                        ["NetworkActivity"] = GetNetworkActivity()
                    },
                    IsCompressed = false,
                    IsEncrypted = false,
                    Checksum = string.Empty
                };

                AddTelemetry(telemetry);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error collecting performance telemetry");
            }
        }

        private async Task SendBatchAsync(List<TelemetryData> batch)
        {
            try
            {
                var tasks = new List<Task>();

                // Send to Azure
                if (_azureCommunicator.IsInitialized)
                {
                    foreach (var telemetry in batch)
                    {
                        tasks.Add(_azureCommunicator.SendTelemetryAsync(telemetry));
                    }
                }

                // Send to AWS
                if (_awsCommunicator.IsInitialized)
                {
                    tasks.Add(_awsCommunicator.SendBatchTelemetryAsync(batch));
                }

                await Task.WhenAll(tasks);
                _logger.LogDebug($"Successfully sent {batch.Count} telemetry records");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending telemetry batch");
            }
        }

        private double GetCpuUsage()
        {
            try
            {
                // Simplified CPU usage calculation
                // In a real implementation, you'd use PerformanceCounter
                return 0.0;
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
                var process = Process.GetCurrentProcess();
                return process.WorkingSet64;
            }
            catch
            {
                return 0;
            }
        }

        private long GetAvailableMemory()
        {
            try
            {
                // Simplified available memory calculation
                return 0;
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
                var drive = new System.IO.DriveInfo("C:");
                return drive.AvailableFreeSpace;
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
                var drive = new System.IO.DriveInfo("C:");
                var totalSpace = drive.TotalSize;
                var freeSpace = drive.AvailableFreeSpace;
                return totalSpace > 0 ? (double)(totalSpace - freeSpace) / totalSpace * 100 : 0;
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
                // Simplified network activity calculation
                return 0.0;
            }
            catch
            {
                return 0.0;
            }
        }
    }
} 
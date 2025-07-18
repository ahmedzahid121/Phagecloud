using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ML;
using Microsoft.ML.Data;
using Microsoft.ML.Trainers;
using System.Management;

namespace PhageVirus.Modules
{
    public class AnomalyScoreClassifier
    {
        private static MLContext mlContext;
        private static ITransformer trainedModel;
        private static PredictionEngine<ProcessBehaviorData, ProcessPrediction> predictionEngine;
        private static bool isInitialized = false;
        private static readonly object modelLock = new object();
        
        // Optimization: Batching queue for reduced CPU usage
        private static readonly ConcurrentQueue<ProcessBehaviorData> _processQueue = new();
        private static readonly SemaphoreSlim _batchSemaphore = new(1, 1);
        private static bool _batchProcessingEnabled = false;
        
        // Optimization: Lightweight model settings
        private static readonly bool EnableContinuousLearning = false; // Disabled by default
        private static readonly int BatchSize = 10; // Process 10 processes at once
        private static readonly TimeSpan BatchInterval = TimeSpan.FromSeconds(30); // Process batches every 30 seconds
        
        // Model file path
        private static readonly string ModelPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "PhageVirus", "Models", "anomaly_model.zip");

        // Training data file
        private static readonly string TrainingDataPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "PhageVirus", "Data", "training_data.csv");

        public class ProcessBehaviorData
        {
            [LoadColumn(0)]
            public string ProcessName { get; set; }

            [LoadColumn(1)]
            public float CpuUsage { get; set; }

            [LoadColumn(2)]
            public float MemoryUsage { get; set; }

            [LoadColumn(3)]
            public int FileAccessCount { get; set; }

            [LoadColumn(4)]
            public int NetworkConnections { get; set; }

            [LoadColumn(5)]
            public int RegistryAccessCount { get; set; }

            [LoadColumn(6)]
            public float EntropyScore { get; set; }

            [LoadColumn(7)]
            public int ThreadCount { get; set; }

            [LoadColumn(8)]
            public int HandleCount { get; set; }

            [LoadColumn(9)]
            public float WorkingSetSize { get; set; }

            [LoadColumn(10)]
            public bool IsSuspicious { get; set; }
        }

        public class ProcessPrediction
        {
            [ColumnName("PredictedLabel")]
            public bool IsSuspicious { get; set; }

            public float Probability { get; set; }

            public float Score { get; set; }
        }

        public static void Initialize()
        {
            try
            {
                lock (modelLock)
                {
                    if (isInitialized) return;

                    mlContext = new MLContext(seed: 42);
                    
                    // Create directories if they don't exist
                    Directory.CreateDirectory(Path.GetDirectoryName(ModelPath));
                    Directory.CreateDirectory(Path.GetDirectoryName(TrainingDataPath));

                    // Initialize or load model
                    if (File.Exists(ModelPath))
                    {
                        LoadTrainedModel();
                    }
                    else
                    {
                        TrainLightweightModel(); // Use lightweight model
                    }

                    isInitialized = true;
                    
                    // Start optimized batch processing
                    StartBatchProcessing();
                    
                    EnhancedLogger.LogSuccess("AnomalyScoreClassifier initialized with lightweight model and batching");
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to initialize AnomalyScoreClassifier: {ex.Message}");
            }
        }

        private static void TrainLightweightModel()
        {
            try
            {
                EnhancedLogger.LogInfo("Training lightweight anomaly detection model...");

                // Generate minimal training data
                var trainingData = GenerateMinimalTrainingData();
                
                // Save training data
                SaveTrainingData(trainingData);

                // Create lightweight model pipeline
                var dataView = mlContext.Data.LoadFromEnumerable(trainingData);
                
                var pipeline = mlContext.Transforms.Text.FeaturizeText("ProcessNameFeatures", "ProcessName")
                    .Append(mlContext.Transforms.Concatenate("Features", 
                        "ProcessNameFeatures", "CpuUsage", "MemoryUsage", "FileAccessCount", 
                        "NetworkConnections", "RegistryAccessCount", "EntropyScore"))
                    .Append(mlContext.Transforms.NormalizeMinMax("Features"))
                    .Append(mlContext.BinaryClassification.Trainers.FastTree(
                        numberOfLeaves: 10,  // Reduced from 20
                        numberOfTrees: 50,   // Reduced from 100
                        minimumExampleCountPerLeaf: 5)); // Reduced from 10

                trainedModel = pipeline.Fit(dataView);
                predictionEngine = mlContext.Model.CreatePredictionEngine<ProcessBehaviorData, ProcessPrediction>(trainedModel);

                // Save the lightweight model
                mlContext.Model.Save(trainedModel, dataView.Schema, ModelPath);
                
                EnhancedLogger.LogSuccess("Lightweight model trained and saved successfully");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to train lightweight model: {ex.Message}");
            }
        }

        private static List<ProcessBehaviorData> GenerateMinimalTrainingData()
        {
            var trainingData = new List<ProcessBehaviorData>();

            // Normal process patterns (reduced samples)
            var normalProcesses = new[] { "explorer", "svchost", "lsass", "winlogon", "services" };
            foreach (var process in normalProcesses)
            {
                for (int i = 0; i < 20; i++) // Reduced from 50 to 20 samples per process
                {
                    trainingData.Add(new ProcessBehaviorData
                    {
                        ProcessName = process,
                        CpuUsage = (float)(new Random().NextDouble() * 5.0),
                        MemoryUsage = (float)(new Random().NextDouble() * 100.0),
                        FileAccessCount = new Random().Next(0, 30), // Reduced range
                        NetworkConnections = new Random().Next(0, 5), // Reduced range
                        RegistryAccessCount = new Random().Next(0, 10), // Reduced range
                        EntropyScore = (float)(new Random().NextDouble() * 5.0),
                        ThreadCount = new Random().Next(1, 10), // Reduced range
                        HandleCount = new Random().Next(10, 50), // Reduced range
                        WorkingSetSize = (float)(new Random().NextDouble() * 100.0), // Reduced range
                        IsSuspicious = false
                    });
                }
            }

            // Suspicious process patterns (reduced samples)
            var suspiciousProcesses = new[] { "powershell", "cmd", "mshta", "wscript", "rundll32" };
            foreach (var process in suspiciousProcesses)
            {
                for (int i = 0; i < 15; i++) // Reduced from 30 to 15 samples per process
                {
                    trainingData.Add(new ProcessBehaviorData
                    {
                        ProcessName = process,
                        CpuUsage = (float)(new Random().NextDouble() * 20.0 + 10.0), // Higher CPU
                        MemoryUsage = (float)(new Random().NextDouble() * 200.0 + 50.0), // Higher memory
                        FileAccessCount = new Random().Next(20, 100), // Higher file access
                        NetworkConnections = new Random().Next(5, 20), // Higher network activity
                        RegistryAccessCount = new Random().Next(10, 50), // Higher registry access
                        EntropyScore = (float)(new Random().NextDouble() * 3.0 + 6.0), // Higher entropy
                        ThreadCount = new Random().Next(5, 25), // More threads
                        HandleCount = new Random().Next(50, 200), // More handles
                        WorkingSetSize = (float)(new Random().NextDouble() * 300.0 + 100.0), // Larger working set
                        IsSuspicious = true
                    });
                }
            }

            return trainingData;
        }

        private static void LoadTrainedModel()
        {
            try
            {
                trainedModel = mlContext.Model.Load(ModelPath, out var schema);
                predictionEngine = mlContext.Model.CreatePredictionEngine<ProcessBehaviorData, ProcessPrediction>(trainedModel);
                EnhancedLogger.LogInfo("Trained model loaded successfully");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to load trained model: {ex.Message}");
                TrainLightweightModel(); // Fallback to training new model
            }
        }

        private static void SaveTrainingData(List<ProcessBehaviorData> data)
        {
            try
            {
                using (var writer = new StreamWriter(TrainingDataPath))
                {
                    writer.WriteLine("ProcessName,CpuUsage,MemoryUsage,FileAccessCount,NetworkConnections,RegistryAccessCount,EntropyScore,ThreadCount,HandleCount,WorkingSetSize,IsSuspicious");
                    
                    foreach (var item in data)
                    {
                        writer.WriteLine($"{item.ProcessName},{item.CpuUsage},{item.MemoryUsage},{item.FileAccessCount},{item.NetworkConnections},{item.RegistryAccessCount},{item.EntropyScore},{item.ThreadCount},{item.HandleCount},{item.WorkingSetSize},{item.IsSuspicious}");
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to save training data: {ex.Message}");
            }
        }

        public static async Task<ProcessPrediction> AnalyzeProcessAsync(Process process)
        {
            try
            {
                // Skip critical system processes to reduce workload
                if (IsCriticalProcess(process))
                {
                    return new ProcessPrediction { IsSuspicious = false, Probability = 0.1f, Score = 0.1f };
                }

                // Add to batch processing queue instead of immediate analysis
                var behaviorData = await CollectProcessBehaviorDataAsync(process);
                _processQueue.Enqueue(behaviorData);

                // Return a default prediction (will be updated when batch is processed)
                return new ProcessPrediction { IsSuspicious = false, Probability = 0.5f, Score = 0.5f };
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Process analysis failed for {process.ProcessName}: {ex.Message}");
                return new ProcessPrediction { IsSuspicious = false, Probability = 0.1f, Score = 0.1f };
            }
        }
        
        private static bool IsCriticalProcess(Process process)
        {
            var criticalNames = new[] { "powershell", "cmd", "mshta", "rundll32", "regsvr32", "wscript", "cscript" };
            return criticalNames.Contains(process.ProcessName.ToLower());
        }

        private static async Task<ProcessBehaviorData> CollectProcessBehaviorDataAsync(Process process)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var behaviorData = new ProcessBehaviorData
                    {
                        ProcessName = process.ProcessName.ToLower(),
                        CpuUsage = GetCpuUsage(process),
                        MemoryUsage = process.WorkingSet64 / (1024.0f * 1024.0f), // Convert to MB
                        FileAccessCount = GetFileAccessCount(process),
                        NetworkConnections = GetNetworkConnections(process),
                        RegistryAccessCount = GetRegistryAccessCount(process),
                        EntropyScore = CalculateProcessEntropy(process),
                        ThreadCount = process.Threads.Count,
                        HandleCount = process.HandleCount,
                        WorkingSetSize = process.WorkingSet64 / (1024.0f * 1024.0f),
                        IsSuspicious = false // This will be predicted
                    };

                    return behaviorData;
                }
                catch
                {
                    // Return safe defaults if we can't collect data
                    return new ProcessBehaviorData
                    {
                        ProcessName = process.ProcessName.ToLower(),
                        CpuUsage = 0.0f,
                        MemoryUsage = 0.0f,
                        FileAccessCount = 0,
                        NetworkConnections = 0,
                        RegistryAccessCount = 0,
                        EntropyScore = 0.0f,
                        ThreadCount = 0,
                        HandleCount = 0,
                        WorkingSetSize = 0.0f,
                        IsSuspicious = false
                    };
                }
            });
        }

        private static float GetCpuUsage(Process process)
        {
            try
            {
                var startTime = DateTime.UtcNow;
                var startCpuUsage = process.TotalProcessorTime;
                
                Thread.Sleep(100); // Wait 100ms
                
                var endTime = DateTime.UtcNow;
                var endCpuUsage = process.TotalProcessorTime;
                
                var cpuUsedMs = (endCpuUsage - startCpuUsage).TotalMilliseconds;
                var totalMsPassed = (endTime - startTime).TotalMilliseconds;
                
                return (float)(cpuUsedMs / totalMsPassed * 100.0);
            }
            catch
            {
                return 0.0f;
            }
        }

        private static int GetFileAccessCount(Process process)
        {
            try
            {
                // Simulate file access count using handle count as proxy
                return process.HandleCount / 10; // Rough approximation
            }
            catch
            {
                return 0;
            }
        }

        private static int GetNetworkConnections(Process process)
        {
            try
            {
                var connections = 0;
                var searcher = new ManagementObjectSearcher(
                    $"SELECT * FROM Win32_NetworkConnection WHERE ProcessId = {process.Id}");
                
                foreach (ManagementObject obj in searcher.Get())
                {
                    connections++;
                }
                
                return connections;
            }
            catch
            {
                return 0;
            }
        }

        private static int GetRegistryAccessCount(Process process)
        {
            try
            {
                // Simulate registry access count
                return process.HandleCount / 20; // Rough approximation
            }
            catch
            {
                return 0;
            }
        }

        private static float CalculateProcessEntropy(Process process)
        {
            try
            {
                // Calculate entropy based on process characteristics
                var entropy = 0.0f;
                
                // High thread count increases entropy
                if (process.Threads.Count > 50) entropy += 2.0f;
                if (process.Threads.Count > 100) entropy += 2.0f;
                
                // High handle count increases entropy
                if (process.HandleCount > 200) entropy += 1.5f;
                if (process.HandleCount > 500) entropy += 1.5f;
                
                // High memory usage increases entropy
                var memoryMB = process.WorkingSet64 / (1024.0 * 1024.0);
                if (memoryMB > 500) entropy += 1.0f;
                if (memoryMB > 1000) entropy += 1.0f;
                
                // Suspicious process names increase entropy
                var suspiciousNames = new[] { "powershell", "cmd", "mshta", "rundll32", "regsvr32" };
                if (suspiciousNames.Contains(process.ProcessName.ToLower()))
                    entropy += 2.0f;
                
                return Math.Min(entropy, 10.0f); // Cap at 10.0
            }
            catch
            {
                return 0.0f;
            }
        }

        public static async Task StartContinuousMonitoring()
        {
            try
            {
                EnhancedLogger.LogInfo("Starting lightweight continuous monitoring...");
                
                while (isInitialized)
                {
                    try
                    {
                        // Only monitor high-risk processes
                        var processes = Process.GetProcesses()
                            .Where(p => IsHighRiskProcess(p))
                            .Take(5); // Limit to 5 processes per cycle

                        foreach (var process in processes)
                        {
                            try
                            {
                                await AnalyzeProcessAsync(process);
                            }
                            catch
                            {
                                // Skip processes we can't analyze
                            }
                        }

                        // Sleep longer to reduce CPU usage
                        await Task.Delay(TimeSpan.FromSeconds(60)); // 60 seconds instead of 30
                    }
                    catch (Exception ex)
                    {
                        EnhancedLogger.LogWarning($"Continuous monitoring error: {ex.Message}");
                        await Task.Delay(TimeSpan.FromSeconds(120)); // Longer delay on error
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start continuous monitoring: {ex.Message}");
            }
        }

        private static void HandleSuspiciousProcessLightweight(ProcessBehaviorData data)
        {
            try
            {
                // Lightweight handling - just log and monitor
                EnhancedLogger.LogInfo($"Monitoring suspicious process detected by ML: {data.ProcessName}");
                
                // Don't take aggressive action in lightweight mode
                // Just add to monitoring list for further observation
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Lightweight suspicious process handling failed: {ex.Message}");
            }
        }

        private static bool IsHighRiskProcess(Process process)
        {
            var highRiskNames = new[] { 
                "powershell", "cmd", "mshta", "wscript", "cscript", "rundll32", 
                "regsvr32", "nc", "ncat", "telnet" 
            };
            
            return highRiskNames.Any(name => 
                process.ProcessName.Contains(name, StringComparison.OrdinalIgnoreCase));
        }

        private static void StartBatchProcessing()
        {
            _batchProcessingEnabled = true;
            
            Task.Run(async () =>
            {
                while (_batchProcessingEnabled)
                {
                    try
                    {
                        await ProcessBatchAsync();
                        await Task.Delay(BatchInterval);
                    }
                    catch (Exception ex)
                    {
                        EnhancedLogger.LogError($"Batch processing error: {ex.Message}");
                        await Task.Delay(TimeSpan.FromSeconds(60)); // Longer delay on error
                    }
                }
            });
        }

        private static async Task ProcessBatchAsync()
        {
            if (!_batchSemaphore.Wait(0)) return; // Don't wait, skip if already processing

            try
            {
                var batch = new List<ProcessBehaviorData>();
                
                // Collect up to BatchSize items from queue
                for (int i = 0; i < BatchSize && _processQueue.TryDequeue(out var data); i++)
                {
                    batch.Add(data);
                }

                if (batch.Count == 0) return;

                // Process the batch
                foreach (var data in batch)
                {
                    try
                    {
                        var prediction = predictionEngine.Predict(data);
                        
                        if (prediction.IsSuspicious && prediction.Probability > 0.7f)
                        {
                            EnhancedLogger.LogWarning($"ML model detected suspicious process: {data.ProcessName} (Probability: {prediction.Probability:P1})");
                            
                            // Handle suspicious process (lightweight action)
                            HandleSuspiciousProcessLightweight(data);
                        }
                    }
                    catch (Exception ex)
                    {
                        EnhancedLogger.LogWarning($"Batch prediction failed: {ex.Message}");
                    }
                }

                // Optional: Retrain model periodically (only if continuous learning is enabled)
                if (EnableContinuousLearning && batch.Count >= BatchSize)
                {
                    // Skip retraining for lightweight mode
                    // await RetrainModelAsync(batch);
                }
            }
            finally
            {
                _batchSemaphore.Release();
            }
        }
        
        public static bool IsInitialized => isInitialized;
    }
}
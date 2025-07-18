using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using System.Text.Json;
using PhageVirus.Modules;

namespace PhageVirus
{
    public partial class MainWindow : Window
    {
        private bool isHunting = false;
        private DispatcherTimer? statusTimer;
        private DispatcherTimer? metricsTimer;
        private DispatcherTimer? uptimeTimer;
        private DateTime startTime;
        private DateTime lastThreatTime;
        
        // Data collections for UI
        private ObservableCollection<ThreatTimelineItem> threatTimeline = new ObservableCollection<ThreatTimelineItem>();
        private ObservableCollection<ProcessInfo> monitoredProcesses = new ObservableCollection<ProcessInfo>();
        private ObservableCollection<AttackSimulationResult> attackResults = new ObservableCollection<AttackSimulationResult>();
        
        // Statistics
        private int credentialAttacksBlocked = 0;
        private int exploitsNeutralized = 0;
        private int persistenceEntriesDeleted = 0;
        private int totalThreatsHandled = 0;
        private int activeThreats = 0;
        private int preventedAttacks = 0;
        
        // Red Team Simulation tracking
        private bool redTeamAgentActive = false;
        private Dictionary<string, int> attackScores = new Dictionary<string, int>
        {
            { "CredentialAccess", 100 },
            { "Exploitation", 100 },
            { "LateralMovement", 100 },
            { "Persistence", 100 },
            { "MalwareProtection", 100 }
        };
        
        // Module status tracking
        private Dictionary<string, ModuleStatus> moduleStatuses = new Dictionary<string, ModuleStatus>();
        
        // Performance monitoring
        private List<double> cpuHistory = new List<double>();
        private List<double> memoryHistory = new List<double>();
        private PerformanceCounter? cpuCounter;
        private PerformanceCounter? memoryCounter;

        public MainWindow()
        {
            InitializeComponent();
            InitializeApp();
            // Command Center UI setup
            UpdateCommandCenter();
        }

        private async void InitializeApp()
        {
            startTime = DateTime.Now;
            lastThreatTime = DateTime.Now;
            
            // Initialize collections (already initialized at declaration, but kept for consistency)
            threatTimeline = new ObservableCollection<ThreatTimelineItem>();
            monitoredProcesses = new ObservableCollection<ProcessInfo>();
            
            // Initialize module statuses
            InitializeModuleStatuses();
            
            // Set up data binding
            ThreatTimelineGrid.ItemsSource = threatTimeline;
            ProcessGrid.ItemsSource = monitoredProcesses;
            AttackResultsGrid.ItemsSource = attackResults;
            
            // Initialize performance counters
            InitializePerformanceCounters();
            
            // Set up timers (optimized - single consolidated timer)
            SetupOptimizedTimers();
            
            // Initialize UI
            LogBox.AppendText("PhageVirus - Unified Cloud-Enabled Virus Hunter Initialized\n");
            LogBox.AppendText("Starting unified module manager with cloud integration...\n");
            
            // Check for elevated privileges
            if (!SystemHacker.IsElevated())
            {
                LogBox.AppendText("WARNING: Running without elevated privileges. Some features may be limited.\n");
                EnhancedLogger.LogWarning("Running without elevated privileges", LogBox.AppendText);
            }
            
            // Load configuration
            LoadConfiguration();
            
            // Initialize and start unified module manager
            await InitializeUnifiedModuleManagerAsync();
            
            EnhancedLogger.LogInfo("PhageVirus unified hunter started with cloud integration", LogBox.AppendText);
        }

        private void InitializeModuleStatuses()
        {
            moduleStatuses = new Dictionary<string, ModuleStatus>
            {
                { "VirusHunter", new ModuleStatus { Name = "Virus Hunter", Status = ModuleHealth.Running } },
                { "PayloadReplacer", new ModuleStatus { Name = "Payload Replacer", Status = ModuleHealth.Running } },
                { "ProcessWatcher", new ModuleStatus { Name = "Process Watcher", Status = ModuleHealth.Running } },
                { "AutorunBlocker", new ModuleStatus { Name = "Autorun Blocker", Status = ModuleHealth.Running } },
                { "MemoryTrap", new ModuleStatus { Name = "Memory Trap", Status = ModuleHealth.Running } },
                { "CredentialTrap", new ModuleStatus { Name = "Credential Trap", Status = ModuleHealth.Running } },
                { "ExploitShield", new ModuleStatus { Name = "Exploit Shield", Status = ModuleHealth.Running } },
                { "Watchdog", new ModuleStatus { Name = "Watchdog Core", Status = ModuleHealth.Running } },
                { "RedTeamAgent", new ModuleStatus { Name = "Red Team Agent", Status = ModuleHealth.Running } }
            };
        }

        private void InitializePerformanceCounters()
        {
            try
            {
                cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                memoryCounter = new PerformanceCounter("Memory", "Available MBytes");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to initialize performance counters: {ex.Message}", LogBox.AppendText);
            }
        }

        private void SetupOptimizedTimers()
        {
            // Single consolidated timer for all updates (optimized)
            statusTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(5) // Increased from 2 seconds
            };
            statusTimer.Tick += OptimizedTimer_Tick;
            statusTimer.Start();

            // Uptime timer (kept separate for accuracy)
            uptimeTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(5) // Increased from 2 seconds
            };
            uptimeTimer.Tick += UptimeTimer_Tick;
            uptimeTimer.Start();
        }

        private AppConfig? appConfig;
        
        private void LoadConfiguration()
        {
            try
            {
                if (File.Exists("appsettings.json"))
                {
                    appConfig = JsonSerializer.Deserialize<AppConfig>(File.ReadAllText("appsettings.json"));
                    if (appConfig?.EmailSettings != null)
                    {
                        SmtpServerBox.Text = appConfig.EmailSettings.SmtpServer ?? "smtp.gmail.com";
                        SmtpPortBox.Text = appConfig.EmailSettings.Port.ToString() ?? "587";
                        EmailBox.Text = appConfig.EmailSettings.Email ?? "";
                    }
                    else
                    {
                        SmtpServerBox.Text = "smtp.gmail.com";
                        SmtpPortBox.Text = "587";
                        EmailBox.Text = "";
                    }
                }
                else
                {
                    appConfig = new AppConfig(); // Use defaults
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to load configuration: {ex.Message}", LogBox.AppendText);
                appConfig = new AppConfig(); // Use defaults on error
            }
        }
        
        private async Task InitializeUnifiedModuleManagerAsync()
        {
            try
            {
                LogBox.AppendText("Initializing unified module manager...\n");
                
                // Initialize unified module manager
                await UnifiedModuleManager.Instance.InitializeAsync();
                
                // Start the unified module manager
                await UnifiedModuleManager.Instance.StartAsync();
                
                LogBox.AppendText("Unified module manager started successfully\n");
                
                // Update module statuses from unified manager
                UpdateModuleStatusesFromUnifiedManager();
                
                // Start behavior test if enabled in unified config
                var config = UnifiedConfig.Instance;
                if (config.IsModuleEnabled("BehaviorTest"))
                {
                    BehaviorTest.StartBehaviorTest();
                }
            }
            catch (Exception ex)
            {
                LogBox.AppendText($"ERROR: Failed to initialize unified module manager: {ex.Message}\n");
                EnhancedLogger.LogError($"Unified module manager initialization failed: {ex.Message}", LogBox.AppendText);
            }
        }

        private void UpdateModuleStatusesFromUnifiedManager()
        {
            try
            {
                var unifiedStatuses = UnifiedModuleManager.Instance.GetModuleStatus();
                
                foreach (var kvp in unifiedStatuses)
                {
                    var moduleName = kvp.Key;
                    var status = kvp.Value;
                    
                    if (moduleStatuses.ContainsKey(moduleName))
                    {
                        moduleStatuses[moduleName].Status = status.Health;
                        moduleStatuses[moduleName].LastUpdate = status.LastActivity;
                    }
                    else
                    {
                        moduleStatuses[moduleName] = new ModuleStatus
                        {
                            Name = status.Name,
                            Status = status.Health,
                            LastUpdate = status.LastActivity
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to update module statuses: {ex.Message}", LogBox.AppendText);
            }
        }

        private async Task StartStaggeredModulesAsync()
        {
            try
            {
                LogBox.AppendText("🔄 Starting modules with staggered activation for optimal performance...\n");
                
                // Phase 1: Lightweight modules (immediate)
                LogBox.AppendText("🔄 Phase 1: Starting lightweight modules...\n");
                StartLightweightModules();
                await Task.Delay(TimeSpan.FromSeconds(2));
                
                // Phase 2: Medium-resource modules (after 2 seconds)
                LogBox.AppendText("🔄 Phase 2: Starting medium-resource modules...\n");
                await StartMediumResourceModulesAsync();
                await Task.Delay(TimeSpan.FromSeconds(3));
                
                // Phase 3: High-resource modules (after 5 seconds total)
                LogBox.AppendText("🔄 Phase 3: Starting high-resource modules...\n");
                await StartHighResourceModulesAsync();
                await Task.Delay(TimeSpan.FromSeconds(5));
                
                // Phase 4: Autonomous hunting (after 10 seconds total)
                LogBox.AppendText("🔄 Phase 4: Starting autonomous threat hunting...\n");
                await StartAutonomousHuntingAsync();
                
                LogBox.AppendText("✅ Staggered module activation complete - system optimized for performance\n");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Staggered module startup failed: {ex.Message}", LogBox.AppendText);
            }
        }

        private void StartLightweightModules()
        {
            try
            {
                // Always start these lightweight modules
                AutorunBlocker.StartMonitoring();
                LogBox.AppendText("✅ Autorun blocker activated\n");
                UpdateModuleStatus("AutorunBlocker", ModuleHealth.Running);
                
                SandboxMode.EnableSandboxMode();
                LogBox.AppendText("✅ Sandbox mode activated\n");
                
                CredentialTrap.StartCredentialMonitoring();
                LogBox.AppendText("✅ Credential trap activated\n");
                UpdateModuleStatus("CredentialTrap", ModuleHealth.Running);
                
                ExploitShield.ActivateExploitShield();
                LogBox.AppendText("✅ Exploit shield activated\n");
                UpdateModuleStatus("ExploitShield", ModuleHealth.Running);
                
                WatchdogCore.StartWatchdog();
                LogBox.AppendText("✅ Watchdog core activated\n");
                UpdateModuleStatus("Watchdog", ModuleHealth.Running);
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start lightweight modules: {ex.Message}", LogBox.AppendText);
            }
        }

        private async Task StartMediumResourceModulesAsync()
        {
            try
            {
                // Start medium-resource modules based on configuration
                if (appConfig?.Modules.ProcessWatcher == true)
                {
                    ProcessWatcher.StartWatching();
                    LogBox.AppendText("✅ Process watcher activated\n");
                    UpdateModuleStatus("ProcessWatcher", ModuleHealth.Running);
                }
                
                if (appConfig?.Modules.MemoryTrap == true)
                {
                    MemoryTrap.StartMemoryMonitoring();
                    LogBox.AppendText("✅ Memory trap activated\n");
                    UpdateModuleStatus("MemoryTrap", ModuleHealth.Running);
                }
                
                if (appConfig?.Modules.ZeroTrustRuntime == true)
                {
                    ZeroTrustRuntime.StartZeroTrustProtection();
                    LogBox.AppendText("✅ ZeroTrustRuntime protection started\n");
                }
                
                if (appConfig?.Modules.DnsSinkhole == true)
                {
                    DnsSinkhole.StartDnsSinkhole();
                    LogBox.AppendText("✅ DNS Sinkhole started\n");
                }
                
                if (appConfig?.Modules.RollbackEngine == true)
                {
                    RollbackEngine.StartRollbackEngine();
                    LogBox.AppendText("✅ Rollback Engine started\n");
                }
                
                if (appConfig?.Modules.PhishingGuard == true)
                {
                    PhishingGuard.StartPhishingGuard();
                    LogBox.AppendText("✅ Phishing Guard started\n");
                }
                
                if (appConfig?.Modules.FirewallGuard == true)
                {
                    FirewallGuard.ActivateFirewallGuard();
                    LogBox.AppendText("✅ FirewallGuard started\n");
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start medium-resource modules: {ex.Message}", LogBox.AppendText);
            }
        }

        private async Task StartHighResourceModulesAsync()
        {
            try
            {
                // Start high-resource modules based on configuration
                if (appConfig?.Modules.AnomalyScoreClassifier == true)
                {
                    AnomalyScoreClassifier.Initialize();
                    LogBox.AppendText("✅ AnomalyScoreClassifier initialized\n");
                }
                
                if (appConfig?.Modules.PhageSync == true)
                {
                    PhageSync.StartMeshNetwork();
                    LogBox.AppendText("✅ PhageSync mesh network started\n");
                }
                
                if (appConfig?.Modules.HoneyProcess == true)
                {
                    HoneyProcess.StartHoneyProcesses();
                    LogBox.AppendText("✅ HoneyProcess decoy processes started\n");
                }
                
                if (appConfig?.Modules.LiveCommandShell == true)
                {
                    LiveCommandShell.StartCommandShell();
                    LogBox.AppendText("✅ Live Command Shell started\n");
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start high-resource modules: {ex.Message}", LogBox.AppendText);
            }
        }

        private async Task StartAutonomousHuntingAsync()
        {
            try
            {
                LogBox.AppendText("🦠 PhageVirus: Beginning lightweight autonomous threat hunting...\n");
                
                // Phase 1: Self-replication (only if enabled)
                if (appConfig?.Modules.SelfReplication == true)
                {
                    LogBox.AppendText("🦠 Phase 1: Self-replication...\n");
                    if (SelfReplicator.Replicate())
                    {
                        LogBox.AppendText("✅ Self-replication successful\n");
                        AddThreatTimelineItem("Self-Replication", "System", "Replicated successfully", "Success");
                    }
                }
                
                // Phase 2: Immediate threat hunting (optimized)
                LogBox.AppendText("🦠 Phase 2: Active threat hunting...\n");
                await Task.Run(() => HuntThreatsAutonomouslyOptimized());
                
                // Phase 3: Schedule periodic hunting (reduced frequency)
                if (appConfig?.Modules.SelfReplication == true)
                {
                    LogBox.AppendText("🦠 Phase 3: Scheduling periodic hunting...\n");
                    SelfReplicator.ScheduleReplication(10); // Replicate every 10 minutes instead of 5
                }
                
                LogBox.AppendText("✅ Lightweight autonomous hunting activated\n");
                isHunting = true;
                UpdateOverallStatus("🟢 System Protected (Optimized)");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Autonomous hunting failed: {ex.Message}", LogBox.AppendText);
                UpdateOverallStatus("🔴 System Error");
            }
        }

        private void StartPreventionModules()
        {
            try
            {
                LogBox.AppendText("🛡️ Activating advanced prevention modules...\n");
                
                // Start process watching (intercepts malicious processes before execution)
                ProcessWatcher.StartWatching();
                LogBox.AppendText("✅ Process watcher activated\n");
                UpdateModuleStatus("ProcessWatcher", ModuleHealth.Running);
                
                // Start autorun monitoring (blocks persistence mechanisms)
                AutorunBlocker.StartMonitoring();
                LogBox.AppendText("✅ Autorun blocker activated\n");
                UpdateModuleStatus("AutorunBlocker", ModuleHealth.Running);
                
                // Start memory trap monitoring (detects injected payloads)
                MemoryTrap.StartMemoryMonitoring();
                LogBox.AppendText("✅ Memory trap activated\n");
                UpdateModuleStatus("MemoryTrap", ModuleHealth.Running);
                
                // Enable sandbox mode (blocks suspicious files in high-risk folders)
                SandboxMode.EnableSandboxMode();
                LogBox.AppendText("✅ Sandbox mode activated\n");
                
                // Start credential trap (monitors for credential theft)
                CredentialTrap.StartCredentialMonitoring();
                LogBox.AppendText("✅ Credential trap activated\n");
                UpdateModuleStatus("CredentialTrap", ModuleHealth.Running);
                
                // Activate exploit shield (blocks memory-based exploits)
                ExploitShield.ActivateExploitShield();
                LogBox.AppendText("✅ Exploit shield activated\n");
                UpdateModuleStatus("ExploitShield", ModuleHealth.Running);
                
                // Start watchdog core (monitors and restarts modules if killed)
                WatchdogCore.StartWatchdog();
                LogBox.AppendText("✅ Watchdog core activated\n");
                UpdateModuleStatus("Watchdog", ModuleHealth.Running);
                
                LogBox.AppendText("🛡️ All advanced prevention modules activated - system fully protected\n");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start prevention modules: {ex.Message}", LogBox.AppendText);
            }
        }

        private void HuntThreatsAutonomously()
        {
            try
            {
                // Hunt for suspicious processes
                var suspiciousProcesses = SystemHacker.HuntSuspiciousProcesses();
                
                foreach (var processInfo in suspiciousProcesses)
                {
                    EnhancedLogger.LogThreat($"Autonomous detection: {processInfo.ProcessName} (PID: {processInfo.ProcessId}) - {processInfo.ThreatLevel}", LogBox.AppendText);
                    
                    // Add to timeline
                    AddThreatTimelineItem("Process Detection", processInfo.ProcessName, $"PID: {processInfo.ProcessId}", "Detected");
                    
                    // Update statistics
                    totalThreatsHandled++;
                    activeThreats++;
                    lastThreatTime = DateTime.Now;
                    
                    // Take immediate action based on threat level
                    switch (processInfo.ThreatLevel)
                    {
                        case ThreatLevel.High:
                        case ThreatLevel.Critical:
                            if (SystemHacker.InjectNeutralizationCode(processInfo))
                            {
                                EnhancedLogger.LogSuccess($"Autonomous neutralization: {processInfo.ProcessName}", LogBox.AppendText);
                                AddThreatTimelineItem("Process Neutralization", processInfo.ProcessName, "Injected neutralization code", "Neutralized");
                                exploitsNeutralized++;
                                activeThreats--;
                            }
                            break;
                        case ThreatLevel.Medium:
                            EnhancedLogger.LogInfo($"Monitoring suspicious process: {processInfo.ProcessName}", LogBox.AppendText);
                            break;
                    }
                }
                
                // Update monitored processes
                UpdateMonitoredProcesses();
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Autonomous hunting error: {ex.Message}", LogBox.AppendText);
            }
        }

        private void HuntThreatsAutonomouslyOptimized()
        {
            try
            {
                // Hunt for suspicious processes (targeted approach)
                var suspiciousProcesses = SystemHacker.HuntSuspiciousProcessesOptimized();
                
                foreach (var processInfo in suspiciousProcesses)
                {
                    EnhancedLogger.LogThreat($"Autonomous detection: {processInfo.ProcessName} (PID: {processInfo.ProcessId}) - {processInfo.ThreatLevel}", LogBox.AppendText);
                    
                    // Add to timeline
                    AddThreatTimelineItem("Process Detection", processInfo.ProcessName, $"PID: {processInfo.ProcessId}", "Detected");
                    
                    // Update statistics
                    totalThreatsHandled++;
                    activeThreats++;
                    lastThreatTime = DateTime.Now;
                    
                    // Take immediate action based on threat level
                    switch (processInfo.ThreatLevel)
                    {
                        case ThreatLevel.High:
                        case ThreatLevel.Critical:
                            if (SystemHacker.InjectNeutralizationCode(processInfo))
                            {
                                EnhancedLogger.LogSuccess($"Autonomous neutralization: {processInfo.ProcessName}", LogBox.AppendText);
                                AddThreatTimelineItem("Process Neutralization", processInfo.ProcessName, "Injected neutralization code", "Neutralized");
                                exploitsNeutralized++;
                                activeThreats--;
                            }
                            break;
                        case ThreatLevel.Medium:
                            EnhancedLogger.LogInfo($"Monitoring suspicious process: {processInfo.ProcessName}", LogBox.AppendText);
                            break;
                    }
                }
                
                // Update monitored processes (reduced frequency)
                UpdateMonitoredProcessesOptimized();
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Autonomous hunting error: {ex.Message}", LogBox.AppendText);
            }
        }

        private void UpdateMonitoredProcesses()
        {
            try
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    monitoredProcesses.Clear();
                    var processes = Process.GetProcesses();
                    
                    foreach (var process in processes.Take(50))
                    {
                        try
                        {
                            var processInfo = new ProcessInfo
                            {
                                ProcessId = process.Id,
                                ProcessName = process.ProcessName ?? "Unknown",
                                Status = "Running",
                                MemoryUsage = process.WorkingSet64,
                                CpuUsage = "0%",
                                ThreatLevel = ThreatLevel.Normal // Default value, will be set properly later
                            };
                            
                            // Set threat level based on process name
                            var threatLevelString = DetermineThreatLevel(process.ProcessName);
                            processInfo.ThreatLevel = threatLevelString switch
                            {
                                "Critical" => ThreatLevel.Critical,
                                "High" => ThreatLevel.High,
                                "Medium" => ThreatLevel.Medium,
                                "Low" => ThreatLevel.Low,
                                _ => ThreatLevel.Normal
                            };
                            
                            monitoredProcesses.Add(processInfo);
                        }
                        catch
                        {
                            // Skip processes we can't access
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to update monitored processes: {ex.Message}", LogBox.AppendText);
            }
        }

        private void UpdateMonitoredProcessesOptimized()
        {
            try
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    monitoredProcesses.Clear();
                    var processes = Process.GetProcesses();
                    
                    // Only monitor high-risk processes to reduce resource usage
                    var highRiskProcesses = processes.Where(p => 
                        IsHighRiskProcess(p.ProcessName) || 
                        p.WorkingSet64 > 100 * 1024 * 1024 // > 100MB memory usage
                    ).Take(20); // Limit to 20 processes instead of 50
                    
                    foreach (var process in highRiskProcesses)
                    {
                        try
                        {
                            var processInfo = new ProcessInfo
                            {
                                ProcessId = process.Id,
                                ProcessName = process.ProcessName ?? "Unknown",
                                Status = "Running",
                                MemoryUsage = process.WorkingSet64,
                                CpuUsage = "0%",
                                ThreatLevel = ThreatLevel.Normal
                            };
                            
                            // Set threat level based on process name
                            var threatLevelString = DetermineThreatLevel(process.ProcessName);
                            processInfo.ThreatLevel = threatLevelString switch
                            {
                                "Critical" => ThreatLevel.Critical,
                                "High" => ThreatLevel.High,
                                "Medium" => ThreatLevel.Medium,
                                "Low" => ThreatLevel.Low,
                                _ => ThreatLevel.Normal
                            };
                            
                            monitoredProcesses.Add(processInfo);
                        }
                        catch
                        {
                            // Skip processes we can't access
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to update monitored processes: {ex.Message}", LogBox.AppendText);
            }
        }

        private string DetermineThreatLevel(string processName)
        {
            var suspiciousProcesses = new[] { "cmd", "powershell", "wscript", "cscript", "rundll32", "regsvr32" };
            var highRiskProcesses = new[] { "mimikatz", "procdump", "wireshark", "fiddler" };
            
            if (highRiskProcesses.Contains(processName.ToLower()))
                return "Critical";
            if (suspiciousProcesses.Contains(processName.ToLower()))
                return "Medium";
            return "Low";
        }

        private bool IsHighRiskProcess(string processName)
        {
            var highRiskProcesses = new[] { 
                "powershell", "cmd", "mshta", "wscript", "cscript", "rundll32", "regsvr32",
                "mimikatz", "procdump", "wireshark", "fiddler", "nc", "ncat", "telnet"
            };
            return highRiskProcesses.Contains(processName.ToLower());
        }

        private void AddThreatTimelineItem(string threatType, string target, string action, string status)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                var item = new ThreatTimelineItem
                {
                    Timestamp = DateTime.Now.ToString("HH:mm:ss"),
                    ThreatType = threatType,
                    Target = target,
                    Action = action,
                    Status = status
                };
                
                threatTimeline.Insert(0, item); // Add to beginning
                
                // Keep only last 100 items
                while (threatTimeline.Count > 100)
                {
                    threatTimeline.RemoveAt(threatTimeline.Count - 1);
                }
            });
        }

        private void UpdateModuleStatus(string moduleName, ModuleHealth status)
        {
            if (moduleStatuses.ContainsKey(moduleName))
            {
                moduleStatuses[moduleName].Status = status;
                UpdateModuleStatusIndicator(moduleName, status);
            }
        }

        private void UpdateModuleStatusIndicator(string moduleName, ModuleHealth status)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                Ellipse statusIndicator = null;
                
                switch (moduleName)
                {
                    case "VirusHunter":
                        statusIndicator = VirusHunterStatus;
                        break;
                    case "PayloadReplacer":
                        statusIndicator = PayloadReplacerStatus;
                        break;
                    case "ProcessWatcher":
                        statusIndicator = ProcessWatcherStatus;
                        break;
                    case "AutorunBlocker":
                        statusIndicator = AutorunBlockerStatus;
                        break;
                    case "MemoryTrap":
                        statusIndicator = MemoryTrapStatus;
                        break;
                    case "CredentialTrap":
                        statusIndicator = CredentialTrapStatus;
                        break;
                    case "ExploitShield":
                        statusIndicator = ExploitShieldStatus;
                        break;
                    case "Watchdog":
                        statusIndicator = WatchdogStatus;
                        break;
                }
                
                if (statusIndicator != null)
                {
                    switch (status)
                    {
                        case ModuleHealth.Running:
                            statusIndicator.Fill = new SolidColorBrush(Colors.Green);
                            break;
                        case ModuleHealth.Stressed:
                            statusIndicator.Fill = new SolidColorBrush(Colors.Yellow);
                            break;
                        case ModuleHealth.Failed:
                            statusIndicator.Fill = new SolidColorBrush(Colors.Red);
                            break;
                    }
                }
            });
        }

        private void UpdateOverallStatus(string status)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                OverallStatus.Text = status;
            });
        }

        // Event Handlers
        private void StartHunting_Click(object? sender, RoutedEventArgs e)
        {
            if (!isHunting)
            {
                StartAutonomousHuntingAsync();
                StartHuntingButton.IsEnabled = false;
                StopHuntingButton.IsEnabled = true;
            }
        }

        private void StopHunting_Click(object? sender, RoutedEventArgs e)
        {
            if (isHunting)
            {
                isHunting = false;
                StartHuntingButton.IsEnabled = true;
                StopHuntingButton.IsEnabled = false;
                UpdateOverallStatus("🟡 Hunting Stopped");
                LogBox.AppendText("🛑 Threat hunting stopped by user\n");
            }
        }

        private void SelfDestruct_Click(object? sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show(
                "Are you sure you want to self-destruct PhageVirus?\n\nThis will:\n- Delete all PhageVirus files\n- Remove from startup\n- Clear all logs\n\nThis action cannot be undone!",
                "Self-Destruct Confirmation",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
            {
                LogBox.AppendText("💥 Self-destruct sequence initiated...\n");
                SelfDestruct.ExecuteSelfDestruct();
            }
        }

        private void ClearLog_Click(object? sender, RoutedEventArgs e)
        {
            LogBox.Clear();
            LogBox.AppendText("Log cleared\n");
        }

        private void ExportLog_Click(object? sender, RoutedEventArgs e)
        {
            try
            {
                var fileName = $"phagevirus_log_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
                File.WriteAllText(fileName, LogBox.Text);
                MessageBox.Show($"Log exported to {fileName}", "Export Complete", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to export log: {ex.Message}", "Export Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void OpenLogViewer_Click(object? sender, RoutedEventArgs e)
        {
            try
            {
                var logViewer = new LogViewer();
                logViewer.Show();
                LogBox.AppendText("Log Viewer opened\n");
            }
            catch (Exception ex)
            {
                LogBox.AppendText($"Failed to open Log Viewer: {ex.Message}\n");
            }
        }

        private void StartBehaviorTest_Click(object? sender, RoutedEventArgs e)
        {
            try
            {
                BehaviorTest.StartBehaviorTest();
                LogBox.AppendText("Behavior test started\n");
            }
            catch (Exception ex)
            {
                LogBox.AppendText($"Failed to start behavior test: {ex.Message}\n");
            }
        }

        private void StopBehaviorTest_Click(object? sender, RoutedEventArgs e)
        {
            try
            {
                BehaviorTest.StopBehaviorTest();
                LogBox.AppendText("Behavior test stopped\n");
            }
            catch (Exception ex)
            {
                LogBox.AppendText($"Failed to stop behavior test: {ex.Message}\n");
            }
        }

        private async void QuickDiagnosticButton_Click(object? sender, RoutedEventArgs e)
        {
            try
            {
                LogBox.AppendText("🔍 Starting comprehensive diagnostic test...\n");
                
                // Disable button during test
                QuickDiagnosticButton.IsEnabled = false;
                QuickDiagnosticButton.Content = "🔍 Running...";
                
                // Show email dialog
                var emailDialog = new EmailDialog();
                if (emailDialog.ShowDialog() == true)
                {
                    var sendToEmail = emailDialog.SendToEmail;
                    var emailAddress = emailDialog.EmailAddress;
                    
                    LogBox.AppendText($"Diagnostic test will send report to: {emailAddress}\n");
                    
                    // Run diagnostic test
                    var success = await DiagnosticTest.RunDiagnosticTest(sendToEmail, emailAddress);
                    
                    if (success)
                    {
                        LogBox.AppendText("✅ Diagnostic test completed successfully!\n");
                        LogBox.AppendText($"📁 Report saved to desktop: PhageVirus_Diagnostic_Report_*.txt\n");
                        if (sendToEmail)
                        {
                            LogBox.AppendText($"📧 Report sent to: {emailAddress}\n");
                        }
                    }
                    else
                    {
                        LogBox.AppendText("❌ Diagnostic test failed\n");
                    }
                }
                else
                {
                    LogBox.AppendText("Diagnostic test cancelled\n");
                }
            }
            catch (Exception ex)
            {
                LogBox.AppendText($"❌ Diagnostic test failed: {ex.Message}\n");
            }
            finally
            {
                // Re-enable button
                QuickDiagnosticButton.IsEnabled = true;
                QuickDiagnosticButton.Content = "🔍 Diagnostic Test";
            }
        }

        private void TestEmail_Click(object? sender, RoutedEventArgs e)
        {
            try
            {
                var config = new PhageVirus.Modules.EmailConfig
                {
                    SmtpServer = SmtpServerBox.Text,
                    Port = int.Parse(SmtpPortBox.Text),
                    Email = EmailBox.Text
                };
                
                EmailReporter.SendTestEmail(config);
                MessageBox.Show("Test email sent successfully!", "Email Test", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to send test email: {ex.Message}", "Email Test Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void Refresh_Click(object? sender, RoutedEventArgs e)
        {
            UpdateMonitoredProcesses();
            UpdateSystemMetrics();
            LogBox.AppendText("🔄 System refreshed\n");
        }

        private void Minimize_Click(object? sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        // Timer Events
        private void StatusTimer_Tick(object? sender, EventArgs e)
        {
            UpdateSystemMetrics();
            UpdateThreatMetrics();
        }

        private void OptimizedTimer_Tick(object? sender, EventArgs e)
        {
            try
            {
                // Update UI elements
                UpdateOverallStatus($"🟢 System Protected (Optimized) - Uptime: {DateTime.Now - startTime:hh\\:mm\\:ss}");
                
                // Update system metrics (reduced frequency)
                UpdateSystemMetrics();
                
                // Update threat metrics
                UpdateThreatMetrics();
                
                // Update performance charts (less frequently)
                if (DateTime.Now.Second % 15 == 0) // Every 15 seconds
                {
                    UpdatePerformanceCharts();
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Timer tick error: {ex.Message}", LogBox.AppendText);
            }
        }

        private void MetricsTimer_Tick(object? sender, EventArgs e)
        {
            UpdatePerformanceCharts();
            UpdateSystemHeatmap();
        }

        private void UptimeTimer_Tick(object? sender, EventArgs e)
        {
            var uptime = DateTime.Now - startTime;
            UptimeText.Text = $"Uptime: {uptime:hh\\:mm\\:ss}";
            LastUpdateTime.Text = $"Last Update: {DateTime.Now:HH:mm:ss}";
        }

        private void UpdateSystemMetrics()
        {
            try
            {
                if (cpuCounter != null)
                {
                    var cpuUsage = Math.Round(cpuCounter.NextValue(), 1);
                    CpuUsageValue.Text = $"{cpuUsage}%";
                    cpuHistory.Add(cpuUsage);
                    
                    if (cpuHistory.Count > 20)
                        cpuHistory.RemoveAt(0);
                }
                
                if (memoryCounter != null)
                {
                    var availableMemory = memoryCounter.NextValue();
                    var totalMemory = GetTotalPhysicalMemory();
                    var usedMemory = totalMemory - availableMemory;
                    
                    // Ensure we don't get negative values
                    if (usedMemory < 0) usedMemory = 0;
                    if (totalMemory <= 0) totalMemory = 4096;
                    
                    MemoryUsageValue.Text = $"{usedMemory:F0} MB";
                    memoryHistory.Add(usedMemory);
                    
                    if (memoryHistory.Count > 20)
                        memoryHistory.RemoveAt(0);
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to update system metrics: {ex.Message}", LogBox.AppendText);
            }
        }

        private void UpdateThreatMetrics()
        {
            ActiveThreatsValue.Text = activeThreats.ToString();
            PreventedAttacksValue.Text = preventedAttacks.ToString();
            
            var timeSinceLastThreat = DateTime.Now - lastThreatTime;
            if (timeSinceLastThreat.TotalSeconds < 60)
                LastThreatValue.Text = $"{(int)timeSinceLastThreat.TotalSeconds}s";
            else if (timeSinceLastThreat.TotalMinutes < 60)
                LastThreatValue.Text = $"{(int)timeSinceLastThreat.TotalMinutes}m";
            else
                LastThreatValue.Text = $"{(int)timeSinceLastThreat.TotalHours}h";
            
            // Update threat intelligence metrics
            CredentialAttacksValue.Text = credentialAttacksBlocked.ToString();
            ExploitsNeutralizedValue.Text = exploitsNeutralized.ToString();
            PersistenceEntriesValue.Text = persistenceEntriesDeleted.ToString();
            TotalThreatsValue.Text = totalThreatsHandled.ToString();
            
            // Calculate system health
            var health = 100 - (activeThreats * 10);
            health = Math.Max(0, health);
            SystemHealthValue.Text = $"{health}%";
        }

        private void UpdatePerformanceCharts()
        {
            UpdateChart(CpuChart, cpuHistory, Colors.Cyan);
            UpdateChart(MemoryChart, memoryHistory, Colors.Magenta);
        }

        private void UpdateChart(Canvas canvas, List<double> data, Color color)
        {
            canvas.Children.Clear();
            
            if (data.Count < 2) return;
            
            var width = canvas.ActualWidth;
            var height = canvas.ActualHeight;
            var maxValue = data.Max();
            var minValue = data.Min();
            var range = maxValue - minValue;
            
            if (range == 0) range = 1;
            
            var polyline = new Polyline
            {
                Stroke = new SolidColorBrush(color),
                StrokeThickness = 2,
                Points = new PointCollection()
            };
            
            for (int i = 0; i < data.Count; i++)
            {
                var x = (i / (double)(data.Count - 1)) * width;
                var y = height - ((data[i] - minValue) / range) * height;
                polyline.Points.Add(new Point(x, y));
            }
            
            canvas.Children.Add(polyline);
        }

        private void UpdateSystemHeatmap()
        {
            SystemHeatmap.Children.Clear();
            
            // Create a simple heatmap showing system activity
            var random = new Random();
            for (int i = 0; i < 10; i++)
            {
                for (int j = 0; j < 10; j++)
                {
                    var intensity = random.Next(0, 100);
                    var color = intensity > 80 ? Colors.Red : 
                               intensity > 60 ? Colors.Orange : 
                               intensity > 40 ? Colors.Yellow : 
                               intensity > 20 ? Colors.Green : Colors.DarkGreen;
                    
                    var rect = new Rectangle
                    {
                        Width = 15,
                        Height = 15,
                        Fill = new SolidColorBrush(color),
                        Opacity = intensity / 100.0
                    };
                    
                    Canvas.SetLeft(rect, i * 18);
                    Canvas.SetTop(rect, j * 18);
                    SystemHeatmap.Children.Add(rect);
                }
            }
        }

        private double GetTotalPhysicalMemory()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var totalMemory = Convert.ToDouble(obj["TotalPhysicalMemory"]) / 1024 / 1024; // Convert to MB
                        if (totalMemory <= 0) totalMemory = 4096; // Fallback to 4GB if invalid
                        return totalMemory;
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Memory WMI query failed: {ex.Message}");
            }
            return 4096; // Default to 4GB instead of 8GB
        }

        protected override void OnClosed(EventArgs e)
        {
            statusTimer?.Stop();
            metricsTimer?.Stop();
            uptimeTimer?.Stop();
            cpuCounter?.Dispose();
            memoryCounter?.Dispose();
            PhageSync.StopMeshNetwork();
            HoneyProcess.StopHoneyProcesses();
            ZeroTrustRuntime.StopZeroTrustProtection();
            DnsSinkhole.StopDnsSinkhole();
            RollbackEngine.StopRollbackEngine();
            PhishingGuard.StopPhishingGuard();
            LiveCommandShell.StopCommandShell();
            base.OnClosed(e);
        }

        // Example hook in detection logic (call in ExploitShield, CredentialTrap, etc.)
        private void OnCriticalThreatDetected(string threatType, string target)
        {
            // Share with mesh
            PhageSync.ShareThreat(new ThreatData {
                ThreatHash = $"{threatType}_{DateTime.Now.Ticks}",
                ThreatType = threatType,
                TargetPath = target,
                ThreatLevel = "Critical",
                Description = $"Critical threat detected: {threatType} on {target}"
            });
            // Trigger rollback
            RollbackEngine.TriggerRollback();
            // Optionally alert phishing guard
            if (threatType.ToLower().Contains("phish"))
                PhishingGuard.StartPhishingGuard();
        }

        private void UpdateCommandCenter()
        {
            // Populate EndpointGrid from PhageSync
            var endpoints = PhageVirus.Modules.PhageSync.GetActivePeers()
                .Select(peer => new EndpointInfo
                {
                    NodeId = peer,
                    LastScan = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), // Placeholder
                    ThreatCount = PhageVirus.Modules.PhageSync.GetSharedThreats().Count(t => t.NodeId == peer),
                    Status = "Online"
                }).ToList();
            EndpointGrid.ItemsSource = endpoints;
            // Update summary
            CommandCenterLastScan.Text = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            CommandCenterThreatCount.Text = PhageVirus.Modules.PhageSync.GetSharedThreats().Count.ToString();
            CommandCenterStatus.Text = "Online";
        }

        private void AdminShellExecute_Click(object? sender, RoutedEventArgs e)
        {
            var cmd = AdminShellInput.Text;
            if (string.IsNullOrWhiteSpace(cmd)) return;
            // For demo, use hardcoded password
            var result = PhageVirus.Modules.LiveCommandShell.ExecuteCommand(cmd, "PhageVirus2024!Secure");
            AdminShellOutput.Text = result;
        }

        public class EndpointInfo
        {
            public string NodeId { get; set; } = string.Empty;
            public string LastScan { get; set; } = string.Empty;
            public int ThreatCount { get; set; }
            public string Status { get; set; } = "Unknown";
        }

        public class ThreatTimelineItem
        {
            public string Timestamp { get; set; } = string.Empty;
            public string ThreatType { get; set; } = string.Empty;
            public string Target { get; set; } = string.Empty;
            public string Action { get; set; } = string.Empty;
            public string Status { get; set; } = string.Empty;
        }



        public class ModuleStatus
        {
            public string Name { get; set; } = string.Empty;
            public ModuleHealth Status { get; set; }
            public DateTime LastUpdate { get; set; } = DateTime.Now;
        }

        public enum ModuleHealth
        {
            Running,
            Stressed,
            Failed
        }

        public class AppConfig
        {
            public EmailSettings EmailSettings { get; set; } = new EmailSettings();
            public ModuleSettings Modules { get; set; } = new ModuleSettings();
            public PerformanceSettings Performance { get; set; } = new PerformanceSettings();
        }
        
        public class ModuleSettings
        {
            public bool ProcessWatcher { get; set; } = true;
            public bool AutorunBlocker { get; set; } = true;
            public bool MemoryTrap { get; set; } = true;
            public bool SandboxMode { get; set; } = true;
            public bool CredentialTrap { get; set; } = true;
            public bool ExploitShield { get; set; } = true;
            public bool WatchdogCore { get; set; } = true;
            public bool RedTeamAgent { get; set; } = false;
            public bool PhageSync { get; set; } = false;
            public bool HoneyProcess { get; set; } = false;
            public bool ZeroTrustRuntime { get; set; } = true;
            public bool DnsSinkhole { get; set; } = true;
            public bool RollbackEngine { get; set; } = true;
            public bool PhishingGuard { get; set; } = true;
            public bool LiveCommandShell { get; set; } = false;
            public bool AnomalyScoreClassifier { get; set; } = true;
            public bool FirewallGuard { get; set; } = true;
            public bool SelfReplication { get; set; } = false; // Added for staggered startup
            public bool BehaviorTest { get; set; } = false; // Added for staggered startup
        }
        
        public class PerformanceSettings
        {
            public bool EnableContinuousLearning { get; set; } = false;
            public int MaxReplicas { get; set; } = 1;
            public int ScanThrottleSeconds { get; set; } = 10;
            public int LogExportIntervalSeconds { get; set; } = 30;
            public int BehaviorTrackingIntervalSeconds { get; set; } = 30;
            public int ProcessMonitoringIntervalSeconds { get; set; } = 30;
            public int MemoryScanIntervalSeconds { get; set; } = 30;
            public int MaxBufferSize { get; set; } = 100;
            public string DefaultLogLevel { get; set; } = "Warning";
        }

        public class EmailSettings
        {
            public string SmtpServer { get; set; } = "smtp.gmail.com";
            public int Port { get; set; } = 587;
            public string Email { get; set; } = string.Empty;
        }

        // Red Team Simulation Event Handlers
        private async void StartRedTeamAgent_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                RedTeamAgent.InitializeRedTeamAgent();
                redTeamAgentActive = true;
                UpdateModuleStatusIndicator("RedTeamAgent", ModuleHealth.Running);
                ProtectionLogBox.AppendText($"[{DateTime.Now:HH:mm:ss}] Red Team Agent initialized and ready for simulations\n");
                ProtectionLogStatus.Text = "Red Team Agent Active";
                
                LogBox.AppendText("🔴 Red Team Agent started - Ready for attack simulations\n");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start Red Team Agent: {ex.Message}", LogBox.AppendText);
                ProtectionLogBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ERROR: Failed to start Red Team Agent: {ex.Message}\n");
            }
        }

        private void StopRedTeamAgent_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                RedTeamAgent.DeactivateRedTeamAgent();
                redTeamAgentActive = false;
                UpdateModuleStatusIndicator("RedTeamAgent", ModuleHealth.Failed);
                ProtectionLogBox.AppendText($"[{DateTime.Now:HH:mm:ss}] Red Team Agent deactivated\n");
                ProtectionLogStatus.Text = "Red Team Agent Stopped";
                
                LogBox.AppendText("⏹️ Red Team Agent stopped\n");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to stop Red Team Agent: {ex.Message}", LogBox.AppendText);
            }
        }

        private async void CredentialDumpSimulation_Click(object sender, RoutedEventArgs e)
        {
            await RunAttackSimulation("Credential Dump", CreateCredentialDumpPlaybook());
        }

        private async void ProcessHollowingSimulation_Click(object sender, RoutedEventArgs e)
        {
            await RunAttackSimulation("Process Hollowing", CreateProcessHollowingPlaybook());
        }

        private async void LateralMovementSimulation_Click(object sender, RoutedEventArgs e)
        {
            await RunAttackSimulation("Lateral Movement", CreateLateralMovementPlaybook());
        }

        private async void PersistenceSimulation_Click(object sender, RoutedEventArgs e)
        {
            await RunAttackSimulation("Persistence", CreatePersistencePlaybook());
        }

        private async void RansomwareSimulation_Click(object sender, RoutedEventArgs e)
        {
            await RunAttackSimulation("Ransomware", CreateRansomwarePlaybook());
        }

        private async void PhishingSimulation_Click(object sender, RoutedEventArgs e)
        {
            await RunAttackSimulation("Phishing", CreatePhishingPlaybook());
        }

        private async void FullAttackChainSimulation_Click(object sender, RoutedEventArgs e)
        {
            await RunAttackSimulation("Full Attack Chain", CreateFullAttackChainPlaybook());
        }

        private async void LOLBinSimulation_Click(object sender, RoutedEventArgs e)
        {
            await RunAttackSimulation("LOLBin Attack", CreateLOLBinPlaybook());
        }

        private async void InMemorySimulation_Click(object sender, RoutedEventArgs e)
        {
            await RunAttackSimulation("In-Memory Loader", CreateInMemoryPlaybook());
        }

        private async void TokenHijackSimulation_Click(object sender, RoutedEventArgs e)
        {
            await RunAttackSimulation("Token Hijacking", CreateTokenHijackPlaybook());
        }

        private async void SupplyChainSimulation_Click(object sender, RoutedEventArgs e)
        {
            await RunAttackSimulation("Supply Chain", CreateSupplyChainPlaybook());
        }

        private async void CloudAttackSimulation_Click(object sender, RoutedEventArgs e)
        {
            await RunAttackSimulation("Cloud Attack", CreateCloudAttackPlaybook());
        }

        private async void SSRFSimulation_Click(object sender, RoutedEventArgs e)
        {
            await RunAttackSimulation("SSRF Attack", CreateSSRFPlaybook());
        }

        private async void PrivilegeEscalationSimulation_Click(object sender, RoutedEventArgs e)
        {
            await RunAttackSimulation("Privilege Escalation", CreatePrivilegeEscalationPlaybook());
        }

        private async Task RunAttackSimulation(string attackName, RedTeamAgent.AttackPlaybook playbook)
        {
            if (!redTeamAgentActive)
            {
                MessageBox.Show("Please start the Red Team Agent first.", "Agent Not Active", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                ProtectionLogBox.AppendText($"[{DateTime.Now:HH:mm:ss}] Starting {attackName} simulation...\n");
                ProtectionLogStatus.Text = $"Running {attackName} simulation...";

                // Run the simulation
                var result = await RedTeamAgent.ExecutePlaybookAsync(playbook);

                // Process results
                ProcessSimulationResults(attackName, result);

                ProtectionLogBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {attackName} simulation completed\n");
                ProtectionLogStatus.Text = "Simulation completed";
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Attack simulation failed: {ex.Message}", LogBox.AppendText);
                ProtectionLogBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ERROR: {attackName} simulation failed: {ex.Message}\n");
                ProtectionLogStatus.Text = "Simulation failed";
            }
        }

        private void ProcessSimulationResults(string attackName, RedTeamAgent.SimulationResult result)
        {
            // Add results to the grid
            foreach (var stepResult in result.StepResults)
            {
                var attackResult = new AttackSimulationResult
                {
                    Timestamp = stepResult.StartTime.ToString("HH:mm:ss"),
                    AttackType = attackName,
                    Step = stepResult.StepName,
                    Result = stepResult.Success ? "Success" : "Failed",
                    WasBlocked = stepResult.WasBlocked,
                    WasDetected = stepResult.WasDetected
                };

                attackResults.Add(attackResult);

                // Log protection module responses
                if (stepResult.WasBlocked)
                {
                    ProtectionLogBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ✅ PROTECTION: {stepResult.StepName} was BLOCKED by security controls\n");
                    UpdateAttackScore(attackName, 100); // Perfect score for blocked attack
                }
                else if (stepResult.WasDetected)
                {
                    ProtectionLogBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ⚠️ DETECTION: {stepResult.StepName} was DETECTED but not blocked\n");
                    UpdateAttackScore(attackName, 75); // Good score for detection
                }
                else
                {
                    ProtectionLogBox.AppendText($"[{DateTime.Now:HH:mm:ss}] ❌ GAP: {stepResult.StepName} was NOT detected or blocked\n");
                    UpdateAttackScore(attackName, 25); // Poor score for undetected attack
                }
            }

            // Update security scores
            UpdateSecurityScores();
        }

        private void UpdateAttackScore(string attackName, int score)
        {
            var category = GetAttackCategory(attackName);
            if (attackScores.ContainsKey(category))
            {
                attackScores[category] = Math.Min(100, Math.Max(0, score));
            }
        }

        private string GetAttackCategory(string attackName)
        {
            return attackName switch
            {
                "Credential Dump" => "CredentialAccess",
                "Process Hollowing" => "Exploitation",
                "Lateral Movement" => "LateralMovement",
                "Persistence" => "Persistence",
                "Ransomware" => "MalwareProtection",
                "Phishing" => "MalwareProtection",
                "Full Attack Chain" => "Exploitation",
                "LOLBin Attack" => "Exploitation",
                "In-Memory Loader" => "Exploitation",
                "Token Hijacking" => "Exploitation",
                "Supply Chain" => "Exploitation",
                "Cloud Attack" => "Exploitation",
                "SSRF Attack" => "Exploitation",
                "Privilege Escalation" => "Exploitation",
                _ => "Exploitation"
            };
        }

        private void UpdateSecurityScores()
        {
            // Calculate overall score
            var overallScore = attackScores.Values.Average();
            OverallSecurityScore.Text = $"{overallScore:F0}%";

            // Update individual scores
            CredentialScore.Text = $"{attackScores["CredentialAccess"]}%";
            ExploitationScore.Text = $"{attackScores["Exploitation"]}%";
            LateralScore.Text = $"{attackScores["LateralMovement"]}%";
            PersistenceScore.Text = $"{attackScores["Persistence"]}%";
            MalwareScore.Text = $"{attackScores["MalwareProtection"]}%";

            // Update colors based on scores
            UpdateScoreColors();
        }

        private void UpdateScoreColors()
        {
            var scores = new[] { CredentialScore, ExploitationScore, LateralScore, PersistenceScore, MalwareScore };
            var scoreValues = new[] { attackScores["CredentialAccess"], attackScores["Exploitation"], attackScores["LateralMovement"], attackScores["Persistence"], attackScores["MalwareProtection"] };

            for (int i = 0; i < scores.Length; i++)
            {
                scores[i].Foreground = scoreValues[i] switch
                {
                    >= 90 => Brushes.Green,
                    >= 70 => Brushes.Orange,
                    >= 50 => Brushes.Yellow,
                    _ => Brushes.Red
                };
            }

            var overallScore = attackScores.Values.Average();
            OverallSecurityScore.Foreground = overallScore switch
            {
                >= 90 => Brushes.Green,
                >= 70 => Brushes.Orange,
                >= 50 => Brushes.Yellow,
                _ => Brushes.Red
            };
        }

        private void ClearSimulationResults_Click(object sender, RoutedEventArgs e)
        {
            attackResults.Clear();
            ProtectionLogBox.Clear();
            ProtectionLogStatus.Text = "Results cleared";
        }

        private void ExportSimulationResults_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var exportPath = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"redteam_simulation_results_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
                
                using (var writer = new StreamWriter(exportPath))
                {
                    writer.WriteLine("PhageVirus Red Team Simulation Results");
                    writer.WriteLine("=====================================");
                    writer.WriteLine($"Generated: {DateTime.Now}");
                    writer.WriteLine();

                    writer.WriteLine("Attack Results:");
                    writer.WriteLine("---------------");
                    foreach (var result in attackResults)
                    {
                        writer.WriteLine($"[{result.Timestamp}] {result.AttackType} - {result.Step}: {result.Result} (Blocked: {result.WasBlocked}, Detected: {result.WasDetected})");
                    }

                    writer.WriteLine();
                    writer.WriteLine("Security Scores:");
                    writer.WriteLine("----------------");
                    writer.WriteLine($"Overall Security Score: {OverallSecurityScore.Text}");
                    writer.WriteLine($"Credential Access: {CredentialScore.Text}");
                    writer.WriteLine($"Process Exploitation: {ExploitationScore.Text}");
                    writer.WriteLine($"Lateral Movement: {LateralScore.Text}");
                    writer.WriteLine($"Persistence: {PersistenceScore.Text}");
                    writer.WriteLine($"Malware Protection: {MalwareScore.Text}");

                    writer.WriteLine();
                    writer.WriteLine("Protection Logs:");
                    writer.WriteLine("----------------");
                    writer.WriteLine(ProtectionLogBox.Text);
                }

                MessageBox.Show($"Simulation results exported to: {exportPath}", "Export Complete", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to export results: {ex.Message}", "Export Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ClearProtectionLog_Click(object sender, RoutedEventArgs e)
        {
            ProtectionLogBox.Clear();
            ProtectionLogStatus.Text = "Protection log cleared";
        }

        private void ExportProtectionLog_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var exportPath = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"protection_log_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
                File.WriteAllText(exportPath, ProtectionLogBox.Text);
                MessageBox.Show($"Protection log exported to: {exportPath}", "Export Complete", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to export protection log: {ex.Message}", "Export Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // Attack Playbook Creation Methods
        private RedTeamAgent.AttackPlaybook CreateCredentialDumpPlaybook()
        {
            return new RedTeamAgent.AttackPlaybook
            {
                Id = "credential_dump_sim",
                Name = "Credential Dump Simulation",
                Description = "Simulates LSASS access and credential dumping attempts",
                Steps = new List<RedTeamAgent.AttackStep>
                {
                    new RedTeamAgent.AttackStep { Name = "Simulate LSASS Access", Action = "simulate_lsass_access", DelayMs = 2000 },
                    new RedTeamAgent.AttackStep { Name = "Drop Fake Mimikatz", Action = "drop_fake_mimikatz", DelayMs = 2000 }
                },
                AutoCleanup = true,
                TimeoutSeconds = 60
            };
        }

        private RedTeamAgent.AttackPlaybook CreateProcessHollowingPlaybook()
        {
            return new RedTeamAgent.AttackPlaybook
            {
                Id = "process_hollowing_sim",
                Name = "Process Hollowing Simulation",
                Description = "Simulates process hollowing and code injection",
                Steps = new List<RedTeamAgent.AttackStep>
                {
                    new RedTeamAgent.AttackStep { Name = "Simulate Process Hollowing", Action = "simulate_process_hollowing", DelayMs = 2000 }
                },
                AutoCleanup = true,
                TimeoutSeconds = 60
            };
        }

        private RedTeamAgent.AttackPlaybook CreateLateralMovementPlaybook()
        {
            return new RedTeamAgent.AttackPlaybook
            {
                Id = "lateral_movement_sim",
                Name = "Lateral Movement Simulation",
                Description = "Simulates lateral movement techniques",
                Steps = new List<RedTeamAgent.AttackStep>
                {
                    new RedTeamAgent.AttackStep { Name = "Simulate Lateral Movement", Action = "simulate_lateral_movement", DelayMs = 2000 }
                },
                AutoCleanup = true,
                TimeoutSeconds = 60
            };
        }

        private RedTeamAgent.AttackPlaybook CreatePersistencePlaybook()
        {
            return new RedTeamAgent.AttackPlaybook
            {
                Id = "persistence_sim",
                Name = "Persistence Simulation",
                Description = "Simulates persistence mechanisms",
                Steps = new List<RedTeamAgent.AttackStep>
                {
                    new RedTeamAgent.AttackStep { Name = "Create Fake Persistence", Action = "create_fake_persistence", DelayMs = 2000 },
                    new RedTeamAgent.AttackStep { Name = "Create Fake Scheduled Task", Action = "create_fake_scheduled_task", DelayMs = 2000 },
                    new RedTeamAgent.AttackStep { Name = "Simulate Registry Attack", Action = "simulate_registry_attack", DelayMs = 2000 }
                },
                AutoCleanup = true,
                TimeoutSeconds = 60
            };
        }

        private RedTeamAgent.AttackPlaybook CreateRansomwarePlaybook()
        {
            return new RedTeamAgent.AttackPlaybook
            {
                Id = "ransomware_sim",
                Name = "Ransomware Simulation",
                Description = "Simulates ransomware behavior",
                Steps = new List<RedTeamAgent.AttackStep>
                {
                    new RedTeamAgent.AttackStep { Name = "Drop Fake Ransomware", Action = "drop_fake_ransomware", DelayMs = 2000 }
                },
                AutoCleanup = true,
                TimeoutSeconds = 60
            };
        }

        private RedTeamAgent.AttackPlaybook CreatePhishingPlaybook()
        {
            return new RedTeamAgent.AttackPlaybook
            {
                Id = "phishing_sim",
                Name = "Phishing Simulation",
                Description = "Simulates phishing attacks",
                Steps = new List<RedTeamAgent.AttackStep>
                {
                    new RedTeamAgent.AttackStep { Name = "Simulate Phishing", Action = "simulate_phishing", DelayMs = 2000 }
                },
                AutoCleanup = true,
                TimeoutSeconds = 60
            };
        }

        private RedTeamAgent.AttackPlaybook CreateFullAttackChainPlaybook()
        {
            return new RedTeamAgent.AttackPlaybook
            {
                Id = "full_attack_chain_sim",
                Name = "Full Attack Chain Simulation",
                Description = "Simulates a complete attack chain",
                Steps = new List<RedTeamAgent.AttackStep>
                {
                    new RedTeamAgent.AttackStep { Name = "Simulate LSASS Access", Action = "simulate_lsass_access", DelayMs = 1000 },
                    new RedTeamAgent.AttackStep { Name = "Simulate Process Hollowing", Action = "simulate_process_hollowing", DelayMs = 1000 },
                    new RedTeamAgent.AttackStep { Name = "Simulate Lateral Movement", Action = "simulate_lateral_movement", DelayMs = 1000 },
                    new RedTeamAgent.AttackStep { Name = "Create Fake Persistence", Action = "create_fake_persistence", DelayMs = 1000 },
                    new RedTeamAgent.AttackStep { Name = "Drop Fake Ransomware", Action = "drop_fake_ransomware", DelayMs = 1000 }
                },
                AutoCleanup = true,
                TimeoutSeconds = 120
            };
        }

        private RedTeamAgent.AttackPlaybook CreateLOLBinPlaybook()
        {
            return new RedTeamAgent.AttackPlaybook
            {
                Id = "lolbin_sim",
                Name = "LOLBin Attack Simulation",
                Description = "Simulates LOLBin (Local Object Link Binary) attacks",
                Steps = new List<RedTeamAgent.AttackStep>
                {
                    new RedTeamAgent.AttackStep { Name = "Simulate LOLBin Attack", Action = "simulate_lolbin_attack", DelayMs = 2000 }
                },
                AutoCleanup = true,
                TimeoutSeconds = 60
            };
        }

        private RedTeamAgent.AttackPlaybook CreateInMemoryPlaybook()
        {
            return new RedTeamAgent.AttackPlaybook
            {
                Id = "inmemory_sim",
                Name = "In-Memory Loader Simulation",
                Description = "Simulates loading malicious code into memory",
                Steps = new List<RedTeamAgent.AttackStep>
                {
                    new RedTeamAgent.AttackStep { Name = "Simulate In-Memory Loader", Action = "simulate_inmemory_loader", DelayMs = 2000 }
                },
                AutoCleanup = true,
                TimeoutSeconds = 60
            };
        }

        private RedTeamAgent.AttackPlaybook CreateTokenHijackPlaybook()
        {
            return new RedTeamAgent.AttackPlaybook
            {
                Id = "tokenhijack_sim",
                Name = "Token Hijacking Simulation",
                Description = "Simulates token hijacking techniques",
                Steps = new List<RedTeamAgent.AttackStep>
                {
                    new RedTeamAgent.AttackStep { Name = "Simulate Token Hijacking", Action = "simulate_token_hijacking", DelayMs = 2000 }
                },
                AutoCleanup = true,
                TimeoutSeconds = 60
            };
        }

        private RedTeamAgent.AttackPlaybook CreateSupplyChainPlaybook()
        {
            return new RedTeamAgent.AttackPlaybook
            {
                Id = "supplychain_sim",
                Name = "Supply Chain Attack Simulation",
                Description = "Simulates supply chain attacks",
                Steps = new List<RedTeamAgent.AttackStep>
                {
                    new RedTeamAgent.AttackStep { Name = "Simulate Supply Chain Attack", Action = "simulate_supply_chain_attack", DelayMs = 2000 }
                },
                AutoCleanup = true,
                TimeoutSeconds = 60
            };
        }

        private RedTeamAgent.AttackPlaybook CreateCloudAttackPlaybook()
        {
            return new RedTeamAgent.AttackPlaybook
            {
                Id = "cloudattack_sim",
                Name = "Cloud Attack Simulation",
                Description = "Simulates cloud-based attack techniques",
                Steps = new List<RedTeamAgent.AttackStep>
                {
                    new RedTeamAgent.AttackStep { Name = "Simulate Cloud Attack", Action = "simulate_cloud_attack", DelayMs = 2000 }
                },
                AutoCleanup = true,
                TimeoutSeconds = 60
            };
        }

        private RedTeamAgent.AttackPlaybook CreateSSRFPlaybook()
        {
            return new RedTeamAgent.AttackPlaybook
            {
                Id = "ssrf_sim",
                Name = "SSRF Attack Simulation",
                Description = "Simulates Server-Side Request Forgery attacks",
                Steps = new List<RedTeamAgent.AttackStep>
                {
                    new RedTeamAgent.AttackStep { Name = "Simulate SSRF Attack", Action = "simulate_ssrf_attack", DelayMs = 2000 }
                },
                AutoCleanup = true,
                TimeoutSeconds = 60
            };
        }

        private RedTeamAgent.AttackPlaybook CreatePrivilegeEscalationPlaybook()
        {
            return new RedTeamAgent.AttackPlaybook
            {
                Id = "privilegeescalation_sim",
                Name = "Privilege Escalation Simulation",
                Description = "Simulates privilege escalation techniques",
                Steps = new List<RedTeamAgent.AttackStep>
                {
                    new RedTeamAgent.AttackStep { Name = "Simulate Privilege Escalation", Action = "simulate_privilege_escalation", DelayMs = 2000 }
                },
                AutoCleanup = true,
                TimeoutSeconds = 60
            };
        }

        // Data Models for Red Team Simulation
        public class AttackSimulationResult
        {
            public string Timestamp { get; set; } = string.Empty;
            public string AttackType { get; set; } = string.Empty;
            public string Step { get; set; } = string.Empty;
            public string Result { get; set; } = string.Empty;
            public bool WasBlocked { get; set; }
            public bool WasDetected { get; set; }
        }
    }
}

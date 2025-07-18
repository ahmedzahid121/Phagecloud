# PhageVirus - Biological Virus Hunter & Advanced EDR System

A Windows desktop application that implements a **real, self-replicating, system-level virus hunter with enterprise-grade EDR capabilities** using .NET 8 WPF. This is not a simulation - it's a biological-style "phage virus" that actively hunts, prevents, injects into memory, neutralizes threats, self-replicates, and provides comprehensive threat intelligence and reporting.

## 🆕 **NEW ENHANCED FEATURES**

### 🧠 **ML-Powered Anomaly Detection**

- **AnomalyScoreClassifier**: Local ML.NET-based behavior scoring system
- **Real-time Process Analysis**: CPU, memory, file access, network connections, entropy scoring
- **Binary Classification Model**: Trained on normal vs suspicious process patterns
- **Continuous Learning**: Model improves over time with new threat data
- **Risk Scoring**: Probability-based threat assessment (0-100%)
- **Automated Response**: High-risk processes automatically flagged and handled

### 🔐 **Advanced Credential Protection (LSASS Guard)**

- **LSASS Access Detection**: Monitors attempts to access LSASS process memory
- **OpenProcess Monitoring**: Detects credential dumping tools (Mimikatz, ProcDump)
- **WDigest Manipulation**: Prevents WDigest registry manipulation attacks
- **Process Injection Detection**: Identifies credential theft via DLL injection
- **Registry Attack Prevention**: Blocks SAM/SYSTEM registry access attempts
- **PowerShell Attack Detection**: Monitors for credential extraction via PowerShell
- **WMI Attack Prevention**: Blocks WMI-based credential enumeration

### 🔧 **Dynamic Firewall Control (FirewallGuard)**

- **Real-time IP Blocking**: Dynamic blocking of malicious IP addresses
- **Domain-based Protection**: Automatic blocking of malicious domains
- **Threat Intelligence**: Built-in database of known malicious IPs and domains
- **PowerShell Integration**: Uses Windows Firewall PowerShell cmdlets
- **Network Connection Monitoring**: Real-time analysis of active connections
- **Suspicious Port Blocking**: Blocks common attack ports (4444, 8080, 9999)
- **Process-based Rules**: Application-specific firewall rules
- **Automatic Rule Management**: Creates and removes rules dynamically

### 📊 Real-time Visual Dashboard

- **Module Status Indicators**: Live pulse indicators for all 15+ security modules
- **Real-time Metrics**: Active threats, prevented attacks, CPU/memory usage, system health
- **Threat Intelligence Dashboard**: Local threat statistics and timeline
- **System Heatmap**: Visual activity representation
- **Process Monitoring**: Real-time system process analysis
- **Command Center**: Live endpoint management and secure admin shell

### 📊 Advanced Log Viewer & Real-Time Export

- **Comprehensive Log Viewer**: Advanced WPF-based log viewer with filtering and search
- **Real-time Log Export**: Automatic log export to desktop every 5 seconds
- **Behavior Testing**: Real system behavior analysis and monitoring
- **System Monitoring**: Process, file system, registry, and network activity tracking
- **Performance Analysis**: CPU, memory, disk, and system performance metrics
- **Security Assessment**: Comprehensive security posture evaluation
- **Multiple Export Formats**: TXT and CSV export capabilities
- **No UI Required**: Access logs even when main UI is not accessible

### 🕸️ Advanced Security Modules

#### Endpoint-to-Endpoint Phage Sync
- **Peer-to-Peer Mesh Network**: Real-time threat intelligence sharing between endpoints
- **Distributed Threat Database**: Synchronized threat signatures and behavioral patterns
- **Mesh Topology Management**: Automatic endpoint discovery and connection management
- **Threat Propagation**: Immediate threat alerts across the entire mesh network

#### HoneyProcess (Decoy Processes)
- **Strategic Decoy Placement**: Creates fake processes in high-risk locations
- **Malware Injection Detection**: Catches attempts to inject code into decoy processes
- **Behavioral Analysis**: Monitors decoy processes for suspicious activity patterns
- **Threat Intelligence Gathering**: Collects attack techniques and payload signatures

#### Zero Trust Runtime Hooks
- **DLL Injection Guards**: Real-time monitoring and blocking of unauthorized DLL injections
- **Process Signature Validation**: Verifies process authenticity using digital signatures
- **Memory Integrity Monitoring**: Detects unauthorized memory modifications
- **Runtime Behavior Analysis**: Continuous monitoring of process behavior patterns

#### DNS Sinkhole Integration
- **Malicious Domain Blocking**: Real-time blocking of known malicious domains
- **DNS Query Monitoring**: Intercepts and analyzes DNS requests for threat detection
- **Custom Block Lists**: User-defined domain blocking rules
- **Network Traffic Analysis**: Monitors network connections for suspicious activity

#### Live Command Shell
- **Secure Admin Terminal**: Isolated command execution environment with elevated privileges
- **Command Validation**: Validates commands before execution to prevent malicious operations
- **Session Logging**: Comprehensive logging of all command activities
- **Access Control**: Role-based access control for different command categories

#### Rollback Engine
- **System State Snapshots**: Automatic creation of system restore points
- **Threat-Triggered Rollback**: Automatic system restoration on serious attacks
- **Selective Rollback**: Granular restoration of specific files or registry entries
- **Backup Management**: Intelligent backup rotation and storage management

#### Phishing Guard
- **Clipboard Monitoring**: Detects and blocks suspicious URLs and credentials in clipboard
- **Browser Integration**: Monitors browser activity for phishing attempts
- **Download Analysis**: Analyzes downloaded files for malicious content
- **Real-time Alerts**: Immediate notifications of potential phishing activities

### 📦 Portable Deployment

- **Single Executable**: Self-contained deployment with all modules
- **Red Team Mode**: Stealth deployment with obfuscation
- **Code Signing**: Optional certificate signing for enterprise use
- **Deployment Scripts**: Automated installation and removal

### 🧪 Modular Testing

- **ModuleTestRunner**: Individual module testing and verification
- **Isolated Testing**: Safe testing in virtual environments
- **Effectiveness Verification**: Detection rate and performance testing
- **Test Reports**: Comprehensive testing documentation

### 🔴 Red Team Simulation Engine

- **Advanced Attack Simulations**: Test against real-world attack techniques
- **Living-off-the-Land (LOLBin)**: Simulate abuse of legitimate Windows tools
- **In-Memory/Fileless Attacks**: Test memory-resident payload detection
- **Token Hijacking**: Simulate session theft and user impersonation
- **Supply Chain Attacks**: Test against compromised package scenarios
- **Cloud Attack Simulations**: Test cloud infrastructure security
- **SSRF Attacks**: Simulate server-side request forgery
- **Privilege Escalation**: Test user privilege elevation detection
- **Security Scoring**: Real-time protection effectiveness assessment
- **Comprehensive Reporting**: Detailed attack simulation results
- **Safe Sandboxing**: All simulations run in isolated environments
- **Automatic Cleanup**: Test artifacts are automatically removed

### 📧 Advanced Email Reporting

- **EDR-Style Reports**: Professional security reports with executive summaries
- **Multiple Attachments**: Logs, JSON data, system information
- **Scheduled Reporting**: 12/24 hour or attack-triggered reports
- **SMTP/TLS Support**: Enterprise email integration

## ☁️ **UNIFIED CLOUD IMPLEMENTATION** 🆕

### 🚀 **Cloud-Enabled Architecture**

PhageVirus now supports **unified cloud integration** that connects all original modules to cloud services while maintaining full local capabilities. This provides the best of both worlds: powerful local security with cloud scalability.

#### **Three Operating Modes**

- **🖥️ Local Mode** (Full Power): All modules run locally (500MB RAM, 20% CPU)
- **🔄 Hybrid Mode** (Balanced): Core modules local + advanced modules cloud (200MB RAM, 10% CPU)  
- **☁️ Cloud Mode** (Lightweight): Minimal local + cloud primary processing (100MB RAM, 5% CPU)

#### **Cloud Integration Features**

- **🔗 Unified Module Manager**: Central coordination of all 25+ security modules
- **📊 Cloud Telemetry**: Real-time threat data sharing with Azure and AWS
- **🧠 Cloud ML Analysis**: Offloads heavy ML processing to cloud services
- **🛡️ Threat Intelligence**: Global threat database access and correlation
- **⚡ Resource Optimization**: Automatic memory and CPU management
- **🔄 Distributed Detection**: Cross-endpoint threat correlation and analysis

#### **Performance Improvements**

| Mode | Memory | CPU | Features | Cloud Usage |
|------|--------|-----|----------|-------------|
| **Original** | 500MB+ | 20%+ | All Local | None |
| **Local** | 500MB | 20% | All Local | None |
| **Hybrid** | 200MB | 10% | Local + Cloud | Moderate |
| **Cloud** | 100MB | 5% | Cloud Primary | High |

#### **Enhanced Modules with Cloud Integration**

- **ProcessWatcher**: Cloud telemetry and threat analysis
- **AnomalyScoreClassifier**: Cloud ML model offloading and analysis
- **CredentialTrap**: Cloud threat intelligence and credential theft detection
- **All Other Modules**: Cloud-enabled with telemetry and analysis

#### **Quick Start - Cloud Mode**

```powershell
# Initialize unified system
.\PhageVirus.exe --mode hybrid

# Switch to cloud mode for lightweight operation
.\PhageVirus.exe --mode cloud

# Return to full local power
.\PhageVirus.exe --mode local
```

#### **Cloud Services Support**

- **Azure Services**: App Service, Functions, Sentinel, ML Studio
- **AWS Services**: Lambda, Kinesis, DynamoDB, ECS
- **Hybrid Deployment**: Multi-cloud support with automatic failover
- **Enterprise Features**: Role-based access, audit logging, compliance

> **📖 For complete cloud implementation details, see [UNIFIED_CLOUD_IMPLEMENTATION.md](UNIFIED_CLOUD_IMPLEMENTATION.md)**

## ⚠️ **IMPORTANT WARNING**

**This is a powerful Red Team tool for educational and research purposes only.**

- **REQUIRES ELEVATED PRIVILEGES** (Administrator)
- **Uses real Windows APIs** for process manipulation and memory injection
- **Self-replicates** to multiple system locations
- **Injects code** into suspicious processes
- **Blocks threats before execution** using prevention modules
- **NEVER run on production systems** without explicit permission
- **Use only in controlled environments** (VM, sandbox, test lab)

## 🦠 What Makes This Different

### Biological Virus Behavior

- **Self-Replicating**: Copies itself to strategic locations with mutations
- **Autonomous Hunting**: Actively scans for threats without user intervention
- **Memory Injection**: Uses Windows APIs to inject neutralization code into processes
- **System-Level Access**: Requires administrator privileges for full functionality
- **Self-Destruction**: Can completely remove itself after cleanup

### Real System-Level Operations

- **Process Memory Scanning**: Reads and analyzes process memory for malicious patterns
- **Code Injection**: Injects neutralization payloads into suspicious processes
- **File Entropy Analysis**: Detects packed/encrypted malware using Shannon entropy
- **Advanced Heuristics**: Uses behavioral analysis and pattern matching
- **Self-Replication**: Creates mutated copies to avoid detection

### 🛡️ Prevention System

- **Real-Time Process Watching**: Intercepts malicious processes before execution
- **Autorun Blocker**: Monitors and blocks persistence mechanisms
- **Memory Trap**: Detects injected payloads in process memory
- **Sandbox Mode**: Blocks suspicious files in high-risk folders
- **Behavioral Pattern Matching**: Lightweight rules engine for threat detection

## 🎯 Features

### Core Functionality

- **Real Process Hunting**: Uses Windows APIs to scan all running processes
- **Memory Injection**: Injects neutralization code into suspicious processes
- **Advanced File Analysis**: Entropy analysis, behavioral heuristics, pattern matching
- **Self-Replication**: Creates mutated copies in strategic locations
- **Autonomous Operation**: Hunts threats automatically without user intervention
- **System-Level Access**: Requires administrator privileges for full functionality
- **Real-time Monitoring**: Live system monitoring with visual indicators
- **Threat Intelligence**: Comprehensive local threat analysis and reporting

### Enhanced Logging & Analysis

- **Advanced Log Viewer**: Sophisticated WPF-based log viewer with real-time updates
- **Real-time Log Export**: Automatic log export to desktop every 5 seconds
- **Behavior Testing**: Real system behavior analysis and monitoring
- **Comprehensive Logging**: Detailed logging of all system activities and operations
- **System Monitoring**: Process, file system, registry, and network activity tracking
- **Performance Analysis**: CPU, memory, disk, and system performance metrics
- **Security Assessment**: Comprehensive security posture evaluation
- **Multiple Export Formats**: TXT and CSV export capabilities
- **No UI Required**: Access logs even when main UI is not accessible

### 🛡️ Prevention Modules

#### ProcessWatcher

- **Real-time process monitoring** using WMI event watchers
- **Command-line analysis** for suspicious patterns
- **Process ancestry tracking** to detect attack chains
- **Automatic blocking** of malicious processes before execution
- **Pattern matching** for PowerShell attacks, reverse shells, and exploit tools

#### AutorunBlocker

- **Registry monitoring** for suspicious autorun entries
- **Startup folder protection** against malicious files
- **Scheduled task analysis** for persistence mechanisms
- **Automatic cleanup** of suspicious persistence attempts
- **Backup creation** before removal for safety

#### MemoryTrap

- **Memory region scanning** for injected payloads
- **Shellcode pattern detection** in process memory
- **High entropy detection** for packed/encrypted content
- **Memory overwriting** of suspicious regions
- **Process memory injection** for defensive purposes

#### SandboxMode

- **High-risk folder monitoring** (Downloads, Desktop, Temp)
- **File signature analysis** for executable detection
- **Entropy-based detection** for packed malware
- **Whitelist management** for legitimate files
- **Automatic quarantine** of suspicious files

#### PhageSync (Endpoint-to-Endpoint)

- **Peer-to-peer mesh network** for threat intelligence sharing
- **Distributed threat database** synchronization
- **Automatic endpoint discovery** and connection management
- **Real-time threat propagation** across the network

#### HoneyProcess (Decoy Processes)

- **Strategic decoy placement** in high-risk locations
- **Malware injection detection** through decoy monitoring
- **Behavioral analysis** of suspicious process interactions
- **Threat intelligence gathering** from attack attempts

#### Zero Trust Runtime Hooks

- **DLL injection guards** with real-time monitoring
- **Process signature validation** using digital certificates
- **Memory integrity monitoring** for unauthorized changes
- **Runtime behavior analysis** for suspicious patterns

#### DNS Sinkhole

- **Malicious domain blocking** with real-time updates
- **DNS query monitoring** for threat detection
- **Custom block lists** for organization-specific threats
- **Network traffic analysis** for suspicious connections

#### Live Command Shell

- **Secure admin terminal** with isolated execution
- **Command validation** to prevent malicious operations
- **Session logging** for audit trails
- **Access control** with role-based permissions

#### Rollback Engine

- **System state snapshots** for automatic restoration
- **Threat-triggered rollback** on serious attacks
- **Selective rollback** for granular restoration
- **Backup management** with intelligent rotation

#### Phishing Guard

- **Clipboard monitoring** for suspicious content
- **Browser integration** for phishing detection
- **Download analysis** for malicious files
- **Real-time alerts** for potential threats

### Biological Virus Features

- **Memory Pattern Scanning**: Detects malicious byte patterns in process memory
- **Code Injection**: Uses CreateRemoteThread and VirtualAllocEx for payload delivery
- **Process Termination**: Forcefully terminates malicious processes
- **File Mutation**: Creates unique variants to avoid detection
- **Persistence**: Establishes startup mechanisms for continuous operation

## 🧱 Project Structure

```
PhageVirus/
├── PhageVirus.csproj          # Main project file with elevated privileges
├── app.manifest              # UAC manifest for admin rights
├── App.xaml                   # Application resources and styling
├── App.xaml.cs               # Application entry point
├── MainWindow.xaml           # Main UI layout
├── MainWindow.xaml.cs        # Main window logic with autonomous hunting
├── Modules/                  # Backend modules
│   ├── SystemHacker.cs      # Windows API process/memory manipulation
│   ├── SelfReplicator.cs    # Self-replication and mutation
│   ├── VirusHunter.cs       # Advanced threat detection engine
│   ├── PayloadReplacer.cs   # Real threat neutralization
│   ├── ProcessWatcher.cs    # Real-time process monitoring & blocking
│   ├── AutorunBlocker.cs    # Persistence mechanism blocking
│   ├── MemoryTrap.cs        # Memory injection detection & prevention
│   ├── SandboxMode.cs       # Safe execution blocking
│   ├── CredentialTrap.cs    # Credential theft prevention (LSASS Guard)
│   ├── ExploitShield.cs     # Memory-based exploit protection
│   ├── WatchdogCore.cs      # Self-healing module monitoring
│   ├── ModuleTestRunner.cs  # Comprehensive module testing
│   ├── EnhancedLogger.cs    # Comprehensive logging
│   ├── SelfDestruct.cs      # Self-deletion functionality
│   ├── EmailReporter.cs     # Advanced EDR-style email reporting
│   ├── PhageSync.cs         # Endpoint-to-endpoint threat sharing
│   ├── HoneyProcess.cs      # Decoy process creation and monitoring
│   ├── ZeroTrustRuntime.cs  # DLL injection guards and process validation
│   ├── DnsSinkhole.cs       # Malicious domain blocking
│   ├── LiveCommandShell.cs  # Secure admin terminal
│   ├── RollbackEngine.cs    # System backup and restoration
│   ├── PhishingGuard.cs     # Phishing detection and prevention
│   ├── AnomalyScoreClassifier.cs # ML-powered behavior analysis
│   ├── FirewallGuard.cs     # Dynamic firewall control
│   ├── CloudIntegration.cs  # Cloud communication bridge 🆕
│   ├── UnifiedConfig.cs     # Unified configuration system 🆕
│   └── UnifiedModuleManager.cs # Central module coordination 🆕
├── build_portable.ps1       # Portable deployment script
├── ENHANCED_FEATURES_GUIDE.md # Complete feature documentation
├── UNIFIED_CLOUD_IMPLEMENTATION.md # Cloud implementation guide 🆕
├── appsettings.json         # Configuration file
├── build_and_run.bat        # Build script
├── run_phagevirus.ps1       # PowerShell build script
├── QUICK_START.md           # Quick setup guide
└── README.md                # This file
```

## 🖥️ Enhanced UI Components

### Main Window Layout

- **Header**: Title with real-time module status indicators (8 pulsing dots)
- **Metrics Dashboard**: 6 real-time metrics (threats, attacks, CPU, memory, time, health)
- **Tabbed Interface**: 4 main sections with comprehensive functionality
- **Status Bar**: Overall system status and uptime display

### Tabbed Interface

1. **📊 Threat Intelligence**: Statistics, timeline, and system heatmap
2. **📋 Live Activity**: Real-time logs with export functionality
3. **🖥️ System Monitor**: Process monitoring and resource charts
4. **⚙️ Configuration**: Module controls, email settings, and system status
5. **🕸️ Command Center**: Endpoint management, mesh network status, and secure admin shell

### Visual Design

- **Theme**: Professional dark mode with futuristic aesthetics
- **Colors**: Deep backgrounds (#0a0a0a, #1a1a1a) with cyan accents (#00ffff)
- **Effects**: Pulsing animations, drop shadows, and glow effects
- **Fonts**: Segoe UI for general text, Consolas for technical data
- **Responsive**: Adaptive layout that scales with window size

## 🚀 Getting Started

### Prerequisites

- .NET 8.0 SDK or Runtime
- Windows 10/11
- Visual Studio 2022 or VS Code (for development)
- **Administrator privileges** (required for full functionality)

### Installation

1. **Clone or Download** the project files
2. **Open Command Prompt as Administrator** in the project directory
3. **Build the project**:

   ```bash
   dotnet build
   ```

4. **Run the application**:

   ```bash
   dotnet run
   ```

### Alternative: Using Visual Studio

1. Open `PhageVirus.csproj` in Visual Studio
2. **Run as Administrator** (right-click → Run as Administrator)
3. The application will launch with the futuristic UI

## 📋 Usage Guide

### Basic Operation

1. **Launch** the application as Administrator
2. **Choose Operating Mode** (Local/Hybrid/Cloud) for optimal performance
3. **Watch** the unified module manager activate all security modules
4. **Monitor** real-time metrics dashboard for system status
5. **Navigate** through tabs to access different features:
   - **Threat Intelligence**: View threat statistics and timeline
   - **Live Activity**: Monitor real-time logs and export data
   - **System Monitor**: Track processes and resource usage
   - **Configuration**: Control modules and email settings
6. **Use "START HUNTING"** to begin additional threat detection
7. **Review** detected threats in the timeline
8. **Configure** email reporting for automated alerts
9. **Use "SELF-DESTRUCT"** if threats were found (optional)

### Cloud-Enabled Operation

The application now supports three operating modes:

- **Local Mode**: Full power, all modules run locally (500MB RAM, 20% CPU)
- **Hybrid Mode**: Balanced, core modules local + advanced modules cloud (200MB RAM, 10% CPU)
- **Cloud Mode**: Lightweight, minimal local + cloud primary processing (100MB RAM, 5% CPU)

Switch modes using command line arguments:
```powershell
.\PhageVirus.exe --mode hybrid  # Recommended for most users
.\PhageVirus.exe --mode cloud   # For resource-constrained systems
.\PhageVirus.exe --mode local   # For maximum security (air-gapped)
```

### Autonomous Prevention System

The application automatically activates prevention modules on startup through the unified module manager:

1. **ProcessWatcher**: Monitors new processes and blocks malicious ones
2. **AutorunBlocker**: Protects against persistence mechanisms
3. **MemoryTrap**: Scans for injected payloads in memory
4. **SandboxMode**: Blocks suspicious files in high-risk folders
5. **PhageSync**: Establishes peer-to-peer mesh network for threat sharing
6. **HoneyProcess**: Deploys decoy processes for attack detection
7. **ZeroTrustRuntime**: Activates DLL injection guards and process validation
8. **DNS Sinkhole**: Blocks malicious domains and monitors network traffic
9. **Rollback Engine**: Creates system snapshots for potential restoration
10. **Phishing Guard**: Monitors clipboard and browser for phishing attempts
11. **AnomalyScoreClassifier**: ML-powered behavior analysis and scoring
12. **CredentialTrap**: Advanced LSASS protection and credential theft prevention
13. **FirewallGuard**: Dynamic firewall control and IP blocking

**Cloud Integration**: All modules now support cloud telemetry and analysis, providing enhanced threat detection and global threat intelligence sharing.

### Scan Process

The application performs a 4-phase scan:

1. **Prevention Activation**: Starts all prevention modules
2. **Threat Detection**: Scans predefined paths for suspicious files
3. **Analysis & Neutralization**: Processes each detected threat
4. **Report Generation**: Creates detailed scan report
5. **Email Delivery**: Sends report to administrator

### Threat Types Detected & Prevented

- **Processes**: PowerShell attacks, reverse shells, exploit tools
- **Files**: Executables, scripts, and text files with suspicious names
- **Memory**: Injected payloads, shellcode, high-entropy regions
- **Persistence**: Registry autorun, startup files, scheduled tasks
- **Content**: Files containing threat-related keywords
- **Network**: Malicious domains, suspicious DNS queries, network attacks
- **Injection**: DLL injection attempts, unauthorized code injection
- **Phishing**: Suspicious URLs, credential theft attempts, malicious downloads
- **Decoy Attacks**: Attempts to inject code into decoy processes
- **Runtime Threats**: Unauthorized process modifications, memory tampering
- **Credential Theft**: LSASS access, Mimikatz, ProcDump, WDigest manipulation
- **Anomalous behavior**: ML-detected suspicious patterns
- **Network threats**: Malicious IPs, suspicious connections

### Actions Performed

- **Block**: Prevent malicious processes from executing
- **Neutralize**: Replace malicious content with harmless alternatives
- **Quarantine**: Move files to secure quarantine folder
- **Terminate**: Kill suspicious processes
- **Overwrite**: Clean suspicious memory regions
- **Analyze**: Perform deep analysis of files
- **Monitor**: Keep track of suspicious activity
- **Sync**: Share threat intelligence across the mesh network
- **Rollback**: Restore system to previous safe state
- **Isolate**: Block network connections to malicious domains
- **Validate**: Verify process authenticity and digital signatures
- **Alert**: Send real-time notifications of detected threats
- **Score**: ML-based risk assessment and probability scoring
- **Protect**: Advanced credential and LSASS protection
- **Firewall**: Dynamic IP and domain blocking

## 🆕 Enhanced Features

### 📊 Real-time Visual Dashboard

The enhanced UI provides immediate visual feedback on system status:

#### Module Status Indicators

- **🟢 Green Pulse**: Module running normally
- **🟡 Yellow**: Module under stress (repeated restarts)  
- **🔴 Red**: Module failed and couldn't recover
- **🕸️ Blue**: Mesh network connected and syncing
- **🟣 Purple**: Decoy processes active and monitoring
- **🧠 Orange**: ML model training or analyzing
- **🔐 Pink**: Credential protection active
- **🔧 Cyan**: Firewall rules active

#### Real-time Metrics

- **Active Threats**: Current number of detected threats
- **Prevented Attacks**: Total attacks blocked
- **CPU Usage**: Current system CPU utilization
- **Memory Usage**: Current memory consumption
- **Time Since Last Threat**: Duration since last threat detection
- **System Health**: Overall system security health percentage
- **Mesh Endpoints**: Number of connected endpoints in the network
- **Decoy Processes**: Active decoy processes being monitored
- **DNS Blocks**: Number of malicious domains blocked
- **Rollback Points**: Available system restore points
- **ML Risk Score**: Current system risk assessment (0-100%)
- **Blocked IPs**: Number of malicious IPs blocked
- **Credential Alerts**: Number of credential theft attempts detected

### 📦 Portable Deployment

Create a single executable with all modules:

```powershell
# Standard build
.\build_portable.ps1

# With obfuscation for red team operations
.\build_portable.ps1 -Obfuscate

# With code signing
.\build_portable.ps1 -Sign

# With testing
.\build_portable.ps1 -Test
```

### 🧪 Modular Testing

Test individual modules in isolated environments:

```csharp
var tester = new ModuleTestRunner();
tester.RunAllTests(); // Test all modules
tester.RunSpecificTest("VirusHunter"); // Test specific module
tester.VerifyEffectiveness(); // Measure detection accuracy
```

### 📧 Advanced Email Reporting

Professional EDR-style reports with multiple attachments:

- **Executive Summary**: High-level security overview
- **Threat Intelligence**: Detailed threat statistics
- **System Inventory**: Hardware and software information
- **Multiple Attachments**: Logs, JSON data, system information
- **Scheduled Reporting**: 12/24 hour or attack-triggered reports

For complete documentation of all enhanced features, see [ENHANCED_FEATURES_GUIDE.md](ENHANCED_FEATURES_GUIDE.md).

## ⚙️ Configuration

### Prevention Module Settings

#### ProcessWatcher Configuration

```csharp
// Threat patterns in ProcessWatcher.cs
private static readonly Dictionary<string, ThreatPattern> ThreatPatterns = new()
{
    { "powershell.*-enc", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical } },
    { "mshta.*http", new ThreatPattern { Action = "kill", Level = ThreatLevel.High } },
    { "nc\\.exe.*-e", new ThreatPattern { Action = "block", Level = ThreatLevel.Critical } }
};
```

#### SandboxMode Configuration

```csharp
// Watched folders in SandboxMode.cs
private static readonly string[] WatchedFolders = {
    Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
    Environment.GetFolderPath(Environment.SpecialFolder.Downloads),
    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp")
};
```

### Email Settings

To enable real email reporting, modify the email settings in `MainWindow.xaml.cs`:

```csharp
var adminEmail = "your-admin@company.com";
var smtpHost = "smtp.gmail.com";
var port = 587;
var senderEmail = "your-bot@gmail.com";
var senderPassword = "your_app_password";
```

### Scan Paths

Modify scan paths in `MainWindow.xaml.cs`:

```csharp
var scanPaths = new[]
{
    @"C:\YourCustomPath",
    @"C:\Users\Public\Documents",
    Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
};
```

## 🔧 Advanced Features

### Prevention System Architecture

#### Lightweight Design

- **Minimal CPU usage**: < 1% on idle, brief spikes on detection
- **Low memory footprint**: ~20-50 MB target
- **Background operation**: All modules run asynchronously
- **Transparent operation**: Only acts on real threats

#### Behavioral Rules Engine

```json
[
  { "pattern": "powershell -enc", "action": "block", "level": "critical" },
  { "pattern": "mshta http", "action": "kill", "level": "high" },
  { "pattern": "nc.exe -e", "action": "log+block", "level": "critical" }
]
```

#### Attack Surface Coverage

- **PowerShell attacks**: Base64 encoded commands, IEX, Mimikatz
- **Script execution**: MSHTA, WScript, CScript with remote URLs
- **Network tools**: Netcat, Ncat, Telnet reverse shells
- **Registry manipulation**: Regsvr32 remote DLL loading
- **Lateral movement**: PsExec, WMIC, scheduled tasks
- **Memory injection**: Shellcode patterns, high entropy regions
- **Credential theft**: LSASS access, Mimikatz, ProcDump, WDigest manipulation
- **Anomalous behavior**: ML-detected suspicious patterns
- **Network threats**: Malicious IPs, suspicious connections

### Self-Destruction

- **Triggered**: After threats are detected and neutralized
- **Process**: Creates temporary batch file to delete executable
- **Cleanup**: Removes all logs and temporary files
- **Safety**: Requires user confirmation

### Logging System

- **File Logs**: Stored in `%LocalAppData%\PhageVirus\Logs\`
- **Real-time**: Displayed in application UI
- **Archiving**: Automatic log rotation and archiving
- **Reporting**: Comprehensive scan reports

### Threat Simulation

The application creates fake threat files for testing:
- `stealer_v2.exe`
- `keylogger_data.txt`
- `trojan_backdoor.dll`
- `crypto_miner.bat`

## 🛡️ Safety Features

### Red Team Tool

- **Real System Operations**: Uses actual Windows APIs for process manipulation
- **Memory Injection**: Injects real code into processes (harmless neutralization)
- **Self-Replication**: Creates actual copies in system directories
- **Prevention System**: Real-time blocking of malicious activities
- **Educational/Research Purpose**: Designed for Red Team testing and research
- **Requires Elevated Privileges**: Administrator rights required for full functionality

### Error Handling

- **Graceful Failures**: Continues operation even if some operations fail
- **Logging**: All errors are logged for debugging
- **User Feedback**: Clear status messages and error notifications
- **Fallback Options**: Multiple strategies for handling failures

## 🎨 Customization

### UI Styling

Modify `App.xaml` to customize the visual appearance: 
- Change color schemes
- Adjust fonts and sizes
- Modify button styles
- Add custom effects

### Threat Detection

Extend `VirusHunter.cs` to add new detection methods:
- Add new threat keywords
- Implement custom file analysis
- Add network-based detection
- Create behavioral analysis

### Prevention Rules

Enhance prevention modules for different scenarios:
- Add new process patterns to `ProcessWatcher.cs`
- Extend autorun monitoring in `AutorunBlocker.cs`
- Customize memory scanning in `MemoryTrap.cs`
- Modify sandbox rules in `SandboxMode.cs`

### Neutralization

Enhance `PayloadReplacer.cs` for different file types:
- Add support for new file formats
- Implement custom neutralization strategies
- Add encryption/decryption capabilities
- Create advanced analysis tools

## 📊 Performance

### Optimization

- **Async Operations**: Non-blocking UI during scans
- **Efficient Logging**: Minimal impact on system performance
- **Memory Management**: Proper disposal of resources
- **Background Processing**: Heavy operations run in background
- **Lightweight Prevention**: Minimal resource usage for prevention modules

### Resource Usage

- **Memory**: ~50-100 MB during operation
- **CPU**: < 1% on idle, brief spikes during detection
- **Disk**: Log files and temporary data (~1-5 MB)
- **Network**: Only when sending email reports

## 🔍 Troubleshooting

### Common Issues

**Application won't start:**
- Ensure .NET 8.0 is installed
- Check Windows compatibility
- Verify all project files are present
- **Run as Administrator**

**Prevention modules not working:**
- Ensure running as Administrator
- Check Windows Defender exclusions
- Verify WMI service is running
- Review event logs for errors

**Scan finds no threats:**
- Check if fake threat files were created
- Verify scan paths are accessible
- Review log files for errors
- Test prevention modules with known malicious patterns

**Email sending fails:**
- Verify SMTP settings
- Check network connectivity
- Ensure email credentials are correct

**Self-destruct doesn't work:**
- Run as administrator if needed
- Check file permissions
- Review antivirus exclusions

**ML model not working:**
- Ensure ML.NET packages are installed
- Check model file permissions
- Verify training data is accessible
- Review model initialization logs

**Firewall rules not applying:**
- Ensure running as Administrator
- Check Windows Firewall service
- Verify PowerShell execution policy
- Review firewall rule creation logs

### Log Files

Logs are stored in: `%LocalAppData%\PhageVirus\Logs\`
- Daily log files: `phage_YYYYMMDD.log`
- Archive folder for old logs
- Temporary logs in system temp directory
- Prevention module logs with detailed activity

## 🚨 Disclaimer

**This is a powerful Red Team tool for educational and research purposes only.**

- **REAL SYSTEM OPERATIONS**: Uses actual Windows APIs for process manipulation
- **MEMORY INJECTION**: Injects real code into processes (harmless neutralization)
- **SELF-REPLICATION**: Creates actual copies in system directories
- **PREVENTION SYSTEM**: Blocks real processes and files
- **REQUIRES ADMINISTRATOR PRIVILEGES**: Must run as administrator
- **NEVER USE ON PRODUCTION SYSTEMS** without explicit permission
- **Use only in controlled environments** (VM, sandbox, test lab)
- **Not intended as a replacement for real antivirus software**
- **Use at your own risk in educational/research environments**

## 📝 License

This project is provided as-is for educational and demonstration purposes. Feel free to modify and extend the code for learning purposes.

## 🤝 Contributing

To contribute to this project:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📞 Support

For questions or issues:
- Check the troubleshooting section
- Review log files for error details
- Ensure all prerequisites are met
- Verify Windows compatibility
- Ensure running as Administrator

---

**PhageVirus** - Advanced Threat Neutralization & Prevention System
*Built with .NET 8 WPF for Windows*
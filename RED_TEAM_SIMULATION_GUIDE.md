# PhageVirus Red Team Simulation Guide

## 🔴 Advanced Attack Simulation Engine

PhageVirus now includes a comprehensive Red Team simulation engine that can test your security controls against advanced attack techniques used by real adversaries. All simulations are **safe, sandboxed, and harmless** - designed to test detection and prevention without causing any real damage.

## 🛡️ Safety Features

- **Sandboxed Environment**: All simulations run in isolated directories
- **Fake Payloads**: No real malware or harmful code is executed
- **Automatic Cleanup**: All test files and registry entries are removed
- **VM Detection**: Simulations are automatically disabled in production environments
- **Logging**: All activities are logged for audit purposes

## 🎯 Attack Categories

### 1. 🔐 Credential Access
**Simulates**: LSASS access, Mimikatz-style credential dumping
**Protection Tested**: CredentialTrap, ProcessWatcher, MemoryTrap
**Real-World Equivalent**: Attackers stealing admin credentials

### 2. 🧬 Process Exploitation
**Simulates**: Process hollowing, code injection, DLL loading
**Protection Tested**: ExploitShield, MemoryTrap, ZeroTrustRuntime
**Real-World Equivalent**: Malware hiding in legitimate processes

### 3. 🔄 Lateral Movement
**Simulates**: WMI queries, remote process execution, network pivoting
**Protection Tested**: ProcessWatcher, FirewallGuard, DnsSinkhole
**Real-World Equivalent**: Attackers moving between systems

### 4. 📌 Persistence
**Simulates**: Registry modifications, scheduled tasks, startup entries
**Protection Tested**: AutorunBlocker, ProcessWatcher, RollbackEngine
**Real-World Equivalent**: Malware surviving system reboots

### 5. 💣 Malware Protection
**Simulates**: Ransomware behavior, file encryption, data exfiltration
**Protection Tested**: SandboxMode, PayloadReplacer, VirusHunter
**Real-World Equivalent**: Ransomware and data theft attacks

### 6. 🛠️ Living-off-the-Land (LOLBin)
**Simulates**: Abuse of legitimate Windows tools (PowerShell, certutil, mshta)
**Protection Tested**: ProcessWatcher, BehaviorTest, AnomalyScoreClassifier
**Real-World Equivalent**: Attackers using built-in tools to avoid detection

### 7. 🧠 In-Memory/Fileless
**Simulates**: Memory-resident payloads, reflective DLL loading
**Protection Tested**: MemoryTrap, ExploitShield, ZeroTrustRuntime
**Real-World Equivalent**: Malware that never touches disk

### 8. 🎫 Token Hijacking
**Simulates**: Session token theft, user impersonation
**Protection Tested**: CredentialTrap, ProcessWatcher, AnomalyScoreClassifier
**Real-World Equivalent**: Stealing browser sessions and tokens

### 9. 📦 Supply Chain
**Simulates**: Malicious package installation, compromised dependencies
**Protection Tested**: SandboxMode, PayloadReplacer, VirusHunter
**Real-World Equivalent**: SolarWinds-style supply chain attacks

### 10. ☁️ Cloud Attacks
**Simulates**: Cloud API abuse, IAM privilege escalation
**Protection Tested**: FirewallGuard, AnomalyScoreClassifier
**Real-World Equivalent**: Cloud infrastructure attacks

### 11. 🌐 SSRF Attacks
**Simulates**: Server-side request forgery, internal resource access
**Protection Tested**: FirewallGuard, DnsSinkhole, AnomalyScoreClassifier
**Real-World Equivalent**: Exploiting web applications to access internal systems

### 12. ⬆️ Privilege Escalation
**Simulates**: User privilege elevation, admin access attempts
**Protection Tested**: CredentialTrap, ProcessWatcher, AnomalyScoreClassifier
**Real-World Equivalent**: Gaining higher privileges on compromised systems

## 🚀 How to Use

### Starting the Red Team Agent

1. **Launch PhageVirus** as Administrator
2. **Navigate** to the "🔴 RED TEAM SIMULATION" tab
3. **Click** "🚀 Start Red Team Agent"
4. **Wait** for initialization to complete

### Running Individual Simulations

1. **Select** an attack type from the available buttons
2. **Click** the attack button (e.g., "🔐 Credential Dump")
3. **Monitor** the results in real-time
4. **Review** protection logs to see how your security responded

### Running Full Attack Chain

1. **Click** "⚡ Full Attack Chain" for a comprehensive test
2. **Monitor** the multi-step attack simulation
3. **Review** results across all attack categories
4. **Analyze** security score improvements needed

## 📊 Understanding Results

### Attack Results Grid

- **Timestamp**: When the attack step was executed
- **Attack Type**: Category of attack (e.g., "Credential Dump")
- **Step**: Specific action performed
- **Result**: Success/Failure of the attack
- **Blocked**: Whether security controls prevented the attack
- **Detected**: Whether security controls detected the attack

### Security Score

- **Overall Score**: Average protection across all categories
- **Individual Scores**: Protection level for each attack category
- **Color Coding**: 
  - 🟢 Green (90-100%): Excellent protection
  - 🟡 Orange (70-89%): Good protection
  - 🟠 Yellow (50-69%): Fair protection
  - 🔴 Red (0-49%): Poor protection

### Protection Logs

Shows detailed information about how your security modules responded:

- **✅ PROTECTION**: Attack was successfully blocked
- **⚠️ DETECTION**: Attack was detected but not blocked
- **❌ GAP**: Attack was not detected or blocked

## 🔧 Advanced Configuration

### Custom Attack Playbooks

You can create custom attack scenarios by modifying the playbook creation methods in `MainWindow.xaml.cs`:

```csharp
private RedTeamAgent.AttackPlaybook CreateCustomPlaybook()
{
    return new RedTeamAgent.AttackPlaybook
    {
        Id = "custom_attack",
        Name = "Custom Attack Simulation",
        Description = "Your custom attack scenario",
        Steps = new List<RedTeamAgent.AttackStep>
        {
            new RedTeamAgent.AttackStep 
            { 
                Name = "Custom Step", 
                Action = "simulate_custom_action", 
                DelayMs = 2000 
            }
        },
        AutoCleanup = true,
        TimeoutSeconds = 60
    };
}
```

### Adding New Attack Types

To add new attack simulation types:

1. **Add** the simulation method to `RedTeamAgent.cs`
2. **Add** the case in `ExecuteAttackStepAsync`
3. **Create** the fake payload method
4. **Add** the UI button and event handler
5. **Create** the playbook method

## 📈 Security Score Interpretation

### 90-100% (Excellent)
- Your security controls are effectively blocking most attacks
- Consider fine-tuning to reduce false positives
- Focus on advanced threat hunting

### 70-89% (Good)
- Good baseline protection with room for improvement
- Review gaps in specific attack categories
- Consider additional security tools

### 50-69% (Fair)
- Significant security gaps exist
- Prioritize critical attack vectors
- Consider implementing additional controls

### 0-49% (Poor)
- Major security vulnerabilities
- Immediate action required
- Consider professional security assessment

## 🛡️ Protection Module Integration

The Red Team simulation engine integrates with all PhageVirus protection modules:

### Real-Time Protection
- **ProcessWatcher**: Monitors for suspicious process creation
- **MemoryTrap**: Detects memory injection attempts
- **CredentialTrap**: Blocks LSASS access and credential theft
- **ExploitShield**: Prevents code injection and exploitation
- **AutorunBlocker**: Blocks persistence mechanisms
- **SandboxMode**: Quarantines suspicious files
- **FirewallGuard**: Blocks malicious network connections
- **DnsSinkhole**: Blocks malicious domains
- **AnomalyScoreClassifier**: ML-based behavior analysis

### Response Actions
- **Block**: Prevent attack execution
- **Detect**: Log attack attempts
- **Alert**: Notify administrators
- **Quarantine**: Isolate suspicious files
- **Rollback**: Restore system state

## 📋 Best Practices

### Before Running Simulations
1. **Backup** important data
2. **Test** in a controlled environment first
3. **Review** security policies
4. **Ensure** all protection modules are active

### During Simulations
1. **Monitor** real-time logs
2. **Document** any gaps found
3. **Note** false positives
4. **Track** response times

### After Simulations
1. **Review** comprehensive results
2. **Export** detailed reports
3. **Address** identified gaps
4. **Update** security policies
5. **Retest** after improvements

## 🚨 Troubleshooting

### Common Issues

**Simulation fails to start:**
- Ensure running as Administrator
- Check if Red Team Agent is initialized
- Review error logs for details

**No attacks detected:**
- Verify protection modules are active
- Check module status indicators
- Review protection logs

**False positives:**
- Adjust detection thresholds
- Whitelist legitimate activities
- Fine-tune ML models

**Performance issues:**
- Reduce simulation frequency
- Optimize protection modules
- Monitor system resources

## 📞 Support

For questions or issues with Red Team simulations:

1. **Check** the troubleshooting section
2. **Review** protection module logs
3. **Export** simulation results for analysis
4. **Contact** security team for assistance

---

**Remember**: Red Team simulations are powerful tools for testing security controls. Use them responsibly and always in controlled environments. The goal is to improve security, not to cause harm.

**PhageVirus Red Team Simulation Engine** - Advanced Security Testing Made Safe 
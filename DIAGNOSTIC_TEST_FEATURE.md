# PhageVirus Diagnostic Test Feature

## Overview

The Diagnostic Test feature is a comprehensive system health assessment tool that performs deep analysis of your endpoint system, PhageVirus runtime status, and potential security issues. It generates detailed reports and can optionally send them via email for remote analysis.

## Features

### 🔍 Comprehensive System Analysis
- **System Health Check**: Basic system information, hardware details, disk health
- **PhageVirus Runtime Check**: Process status, module health, memory usage
- **Windows Event Log Analysis**: Recent system and application events
- **Network Status Check**: Interface status, connectivity tests, active connections
- **WMI Health Check**: Windows Management Instrumentation connectivity and performance
- **Exception Analysis**: Recent errors and exception tracking
- **Security Assessment**: User privileges, Windows Defender status, firewall status
- **Performance Analysis**: CPU, memory, and disk usage metrics
- **Registry Health Check**: Critical registry key accessibility
- **Service Status Check**: Critical Windows services status

### 📊 Detailed Reporting
- **Timestamped Reports**: All reports include precise timestamps
- **Desktop Export**: Reports automatically saved to desktop
- **Email Integration**: Optional email sending with validation
- **Multiple Formats**: Both detailed log and summary report formats

### 🛡️ Security Features
- **Privilege Detection**: Identifies elevated permissions
- **Antivirus Status**: Checks Windows Defender and other AV products
- **Firewall Status**: Verifies firewall configuration
- **Network Security**: Analyzes network interface security

## Usage

### Running the Diagnostic Test

1. **Launch PhageVirus**: Start the PhageVirus application
2. **Click Diagnostic Test**: Press the "🔍 Diagnostic Test" button
3. **Email Options**: Choose whether to send report via email
4. **Wait for Completion**: The test runs comprehensive checks
5. **Review Results**: Check the generated reports on desktop

### Email Configuration

When you choose to send the diagnostic report via email:

- **Email Validation**: Automatic email format validation
- **SMTP Integration**: Uses existing EmailReporter module
- **Secure Transmission**: Reports sent via configured SMTP
- **Delivery Confirmation**: Success/failure logging

## Technical Details

### Report Structure

```
=== PHAGEVIRUS COMPREHENSIVE DIAGNOSTIC REPORT ===
Generated: 2024-01-15 14:30:25.123
Diagnostic Version: 1.0
PhageVirus Version: 2.0

=== SYSTEM HEALTH CHECK ===
--- Basic System Information ---
Machine Name: DESKTOP-ABC123
User Name: Administrator
OS Version: Microsoft Windows NT 10.0.19045.0
Processor Count: 8
Working Set: 2048 MB
...

=== PHAGEVIRUS RUNTIME CHECK ===
--- Process Information ---
Process ID: 1234
Process Name: PhageVirus
Working Set: 156 MB
Thread Count: 12
...

=== WINDOWS EVENT LOG ANALYSIS ===
--- Recent System Events ---
Found 15 recent system events:
  [14:25:30] Information: Service Control Manager - Service started
  [14:20:15] Warning: Disk - Low disk space detected
...

=== NETWORK STATUS CHECK ===
--- Network Interfaces ---
Interface: Ethernet
  Type: Ethernet
  Status: Up
  Speed: 1000 Mbps
  IPv4: 192.168.1.100
...

=== WMI HEALTH CHECK ===
--- WMI Connectivity Test ---
WMI connection: SUCCESS

--- WMI Provider Status ---
  Win32_ComputerSystem: 1 instances found
  Win32_OperatingSystem: 1 instances found
...

=== EXCEPTION ANALYSIS ===
--- Recent Exceptions ---
Found 3 recent exceptions/errors:
  [14:15:22] Error: Application Error - Exception in module
...

=== SECURITY ASSESSMENT ===
--- User Privileges ---
Current User: Administrator
Elevated: True

--- Windows Defender Status ---
Antivirus: Windows Defender
  State: 262144
  Up to date: True
...

=== PERFORMANCE ANALYSIS ===
--- CPU Performance ---
CPU Usage: 45.2%

--- Memory Performance ---
Memory Usage: 67.8%
Total Physical Memory: 16384 MB
...

=== REGISTRY HEALTH CHECK ===
--- Critical Registry Keys ---
  HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run: 8 values (OK)
  HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run: 3 values (OK)
...

=== SERVICE STATUS CHECK ===
--- Critical Services ---
  WinDefend: Running
  MpsSvc: Running
  BITS: Running
...

=== DIAGNOSTIC SUMMARY ===
--- Overall System Health ---
✅ System information collected successfully
✅ PhageVirus runtime status verified
✅ Windows event logs analyzed
✅ Network connectivity tested
✅ WMI health verified
✅ Exception analysis completed
✅ Security assessment performed
✅ Performance metrics collected
✅ Registry health checked
✅ Service status verified

--- Recommendations ---
1. Review any errors or warnings in the detailed sections above
2. Check disk space if low space warnings were detected
3. Verify network connectivity if connection issues were found
4. Monitor system performance if high usage was detected
5. Review Windows event logs for any critical errors
6. Ensure Windows Defender and firewall are properly configured

--- Report Information ---
Report generated by: PhageVirus Diagnostic Tool v1.0
Report saved to: C:\Users\Username\Desktop\PhageVirus_Diagnostic_Report_20240115_143025.txt
Log file saved to: C:\Users\Username\Desktop\PhageVirus_Diagnostic_20240115_143025.log
Total diagnostic time: 2024-01-15 14:30:25.456
```

### File Outputs

The diagnostic test generates two files on the desktop:

1. **PhageVirus_Diagnostic_Report_YYYYMMDD_HHMMSS.txt**
   - Human-readable detailed report
   - Formatted for easy reading
   - Contains all diagnostic sections

2. **PhageVirus_Diagnostic_YYYYMMDD_HHMMSS.log**
   - Machine-readable log format
   - Compatible with log analysis tools
   - Same content as report file

### Performance Impact

- **Test Duration**: Typically 5-10 seconds
- **CPU Usage**: Minimal during test execution
- **Memory Usage**: < 50MB additional memory
- **Disk I/O**: Light read operations for system information
- **Network**: Only if email sending is enabled

## Integration

### With Existing Modules

The Diagnostic Test integrates seamlessly with existing PhageVirus modules:

- **EnhancedLogger**: All diagnostic activities are logged
- **EmailReporter**: Email functionality for report delivery
- **BehaviorTest**: Complementary to behavior analysis
- **ProcessWatcher**: Monitors diagnostic process execution

### API Usage

```csharp
// Run diagnostic test without email
var success = await DiagnosticTest.RunDiagnosticTest(false, "");

// Run diagnostic test with email
var success = await DiagnosticTest.RunDiagnosticTest(true, "admin@company.com");
```

## Security Considerations

### Data Privacy
- **Local Storage**: Reports saved locally on desktop
- **Email Security**: Uses configured SMTP with authentication
- **No Cloud Upload**: No automatic cloud storage
- **User Control**: User chooses what to send via email

### Access Requirements
- **Standard User**: Most checks work with standard privileges
- **Admin Rights**: Some checks require elevated privileges
- **WMI Access**: Requires WMI permissions
- **Event Log Access**: Requires event log read permissions

## Troubleshooting

### Common Issues

1. **WMI Access Denied**
   - Run as administrator
   - Check Windows Management Instrumentation service
   - Verify WMI permissions

2. **Event Log Access Failed**
   - Ensure event log service is running
   - Check user permissions
   - Verify registry access

3. **Email Sending Failed**
   - Check SMTP configuration
   - Verify email address format
   - Ensure network connectivity

4. **Performance Counters Unavailable**
   - Run as administrator
   - Check Performance Counter service
   - Verify counter permissions

### Error Recovery

- **Partial Failures**: Test continues even if some checks fail
- **Detailed Logging**: All errors are logged with context
- **Graceful Degradation**: Unavailable checks are skipped
- **User Feedback**: Clear error messages in UI

## Future Enhancements

### Planned Features
- **Real-time Monitoring**: Continuous system health monitoring
- **Trend Analysis**: Historical performance tracking
- **Custom Checks**: User-defined diagnostic checks
- **Remote Analysis**: Cloud-based report analysis
- **Integration APIs**: Third-party tool integration

### Advanced Capabilities
- **Machine Learning**: Anomaly detection in system behavior
- **Predictive Analysis**: System health forecasting
- **Automated Remediation**: Automatic issue resolution
- **Compliance Reporting**: Security compliance validation

## Support

For issues with the Diagnostic Test feature:

1. **Check Logs**: Review PhageVirus logs for error details
2. **Verify Permissions**: Ensure proper user privileges
3. **Test Components**: Run individual diagnostic sections
4. **Contact Support**: Use diagnostic report for troubleshooting

The Diagnostic Test feature provides comprehensive system analysis capabilities, making it an essential tool for maintaining and troubleshooting PhageVirus deployments. 
# 🦠 PhageVirus EDR System - Industry Standard Testing Framework

## 📋 **Overview**

This testing framework implements **industry-standard testing practices** used by leading cybersecurity companies like **CrowdStrike**, **SentinelOne**, and **Microsoft Defender**. It provides comprehensive testing for the PhageVirus EDR system with detailed reporting and analysis.

## 🎯 **Testing Categories**

### **1. Unit Testing** 🔧
- **Purpose**: Test individual methods/functions in isolation
- **Coverage**: Core logic, edge cases, exceptions
- **Tools**: Custom test framework with xUnit-style assertions
- **Modules Tested**: All 13 new modules + core infrastructure

### **2. Integration Testing** 🔗
- **Purpose**: Validate interactions between modules and shared services
- **Coverage**: Module communication, telemetry flow, cloud integration
- **Scenarios**: UnifiedModuleManager coordination, CloudIntegration telemetry
- **Validation**: End-to-end data flow verification

### **3. Functional Testing** ⚙️
- **Purpose**: End-to-end feature flow simulation
- **Scenarios**: 
  - File encryption → RansomwareProtection detects → isolates device
  - IAM role created with wildcard permission → IAMMisconfigDetector flags → sends telemetry
  - MFA login from 2 countries → MFAAnomalyDetector raises alert
- **Validation**: Complete workflow verification

### **4. Performance Testing** 📈
- **Purpose**: Resource usage, scalability, and stress testing
- **Metrics**: Memory usage, CPU usage, response times
- **Tests**: Baseline, normal load, high load, stress testing
- **Thresholds**: Memory < 500MB, CPU < 80%

### **5. Security Testing** 🔒
- **Purpose**: Vulnerability assessment and security validation
- **Types**: Static analysis, dependency scanning, secure serialization
- **Coverage**: SQL injection, XSS, command injection, buffer overflow
- **Validation**: Industry security standards compliance

### **6. Regression Testing** 🔄
- **Purpose**: Ensure new updates don't break existing features
- **Method**: Automated test suite re-execution
- **Coverage**: All functional tests on every code change
- **Validation**: Feature stability verification

### **7. Manual QA Testing** 👤
- **Purpose**: Simulated manual testing scenarios
- **Coverage**: GUI testing, real-world attack simulation
- **Validation**: User experience and attack response verification

## 🚀 **Quick Start**

### **Prerequisites**
- .NET 8.0 SDK
- Windows 10/11
- PowerShell 7+ (for script execution)

### **Running Tests**

#### **Option 1: PowerShell Script (Recommended)**
```powershell
# Navigate to testing framework directory
cd Phagecloud/Modules/TestingFramework

# Run all automated tests
.\run-tests.ps1 -All

# Run specific test categories
.\run-tests.ps1 -Unit -Integration

# Run performance tests with custom parameters
.\run-tests.ps1 -Performance -Duration 60 -Memory 400 -Cpu 70

# Show help
.\run-tests.ps1 -Help
```

#### **Option 2: Direct .NET Execution**
```bash
# Navigate to testing framework directory
cd Phagecloud/Modules/TestingFramework

# Build the project
dotnet build -c Release

# Run all tests
dotnet run -c Release -- --all

# Run specific test categories
dotnet run -c Release -- --unit --integration --functional

# Run with custom performance parameters
dotnet run -c Release -- --performance --duration 60 --iterations 2000
```

## 📊 **Test Results and Reporting**

### **Console Output**
The framework provides real-time console output with:
- ✅ **Pass indicators** for successful tests
- ❌ **Fail indicators** for failed tests
- 📊 **Performance metrics** and statistics
- 🔒 **Security findings** and recommendations
- 💡 **Actionable recommendations** for improvements

### **Detailed Report File**
A comprehensive report is automatically saved to your desktop:
- **Filename**: `phagevirus_test_results_YYYYMMDD_HHMMSS.txt`
- **Location**: Desktop folder
- **Content**: Complete test results, performance metrics, security findings

### **Report Sections**
1. **Executive Summary**: Overall test results and success rate
2. **Test Configuration**: Which test categories were executed
3. **Detailed Results**: Individual test results by category
4. **Performance Metrics**: Resource usage and performance data
5. **Security Findings**: Vulnerability assessment results
6. **Recommendations**: Actionable improvement suggestions

## 🔧 **Configuration Options**

### **Test Selection**
```powershell
# Run all automated tests
.\run-tests.ps1 -All

# Run specific test categories
.\run-tests.ps1 -Unit -Integration -Functional

# Run only security tests
.\run-tests.ps1 -Security

# Run only performance tests
.\run-tests.ps1 -Performance
```

### **Performance Parameters**
```powershell
# Custom performance test duration (seconds)
.\run-tests.ps1 -Performance -Duration 60

# Custom stress test iterations
.\run-tests.ps1 -Performance -Iterations 2000

# Custom memory threshold (MB)
.\run-tests.ps1 -Performance -Memory 400

# Custom CPU threshold (percent)
.\run-tests.ps1 -Performance -Cpu 70
```

## 📈 **Performance Benchmarks**

### **Expected Results**
| Test Category | Success Rate | Duration | Memory Usage | CPU Usage |
|---------------|-------------|----------|--------------|-----------|
| Unit Tests | >95% | <30s | <50MB | <5% |
| Integration Tests | >90% | <60s | <100MB | <10% |
| Functional Tests | >85% | <120s | <150MB | <15% |
| Performance Tests | >80% | <300s | <500MB | <50% |
| Security Tests | >95% | <180s | <100MB | <10% |
| Regression Tests | >90% | <240s | <200MB | <20% |

### **Thresholds**
- **Memory Usage**: < 500MB under high load
- **CPU Usage**: < 80% under stress testing
- **Response Time**: < 1 second for most operations
- **Success Rate**: > 95% for production readiness

## 🔒 **Security Testing Details**

### **Static Analysis**
- **SQL Injection**: Pattern matching for vulnerable queries
- **XSS Vulnerabilities**: Cross-site scripting detection
- **Command Injection**: Shell command injection prevention
- **Buffer Overflow**: Memory boundary checking

### **Dependency Scanning**
- **NuGet Vulnerabilities**: Known vulnerability detection
- **Outdated Packages**: Security update requirements
- **License Compliance**: Open source license validation
- **SBOM Generation**: Software bill of materials

### **Secure Serialization**
- **JSON Security**: Safe JSON handling
- **XML Security**: XXE attack prevention
- **Binary Security**: Safe binary serialization
- **Deserialization**: Attack prevention mechanisms

## 📋 **Test Coverage**

### **Module Coverage**
- ✅ **RansomwareProtection**: File monitoring, entropy analysis
- ✅ **DeviceIsolation**: Network isolation, firewall rules
- ✅ **IAMMisconfigDetector**: IAM analysis, risk scoring
- ✅ **ServerlessContainerMonitor**: Container security, workload analysis
- ✅ **IaCScanner**: Infrastructure scanning, misconfiguration detection
- ✅ **CloudMetricsCollector**: Metrics collection, dashboard generation
- ✅ **ADMonitor**: Active Directory monitoring, threat detection
- ✅ **MFAAnomalyDetector**: MFA analysis, anomaly detection
- ✅ **TokenTheftDetector**: Token monitoring, theft detection
- ✅ **ITDR**: Identity threat detection, automated response
- ✅ **CSPMScanner**: Cloud posture management
- ✅ **CWPPMonitor**: Cloud workload protection
- ✅ **CloudAPIThreatDetector**: API threat detection

### **Infrastructure Coverage**
- ✅ **UnifiedModuleManager**: Module coordination, lifecycle management
- ✅ **CloudIntegration**: Telemetry processing, cloud communication
- ✅ **EnhancedLogger**: Logging system, performance monitoring
- ✅ **UnifiedConfig**: Configuration management, environment settings

## 🚨 **Troubleshooting**

### **Common Issues**

#### **Build Failures**
```powershell
# Clean and rebuild
dotnet clean
dotnet build -c Release
```

#### **Test Failures**
```powershell
# Run with verbose output
dotnet run -c Release -- --unit --verbose

# Check specific test category
dotnet run -c Release -- --unit
```

#### **Performance Issues**
```powershell
# Reduce test load
.\run-tests.ps1 -Performance -Duration 30 -Iterations 500

# Check system resources
Get-Process | Where-Object {$_.ProcessName -like "*dotnet*"}
```

### **Error Messages**

#### **"NET 8 is required but not found"**
```powershell
# Install .NET 8 SDK from Microsoft
# https://dotnet.microsoft.com/download/dotnet/8.0
```

#### **"Build failed"**
```powershell
# Check for missing dependencies
dotnet restore
dotnet build -c Release
```

#### **"Tests failed"**
```powershell
# Review detailed report for specific failures
# Check console output for error details
```

## 📚 **Advanced Usage**

### **CI/CD Integration**
```yaml
# GitHub Actions example
- name: Run PhageVirus Tests
  run: |
    cd Phagecloud/Modules/TestingFramework
    .\run-tests.ps1 -All
```

### **Custom Test Development**
```csharp
// Add custom test to UnitTestSuite.cs
public async Task TestCustomModuleAsync()
{
    var testStopwatch = Stopwatch.StartNew();
    
    try
    {
        // Your custom test logic here
        var result = await YourCustomTest();
        
        _testResults.Add(new TestResult
        {
            TestName = "Custom.TestName",
            Passed = result.Success,
            Duration = testStopwatch.Elapsed,
            Details = $"Custom test result: {result.Details}"
        });
    }
    catch (Exception ex)
    {
        _testResults.Add(new TestResult
        {
            TestName = "Custom.TestName",
            Passed = false,
            Duration = testStopwatch.Elapsed,
            ErrorMessage = ex.Message
        });
    }
}
```

### **Performance Monitoring**
```powershell
# Monitor test execution
Get-Process | Where-Object {$_.ProcessName -like "*dotnet*"} | Select-Object ProcessName, CPU, WorkingSet

# Check memory usage during tests
Get-Counter "\Process(dotnet)\Working Set" -SampleInterval 5 -MaxSamples 10
```

## 🎯 **Best Practices**

### **Test Execution**
1. **Run tests regularly**: Execute full test suite before deployments
2. **Monitor performance**: Track resource usage trends over time
3. **Review security findings**: Address vulnerabilities promptly
4. **Update dependencies**: Keep packages updated for security

### **Development Workflow**
1. **Unit tests first**: Write unit tests for new features
2. **Integration testing**: Verify module interactions
3. **Performance validation**: Ensure acceptable resource usage
4. **Security review**: Validate security measures

### **Production Deployment**
1. **Full test suite**: Run all tests before production
2. **Performance baseline**: Establish performance benchmarks
3. **Security validation**: Ensure no critical vulnerabilities
4. **Regression verification**: Confirm no breaking changes

## 📞 **Support**

### **Documentation**
- **Framework Guide**: This README
- **Module Documentation**: Individual module READMEs
- **API Documentation**: Inline code documentation

### **Issues and Questions**
- **Test Failures**: Review detailed reports and console output
- **Performance Issues**: Check system resources and thresholds
- **Security Concerns**: Address findings in security test results

### **Contributing**
1. **Follow patterns**: Use existing test structure
2. **Add documentation**: Document new tests and features
3. **Maintain coverage**: Ensure comprehensive test coverage
4. **Performance awareness**: Consider resource usage in tests

---

**PhageVirus Testing Framework** - Industry Standard Cybersecurity Testing
*Built with .NET 8 and following CrowdStrike, SentinelOne, and Microsoft Defender practices*

**Version**: 1.0.0
**Last Updated**: January 2025
**Status**: ✅ Production Ready 
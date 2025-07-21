# 🌐 Cloud Telemetry Display Guide

## 📋 Overview

The **Cloud Telemetry Display** feature allows you to see real-time cloud metrics and telemetry data directly in your PhageVirus desktop application. This includes:

- **Cloud CPU and Memory Usage** from AWS Lambda
- **Local vs Cloud Performance** comparison
- **Threat Detection Metrics** from cloud analysis
- **Lambda Function Status** and performance
- **S3 and DynamoDB Usage** statistics
- **Real-time Threat Alerts** from cloud processing

## 🚀 Quick Start

### 1. Deploy Updated Lambda Function

First, deploy the updated Lambda function with metrics support:

```powershell
# Navigate to Lambda directory
cd phagevirus-cloud-implementation/phagevirus-lambda

# Deploy with metrics support
.\deploy-with-metrics.ps1
```

### 2. Update Desktop Application

The desktop application now includes the `CloudTelemetryDisplay` module. When you start PhageVirus, it will automatically:

- Initialize cloud telemetry display
- Connect to your AWS Lambda function
- Start fetching metrics every 30 seconds
- Display cloud data in the log window

### 3. View Cloud Metrics

Once running, you'll see cloud metrics in the log window like this:

```
[CLOUD METRICS] Local CPU: 15.2% | Local RAM: 45.8% | Cloud CPU: 12.1% | Cloud RAM: 38.5% | Threats: 3 | Risk Score: 65.5% | Lambda Status: Active
[METRICS] Local CPU: 15.2%, Cloud CPU: 12.1%, Health: 34.5%
[CLOUD ALERT] Threats: 3, Risk: 65.5%
```

## 📊 What You'll See

### Real-Time Metrics Display

The application shows comprehensive metrics including:

#### **Performance Metrics**
- **Local CPU Usage**: Your VM's current CPU usage
- **Local RAM Usage**: Your VM's current memory usage  
- **Cloud CPU Usage**: AWS Lambda function CPU usage
- **Cloud RAM Usage**: AWS Lambda function memory usage
- **System Health**: Overall security health percentage

#### **Threat Metrics**
- **Threats Detected**: Number of threats found by cloud analysis
- **Threats Blocked**: Number of threats successfully blocked
- **Risk Score**: Current system risk assessment (0-100%)
- **Severity Level**: Highest threat severity detected

#### **Cloud Service Metrics**
- **Lambda Status**: Function health and status
- **Lambda Invocations**: Number of function calls
- **Lambda Duration**: Average execution time
- **S3 Storage Used**: Amount of data stored in S3
- **DynamoDB Records**: Number of telemetry records processed

### Threat Timeline Integration

Cloud-detected threats automatically appear in the threat timeline:

```
[CLOUD THREAT] High: Suspicious Process - powershell.exe
[CLOUD THREAT] Critical: Memory Injection - explorer.exe
```

## 🔧 Configuration

### Lambda Function URL

The application connects to your Lambda function using this URL:
```
https://phagevirus-telemetry-processor.lambda-url.ap-southeast-2.on.aws/
```

And your API Gateway using this URL:
```
https://9tjtwblsg3.execute-api.ap-southeast-2.amazonaws.com/
```

### Configuration File

The configuration is stored in:
```
%LocalAppData%\PhageVirus\config\cloud-display-config.json
```

Example configuration:
```json
{
  "LambdaFunctionUrl": "https://phagevirus-telemetry-processor.lambda-url.ap-southeast-2.on.aws/",
  "ApiGatewayUrl": "https://9tjtwblsg3.execute-api.ap-southeast-2.amazonaws.com/",
  "EndpointId": "endpoint-YOUR-COMPUTER-NAME-YOUR-USERNAME-PROCESSID",
  "RefreshIntervalSeconds": 30,
  "EnableRealTimeUpdates": true,
  "ShowDetailedMetrics": true,
  "MaxHistoryItems": 100
}
```

## 🧪 Testing

### Test Cloud Telemetry Display

Run the test script to verify everything is working:

```powershell
# Test the cloud telemetry display
.\test-cloud-telemetry.ps1
```

### Test Lambda Metrics Endpoint

Test the Lambda function's metrics endpoint directly:

```powershell
# Navigate to Lambda directory
cd phagevirus-cloud-implementation/phagevirus-lambda

# Test metrics endpoint
$testPayload = @{
    agentId = "test-endpoint-001"
    timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    dataType = "Metrics"
    data = @{
        requestType = "get_metrics"
        includePerformance = $true
        includeThreats = $true
    }
} | ConvertTo-Json -Depth 3

$testPayload | Out-File -FilePath "test-metrics.json" -Encoding UTF8

aws lambda invoke `
    --function-name phagevirus-telemetry-processor `
    --payload file://test-metrics.json `
    --region ap-southeast-2 `
    response-metrics.json

Get-Content response-metrics.json | ConvertFrom-Json
```

## 📈 Understanding the Metrics

### Performance Comparison

| Metric | Local (VM) | Cloud (AWS) | What it means |
|--------|------------|-------------|---------------|
| **CPU Usage** | 15.2% | 12.1% | Your VM is using more CPU than the cloud processing |
| **Memory Usage** | 45.8% | 38.5% | Your VM is using more memory than the cloud processing |
| **System Health** | 34.5% | - | Overall security health (lower = more threats) |

### Threat Analysis

| Metric | Value | Meaning |
|--------|-------|---------|
| **Threats Detected** | 3 | Number of threats found by cloud analysis |
| **Threats Blocked** | 2 | Number of threats successfully neutralized |
| **Risk Score** | 65.5% | Current system risk (0-100%) |
| **Severity** | High | Highest threat severity level |

### Cloud Service Status

| Service | Status | Performance |
|---------|--------|-------------|
| **Lambda Function** | Active | 150ms average duration |
| **S3 Storage** | 2.5MB used | 15 objects stored |
| **DynamoDB** | 25 records | 3 threat records |

## 🔍 Troubleshooting

### Common Issues

#### **"Failed to fetch cloud metrics"**
- Check your internet connection
- Verify Lambda function URL is correct
- Ensure Lambda function is deployed and running

#### **"Lambda function not found"**
- Deploy the Lambda function first using `deploy-with-metrics.ps1`
- Check AWS credentials are configured correctly
- Verify the function name matches your deployment

#### **"No metrics displayed"**
- Check the log window for initialization messages
- Verify the CloudTelemetryDisplay module is initialized
- Check configuration file exists and is valid

#### **"High latency in metrics"**
- The refresh interval is 30 seconds by default
- You can reduce it in the configuration file
- Check your internet connection speed

### Debug Information

Enable detailed logging by setting `ShowDetailedMetrics` to `true` in the configuration:

```json
{
  "ShowDetailedMetrics": true
}
```

This will show additional debug information in the log window.

## 🎯 Use Cases

### **Security Monitoring**
- Monitor real-time threat detection from cloud analysis
- Compare local vs cloud threat detection capabilities
- Track threat trends over time

### **Performance Optimization**
- Compare local vs cloud resource usage
- Identify performance bottlenecks
- Optimize resource allocation

### **System Health Assessment**
- Get comprehensive security health score
- Monitor system risk levels
- Track security posture improvements

### **Cloud Integration Validation**
- Verify AWS services are working correctly
- Monitor Lambda function performance
- Track data storage and processing metrics

## 📱 Integration with Existing Features

### **Threat Timeline**
Cloud-detected threats automatically appear in the threat timeline with `[CLOUD THREAT]` prefix.

### **Log Viewer**
All cloud telemetry data is logged and can be viewed in the enhanced log viewer.

### **Email Reporting**
Cloud metrics are included in diagnostic reports and email alerts.

### **Performance Charts**
Local and cloud performance data is integrated into the performance charts.

## 🔄 Real-Time Updates

The cloud telemetry display updates automatically every 30 seconds. You'll see:

1. **Metrics Summary**: Brief overview of current status
2. **Threat Alerts**: Immediate notifications of new threats
3. **Performance Updates**: Real-time CPU and memory usage
4. **Health Score**: Updated system security health

## 🚨 Alerts and Notifications

### **High-Risk Alerts**
When risk score exceeds 50%:
```
[CLOUD ALERT] Threats: 5, Risk: 75.2%
```

### **Critical Threats**
When critical threats are detected:
```
[CLOUD THREAT] Critical: Memory Injection - explorer.exe
```

### **Performance Warnings**
When cloud services are under stress:
```
[CLOUD WARNING] Lambda duration: 250ms (high)
```

## 📊 Metrics History

The application maintains a history of:
- **Performance data** (last 100 records)
- **Threat detection** patterns
- **System health** trends
- **Cloud service** performance

This data is used for:
- Trend analysis
- Performance optimization
- Security assessment
- Capacity planning

## 🔐 Security Considerations

### **Data Privacy**
- All telemetry data is encrypted in transit
- Sensitive information is not logged
- Endpoint IDs are anonymized

### **Access Control**
- Only authorized endpoints can access metrics
- AWS IAM controls access to cloud services
- Local configuration is protected

### **Audit Trail**
- All cloud interactions are logged
- Access attempts are tracked
- Security events are recorded

## 🎉 Benefits

### **Comprehensive Monitoring**
- See both local and cloud performance
- Real-time threat detection
- System health assessment

### **Performance Optimization**
- Identify resource bottlenecks
- Compare local vs cloud efficiency
- Optimize resource allocation

### **Security Enhancement**
- Cloud-powered threat analysis
- Real-time threat alerts
- Comprehensive security metrics

### **Operational Insights**
- Monitor AWS service performance
- Track data processing metrics
- Validate cloud integration

---

**🎯 Ready to see your cloud telemetry in action!**

Start PhageVirus and watch the cloud metrics appear in your log window. You'll have real-time visibility into both your local VM performance and the cloud processing capabilities. 
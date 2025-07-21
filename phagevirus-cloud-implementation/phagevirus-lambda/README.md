# 🦠 PhageVirus Lambda Function

AWS Lambda function for processing PhageVirus agent telemetry data with advanced threat analysis and data storage.

## 🚀 **Overview**

This Lambda function serves as the central processing hub for all PhageVirus agent telemetry data. It handles:

- **Telemetry Processing**: Receives and processes agent telemetry data
- **Threat Analysis**: Performs real-time threat analysis using ML algorithms
- **Data Storage**: Stores data in S3, DynamoDB, and CloudWatch Logs
- **API Gateway**: Provides REST API endpoints for agent communication
- **Event Processing**: Handles Kinesis streams and SQS queues

## ✅ **Current Status**

**🟢 DEPLOYED AND OPERATIONAL**
- **Function Name**: `phagevirus-telemetry-processor`
- **Runtime**: `dotnet8`
- **Handler**: `PhageVirusLambda::PhageVirus.Lambda.Function::FunctionHandler`
- **Region**: `ap-southeast-2`
- **Account**: `236058984627`
- **Last Updated**: `2025-07-20T04:47:16.000+0000`

## 🏗️ **Architecture**

```
PhageVirus Agents
       ↓
   API Gateway
       ↓
   Lambda Function
       ↓
┌─────────────────┬─────────────────┬─────────────────┐
│      S3         │    DynamoDB     │  CloudWatch     │
│   (Storage)     │   (Database)    │    (Logs)       │
└─────────────────┴─────────────────┴─────────────────┘
```

## 📋 **Features**

### **Multi-Event Support**
- **API Gateway**: REST API endpoints for direct agent communication
- **Kinesis Streams**: Real-time streaming data processing
- **SQS Queues**: Batch processing of telemetry data

### **Advanced Threat Analysis**
- **Risk Scoring**: ML-based risk assessment (0-100%)
- **Pattern Detection**: Identifies suspicious activity patterns
- **Severity Classification**: Categorizes threats (Info, Low, Medium, High, Critical)
- **Recommendations**: Provides actionable security recommendations

### **Data Processing**
- **Process Analysis**: Analyzes process telemetry for suspicious activity
- **Memory Analysis**: Detects high-entropy and suspicious memory regions
- **Network Analysis**: Monitors network connections and traffic patterns
- **System Analysis**: Tracks system performance and resource usage

### **Storage & Logging**
- **S3 Storage**: Long-term telemetry data archival
- **DynamoDB**: Real-time endpoint status and threat data
- **CloudWatch Logs**: Comprehensive logging and monitoring

## 🚀 **Deployment Guide**

### **Prerequisites**
- AWS CLI v2 installed and configured
- .NET 8.0 SDK installed
- PowerShell 7+ (for deployment scripts)
- AWS credentials with Lambda, S3, DynamoDB, and CloudWatch permissions

### **1. AWS CLI Configuration**
```powershell
# Add AWS CLI to PATH (Windows)
$env:PATH += ";C:\Program Files\Amazon\AWSCLIV2"

# Configure AWS credentials
aws configure set aws_access_key_id YOUR_ACCESS_KEY
aws configure set aws_secret_access_key YOUR_SECRET_KEY
aws configure set default.region ap-southeast-2
aws configure set default.output json
```

### **2. Build and Deploy**
```powershell
# Navigate to Lambda directory
cd phagevirus-cloud-implementation/phagevirus-lambda

# Build the project
dotnet build -c Release

# Publish for deployment
dotnet publish -c Release -o ./publish

# Create deployment package
Compress-Archive -Path "./publish/*" -DestinationPath "./PhageVirusLambda.zip" -Force

# Deploy using simple script
.\deploy-simple.ps1
```

### **3. Available Deployment Scripts**

**Simple Deployment** (`deploy-simple.ps1`):
- Updates existing Lambda function
- No IAM role required
- Quick deployment for updates

**Full Deployment** (`deploy-lambda.ps1`):
- Creates new function if needed
- Requires IAM role ARN
- Complete setup with testing

**AWS Configuration** (`configure-aws.ps1`):
- Configures AWS CLI with credentials
- Tests configuration
- Sets up environment

**Lambda Testing** (`test-lambda.ps1`):
- Tests Lambda function with sample payload
- Checks CloudWatch logs
- Validates deployment

### **4. Manual Deployment Commands**
```bash
# Update function code
aws lambda update-function-code \
  --function-name phagevirus-telemetry-processor \
  --zip-file fileb://PhageVirusLambda.zip \
  --region ap-southeast-2

# Update function configuration
aws lambda update-function-configuration \
  --function-name phagevirus-telemetry-processor \
  --runtime dotnet8 \
  --handler "PhageVirusLambda::PhageVirus.Lambda.Function::FunctionHandler" \
  --timeout 30 \
  --memory-size 512 \
  --region ap-southeast-2
```

## 🔧 **Recent Fixes & Improvements**

### **✅ Compilation Issues Resolved**
1. **Missing Using Directive**: Added `using System.Linq;` for extension methods
2. **Query Parameter Access**: Fixed `GetValueOrDefault` with proper dictionary access
3. **CloudWatch Timestamp**: Corrected timestamp format for AWS SDK compatibility
4. **DynamoDB Boolean Handling**: Fixed nullable boolean access in query results
5. **Async Method Warning**: Converted to `Task.FromResult` pattern
6. **System.Text.Json**: Updated to version 8.0.2 for security fixes
7. **PublishReadyToRun**: Set to `false` to avoid runtime optimization errors

### **✅ Deployment Package**
- **Size**: 1.1MB (optimized)
- **Dependencies**: All AWS SDK packages included
- **Runtime**: .NET 8.0 compatible
- **Handler**: Correctly configured

### **✅ AWS Integration**
- **Credentials**: Configured and tested
- **Region**: ap-southeast-2
- **Account**: 236058984627
- **Function**: Successfully deployed and operational

## 🔧 **Configuration**

### **Environment Variables**
The Lambda function uses the following environment variables:

```json
{
  "AWS_REGION": "ap-southeast-2",
  "S3_BUCKET": "phagevirus-logs",
  "DYNAMODB_TABLE": "phagevirus-endpoints",
  "CLOUDWATCH_LOG_GROUP": "/aws/phagevirus/agent"
}
```

### **IAM Permissions**
The Lambda function requires the following permissions:

- **S3**: Read/Write access to telemetry bucket
- **DynamoDB**: Full access to endpoints table
- **CloudWatch Logs**: Create and write to log groups
- **Kinesis**: Read from telemetry streams
- **SQS**: Read from telemetry queues

## 📡 **API Endpoints**

### **POST /telemetry**
Submit telemetry data for processing.

**Request Body:**
```json
{
  "agentId": "endpoint-001",
  "timestamp": "2024-01-15T10:30:00Z",
  "dataType": "Process",
  "data": {
    "processCount": 150,
    "suspiciousProcesses": 2,
    "highCpuProcesses": 5
  },
  "isCompressed": false,
  "isEncrypted": false,
  "checksum": "abc123..."
}
```

**Response:**
```json
{
  "message": "Telemetry processed successfully",
  "analysisId": "uuid-12345"
}
```

### **GET /telemetry?agentId={id}&limit={count}**
Retrieve telemetry history for an agent.

**Response:**
```json
[
  {
    "agentId": "endpoint-001",
    "timestamp": "2024-01-15T10:30:00Z",
    "dataType": "Process",
    "data": { ... },
    "riskScore": 0.75,
    "severity": "High"
  }
]
```

## 🔍 **Threat Analysis**

### **Risk Scoring Algorithm**
The function calculates risk scores based on:

1. **Process Analysis** (0-50% risk):
   - Suspicious process count
   - High CPU usage processes
   - Unusual process patterns

2. **Memory Analysis** (0-50% risk):
   - Suspicious memory regions
   - High entropy regions
   - Memory injection attempts

3. **Network Analysis** (0-50% risk):
   - Suspicious connections
   - Unusual traffic patterns
   - Known malicious IPs

4. **System Analysis** (0-30% risk):
   - High CPU/memory usage
   - System performance anomalies

### **Threat Patterns Detected**
- PowerShell encoded command execution
- High entropy memory regions
- Code injection attempts
- Suspicious network connections
- Unusual process behavior

### **Severity Levels**
- **Info** (0-20%): Normal system activity
- **Low** (20-40%): Minor anomalies
- **Medium** (40-60%): Suspicious activity
- **High** (60-80%): Potential threats
- **Critical** (80-100%): Immediate action required

## 📊 **Data Storage**

### **S3 Storage Structure**
```
phagevirus-logs/
├── telemetry/
│   ├── endpoint-001/
│   │   ├── 2024/01/15/
│   │   │   ├── 103000-uuid1.json
│   │   │   └── 103100-uuid2.json
│   │   └── 2024/01/16/
│   └── endpoint-002/
└── analysis/
    ├── endpoint-001/
    └── endpoint-002/
```

### **DynamoDB Schema**
```json
{
  "AgentId": "endpoint-001",
  "Timestamp": "2024-01-15T10:30:00Z",
  "DataType": "Process",
  "Data": "{...}",
  "IsCompressed": false,
  "IsEncrypted": false,
  "Checksum": "abc123...",
  "ProcessingTimestamp": "2024-01-15T10:30:05Z"
}
```

### **CloudWatch Logs**
- **Log Group**: `/aws/phagevirus/agent`
- **Log Streams**: `{agentId}/{YYYY/MM/DD}`
- **Retention**: 30 days (configurable)

## 🧪 **Testing**

### **Local Testing**
```bash
# Test with sample payload
aws lambda invoke \
  --function-name phagevirus-telemetry-processor \
  --payload file://test-payload.json \
  --region ap-southeast-2 \
  response.json
```

### **Using Test Scripts**
```powershell
# Run comprehensive test
.\test-lambda.ps1

# Test with simple payload
.\deploy-simple.ps1
```

### **API Gateway Testing**
```bash
# Test POST endpoint
curl -X POST https://your-api-id.execute-api.ap-southeast-2.amazonaws.com/prod/telemetry \
  -H "Content-Type: application/json" \
  -d @test-payload.json

# Test GET endpoint
curl "https://your-api-id.execute-api.ap-southeast-2.amazonaws.com/prod/telemetry?agentId=endpoint-001&limit=10"
```

## 📈 **Monitoring**

### **CloudWatch Metrics**
- **Invocation Count**: Number of function invocations
- **Duration**: Function execution time
- **Error Rate**: Percentage of failed invocations
- **Throttles**: Number of throttled invocations

### **Custom Metrics**
- **Telemetry Processed**: Number of telemetry records processed
- **Threats Detected**: Number of threats identified
- **Risk Score Average**: Average risk score across all telemetry
- **Processing Time**: Time to process each telemetry record

### **CloudWatch Alarms**
```bash
# Create alarm for high error rate
aws cloudwatch put-metric-alarm \
  --alarm-name "PhageVirus-Lambda-Errors" \
  --alarm-description "High error rate in PhageVirus Lambda" \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Sum \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2 \
  --region ap-southeast-2
```

## 🔒 **Security**

### **Encryption**
- **In Transit**: TLS 1.2+ for all communications
- **At Rest**: AES-256 encryption for S3 and DynamoDB
- **Environment Variables**: Encrypted using AWS KMS

### **Access Control**
- **IAM Roles**: Least privilege access
- **API Gateway**: Optional API key authentication
- **VPC**: Can be deployed in private VPC

### **Audit Logging**
- **CloudTrail**: All API calls logged
- **CloudWatch Logs**: Function execution logs
- **DynamoDB**: Data access audit logs

## 🚨 **Troubleshooting**

### **Common Issues**

**Function Timeout**
- Increase timeout in Lambda configuration
- Optimize code for faster execution
- Use async/await patterns

**Memory Issues**
- Increase memory allocation
- Optimize data structures
- Use streaming for large payloads

**Permission Errors**
- Verify IAM role permissions
- Check resource ARNs
- Ensure role trust policy is correct

**AWS CLI Not Found**
```powershell
# Add AWS CLI to PATH
$env:PATH += ";C:\Program Files\Amazon\AWSCLIV2"

# Verify installation
aws --version
```

### **Debugging**
```bash
# View function logs
aws logs tail /aws/lambda/phagevirus-telemetry-processor --follow

# Check function configuration
aws lambda get-function --function-name phagevirus-telemetry-processor

# Test function with error handling
aws lambda invoke --function-name phagevirus-telemetry-processor --payload '{"test": "error"}' response.json
```

## 📚 **Development**

### **Local Development**
```bash
# Install dependencies
dotnet restore

# Run tests
dotnet test

# Build for development
dotnet build

# Run locally with SAM
sam local invoke -e events/test-event.json
```

### **Adding New Features**
1. **New Data Types**: Add handlers in `ProcessTelemetryData`
2. **New Analysis**: Extend `PerformThreatAnalysisAsync`
3. **New Storage**: Add methods for new AWS services
4. **New Events**: Add handlers for new event types

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 **Contributing**

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

---

**PhageVirus Lambda** - Advanced Telemetry Processing & Threat Analysis
*Built with .NET 8 and AWS Lambda*

**Last Updated**: July 20, 2025
**Status**: ✅ Deployed and Operational
**Version**: 1.0.0 

## 🆕 **2025: Expanded Module Support**

The Lambda function now supports telemetry and analysis for the following modules:
- **EndpointSecurity**: RansomwareProtection, DeviceIsolation
- **CloudSecurity**: CSPMScanner, CWPPMonitor, CloudAPIThreatDetector, IAMMisconfigDetector, ServerlessContainerMonitor, IaCScanner, CloudMetricsCollector
- **IdentityProtection**: ADMonitor, MFAAnomalyDetector, TokenTheftDetector, ITDR

### Telemetry Routing & Analysis
- Lambda parses the `DataType` field and routes to the appropriate analysis logic for each module.
- Each module's telemetry is risk scored, patterns are detected, and recommendations are returned in a unified format.
- See the agent and module documentation for telemetry payload examples.

### API & Architecture Updates
- The API and backend now support all new modules and return structured analysis for each.
- See the main project README for a full list of modules and cloud integration details. 
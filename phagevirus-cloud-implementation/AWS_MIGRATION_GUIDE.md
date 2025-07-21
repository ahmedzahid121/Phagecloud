# 🦠 PhageVirus AWS Migration Guide

## 🚀 **Migration Overview**

This document outlines the migration from Azure cloud services to AWS as the primary cloud platform for PhageVirus, while maintaining Azure Key Vault for secrets management.

## ✅ **Migration Summary**

### **AWS Services (Primary)**
- **S3** – Scan log and report storage
- **DynamoDB** – Agent status and threat data storage
- **Lambda** – Telemetry processing and ML logic
- **CloudWatch Logs** – Logging and diagnostics
- **Kinesis** – Real-time data streaming (optional)
- **API Gateway** – Remote commands and control (future)

### **Azure Services (Secrets Only)**
- **Azure Key Vault** – Secure storage for:
  - SMTP credentials (for alert emails)
  - API tokens and client secrets
  - Other sensitive configuration

## 🏗️ **Architecture Changes**

### **Before (Azure-Focused)**
```
PhageVirus Agent
├── AzureCommunicator (Primary)
│   ├── App Service APIs
│   ├── Azure Functions
│   └── Microsoft Sentinel
└── AWSCommunicator (Secondary)
    ├── Kinesis Streams
    └── DynamoDB
```

### **After (AWS-Focused)**
```
PhageVirus Agent
├── AWSCommunicator (Primary)
│   ├── S3 (Storage)
│   ├── DynamoDB (Data)
│   ├── Lambda (Processing)
│   ├── CloudWatch Logs (Logging)
│   └── Kinesis (Streaming)
└── AzureKeyVaultService (Secrets Only)
    └── Key Vault (Credentials)
```

## 🔧 **Configuration Changes**

### **Updated Configuration Structure**

#### **Cloud Mode (`config/cloud.json`)**
```json
{
  "mode": "cloud",
  "cloud": {
    "aws": {
      "region": "ap-southeast-2",
      "s3_bucket": "phagevirus-logs",
      "dynamodb_table": "phagevirus-endpoints",
      "lambda_function": "phagevirus-telemetry-processor",
      "cloudwatch_log_group": "/aws/phagevirus/agent",
      "kinesis_stream": "phagevirus-telemetry",
      "telemetry": {
        "interval": 300,
        "batch_size": 50,
        "retry_attempts": 3
      }
    },
    "azure": {
      "key_vault": {
        "enabled": true,
        "vault_url": "https://phagevirus-secrets.vault.azure.net/",
        "secrets": {
          "smtp_username": "smtp-username",
          "smtp_password": "smtp-password",
          "api_tokens": "api-tokens"
        }
      }
    }
  }
}
```

#### **Hybrid Mode (`config/hybrid.json`)**
```json
{
  "mode": "hybrid",
  "cloud": {
    "aws": {
      "region": "ap-southeast-2",
      "s3_bucket": "phagevirus-logs",
      "dynamodb_table": "phagevirus-endpoints",
      "lambda_function": "phagevirus-telemetry-processor",
      "cloudwatch_log_group": "/aws/phagevirus/agent",
      "telemetry": {
        "interval": 120,
        "batch_size": 50
      }
    },
    "azure": {
      "key_vault": {
        "enabled": true,
        "vault_url": "https://phagevirus-secrets.vault.azure.net/"
      }
    }
  },
  "local": {
    "modules": {
      "ProcessWatcher": true,
      "MemoryTrap": true,
      "CredentialTrap": true
    },
    "max_memory_usage": 100
  }
}
```

## 🚀 **AWS Setup Instructions**

### **1. Prerequisites**

```bash
# Install AWS CLI
aws --version

# Configure AWS credentials
aws configure

# Set default region
aws configure set default.region ap-southeast-2
```

### **2. Create AWS Resources**

#### **S3 Bucket**
```bash
# Create S3 bucket for logs and reports
aws s3 mb s3://phagevirus-logs --region ap-southeast-2

# Configure bucket policy for security
aws s3api put-bucket-policy --bucket phagevirus-logs --policy file://s3-bucket-policy.json
```

#### **DynamoDB Table**
```bash
# Create DynamoDB table for endpoint data
aws dynamodb create-table \
  --table-name phagevirus-endpoints \
  --attribute-definitions AttributeName=AgentId,AttributeType=S AttributeName=Timestamp,AttributeType=S \
  --key-schema AttributeName=AgentId,KeyType=HASH AttributeName=Timestamp,KeyType=RANGE \
  --billing-mode PAY_PER_REQUEST \
  --region ap-southeast-2
```

#### **CloudWatch Log Group**
```bash
# Create CloudWatch log group
aws logs create-log-group --log-group-name "/aws/phagevirus/agent" --region ap-southeast-2

# Set retention policy (30 days)
aws logs put-retention-policy --log-group-name "/aws/phagevirus/agent" --retention-in-days 30 --region ap-southeast-2
```

#### **Lambda Function**
```bash
# Create Lambda function for telemetry processing
aws lambda create-function \
  --function-name phagevirus-telemetry-processor \
  --runtime dotnet8 \
  --role arn:aws:iam::YOUR_ACCOUNT:role/phagevirus-lambda-role \
  --handler PhageVirus.Lambda::PhageVirus.Lambda.Function::FunctionHandler \
  --zip-file fileb://phagevirus-lambda.zip \
  --region ap-southeast-2
```

#### **Kinesis Stream (Optional)**
```bash
# Create Kinesis stream for real-time data
aws kinesis create-stream \
  --stream-name phagevirus-telemetry \
  --shard-count 1 \
  --region ap-southeast-2
```

### **3. IAM Roles and Policies**

#### **Lambda Execution Role**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:ap-southeast-2:*:*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::phagevirus-logs/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:Query",
        "dynamodb:Scan"
      ],
      "Resource": "arn:aws:dynamodb:ap-southeast-2:*:table/phagevirus-endpoints"
    }
  ]
}
```

#### **Agent IAM Role**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::phagevirus-logs/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem",
        "dynamodb:GetItem",
        "dynamodb:Query"
      ],
      "Resource": "arn:aws:dynamodb:ap-southeast-2:*:table/phagevirus-endpoints"
    },
    {
      "Effect": "Allow",
      "Action": [
        "lambda:InvokeFunction"
      ],
      "Resource": "arn:aws:lambda:ap-southeast-2:*:function:phagevirus-telemetry-processor"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:ap-southeast-2:*:log-group:/aws/phagevirus/agent:*"
    }
  ]
}
```

## 🔐 **Azure Key Vault Setup**

### **1. Create Key Vault**
```bash
# Create resource group
az group create --name phagevirus-rg --location australiaeast

# Create Key Vault
az keyvault create \
  --name phagevirus-secrets \
  --resource-group phagevirus-rg \
  --location australiaeast \
  --sku standard
```

### **2. Store Secrets**
```bash
# Store SMTP credentials
az keyvault secret set --vault-name phagevirus-secrets --name smtp-username --value "your-smtp-username"
az keyvault secret set --vault-name phagevirus-secrets --name smtp-password --value "your-smtp-password"

# Store API tokens
az keyvault secret set --vault-name phagevirus-secrets --name api-tokens --value '{"default":"your-api-token"}'
```

### **3. Configure Access**
```bash
# Grant access to the application
az keyvault set-policy \
  --name phagevirus-secrets \
  --object-id YOUR_APP_OBJECT_ID \
  --secret-permissions get list set
```

## 📦 **Deployment**

### **1. Build the Agent**
```powershell
# Navigate to agent directory
cd phagevirus-agent

# Build for AWS
dotnet build -c Release

# Create deployment package
dotnet publish -c Release -o ./publish
```

### **2. Configure Environment**
```bash
# Set AWS credentials
export AWS_ACCESS_KEY_ID=your-access-key
export AWS_SECRET_ACCESS_KEY=your-secret-key
export AWS_DEFAULT_REGION=ap-southeast-2

# Set Azure credentials (for Key Vault)
export AZURE_CLIENT_ID=your-client-id
export AZURE_CLIENT_SECRET=your-client-secret
export AZURE_TENANT_ID=your-tenant-id
```

### **3. Run the Agent**
```bash
# Cloud mode (AWS primary)
./publish/PhageVirusAgent.exe --mode cloud

# Hybrid mode (AWS + local)
./publish/PhageVirusAgent.exe --mode hybrid

# Local mode (AWS for storage only)
./publish/PhageVirusAgent.exe --mode local
```

## 📊 **Monitoring and Verification**

### **1. Check S3 Storage**
```bash
# List uploaded files
aws s3 ls s3://phagevirus-logs/ --recursive

# Check specific agent data
aws s3 ls s3://phagevirus-logs/telemetry/YOUR_AGENT_ID/
```

### **2. Check DynamoDB Data**
```bash
# Query agent data
aws dynamodb query \
  --table-name phagevirus-endpoints \
  --key-condition-expression "AgentId = :agentId" \
  --expression-attribute-values '{":agentId":{"S":"YOUR_AGENT_ID"}}' \
  --region ap-southeast-2
```

### **3. Check CloudWatch Logs**
```bash
# List log streams
aws logs describe-log-streams \
  --log-group-name "/aws/phagevirus/agent" \
  --region ap-southeast-2

# Get log events
aws logs get-log-events \
  --log-group-name "/aws/phagevirus/agent" \
  --log-stream-name "YOUR_AGENT_ID/2024/01/15" \
  --region ap-southeast-2
```

### **4. Check Lambda Function**
```bash
# List Lambda functions
aws lambda list-functions --region ap-southeast-2

# Check function metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=phagevirus-telemetry-processor \
  --start-time 2024-01-15T00:00:00Z \
  --end-time 2024-01-15T23:59:59Z \
  --period 3600 \
  --statistics Sum \
  --region ap-southeast-2
```

## 🔧 **Troubleshooting**

### **Common Issues**

#### **AWS Credentials**
```bash
# Verify AWS credentials
aws sts get-caller-identity

# Check region
aws configure get region
```

#### **S3 Access**
```bash
# Test S3 access
aws s3 ls s3://phagevirus-logs/

# Check bucket policy
aws s3api get-bucket-policy --bucket phagevirus-logs
```

#### **DynamoDB Access**
```bash
# Test DynamoDB access
aws dynamodb describe-table --table-name phagevirus-endpoints --region ap-southeast-2
```

#### **Lambda Access**
```bash
# Test Lambda access
aws lambda get-function --function-name phagevirus-telemetry-processor --region ap-southeast-2
```

#### **Azure Key Vault**
```bash
# Test Key Vault access
az keyvault secret list --vault-name phagevirus-secrets

# Get specific secret
az keyvault secret show --vault-name phagevirus-secrets --name smtp-username
```

### **Log Analysis**

#### **Agent Logs**
```bash
# Check agent logs
tail -f /var/log/phagevirus-agent.log

# Check Windows Event Logs
Get-EventLog -LogName Application -Source "PhageVirus Agent" -Newest 50
```

#### **CloudWatch Logs**
```bash
# Search for errors
aws logs filter-log-events \
  --log-group-name "/aws/phagevirus/agent" \
  --filter-pattern "ERROR" \
  --region ap-southeast-2
```

## 📈 **Performance Optimization**

### **AWS Service Limits**
- **S3**: 5,500 PUT requests per second per prefix
- **DynamoDB**: 40,000 read/write capacity units
- **Lambda**: 1,000 concurrent executions
- **CloudWatch Logs**: 5 requests per second per log stream

### **Cost Optimization**
- Use S3 Intelligent Tiering for log storage
- Configure DynamoDB auto-scaling
- Set CloudWatch Logs retention policies
- Use Lambda provisioned concurrency for consistent performance

## 🔒 **Security Considerations**

### **Data Encryption**
- S3: Server-side encryption (SSE-S3)
- DynamoDB: Encryption at rest
- CloudWatch Logs: Encryption in transit and at rest
- Lambda: Encryption at rest

### **Access Control**
- Use IAM roles with least privilege
- Enable CloudTrail for audit logging
- Use VPC endpoints for private access
- Implement cross-account access if needed

### **Compliance**
- Enable AWS Config for compliance monitoring
- Use AWS CloudWatch for security monitoring
- Implement data retention policies
- Enable AWS GuardDuty for threat detection

## 📚 **Additional Resources**

- [AWS SDK for .NET Documentation](https://docs.aws.amazon.com/sdk-for-net/)
- [AWS Lambda Developer Guide](https://docs.aws.amazon.com/lambda/latest/dg/)
- [Amazon S3 Developer Guide](https://docs.aws.amazon.com/s3/)
- [Amazon DynamoDB Developer Guide](https://docs.aws.amazon.com/dynamodb/)
- [Amazon CloudWatch Logs User Guide](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/)

---

**Migration Status**: ✅ Complete  
**Primary Cloud**: AWS (ap-southeast-2)  
**Secrets Management**: Azure Key Vault  
**Last Updated**: January 2024 
# 🦠 PhageVirus Hybrid Cloud Implementation

A comprehensive hybrid cloud security solution that transforms the original PhageVirus into a distributed, scalable, enterprise-grade EDR system using **AWS as the primary cloud platform** with Azure Key Vault for secrets management.

## 🚀 **Overview**

This implementation provides a complete hybrid cloud architecture for PhageVirus, featuring:

- **Lightweight Endpoint Agent**: Minimal resource usage with AWS cloud offloading
- **AWS Services**: S3, DynamoDB, Lambda, CloudWatch Logs, Kinesis
- **Azure Key Vault**: Secure secrets management for SMTP and API credentials
- **Infrastructure as Code**: Automated deployment across AWS services
- **Real-time Threat Intelligence**: Distributed threat sharing and analysis

## 🏗️ **Architecture**

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

## 📁 **Repository Structure**

```
phagevirus-cloud-implementation/
├── phagevirus-agent/           # Lightweight endpoint agent
│   ├── src/
│   │   ├── Core/              # Main agent logic
│   │   ├── Cloud/             # AWS communication modules
│   │   ├── Local/             # Lightweight local security
│   │   └── Shared/            # Common data models
│   ├── config/                # Agent configuration files
│   ├── deployment/            # Deployment scripts
│   └── PhageVirusAgent.csproj # Agent project file
├── AWS_MIGRATION_GUIDE.md     # Complete AWS setup guide
├── IMPLEMENTATION_SUMMARY.md  # Implementation details
└── README.md                  # This file
```

## 🎯 **Agent Modes**

### **Cloud Mode** (Lightweight)
- **Memory Usage**: < 50MB
- **CPU Usage**: < 1%
- **Features**: Telemetry collection, heartbeat, AWS analysis
- **Local Processing**: Minimal
- **Use Case**: Large-scale deployments, resource-constrained environments

### **Hybrid Mode** (Balanced)
- **Memory Usage**: < 100MB
- **CPU Usage**: < 5%
- **Features**: Local detection + AWS offloading
- **Local Processing**: Quick threat analysis, high-risk escalation
- **Use Case**: Standard enterprise deployments

### **Local Mode** (Full)
- **Memory Usage**: < 200MB
- **CPU Usage**: < 10%
- **Features**: Full local security engine
- **Local Processing**: Complete threat analysis and response
- **Use Case**: Air-gapped environments, high-security requirements

## 🚀 **Quick Start**

### **1. Prerequisites**

```bash
# Required tools
- .NET 8.0 SDK
- AWS CLI
- Azure CLI (for Key Vault)
- PowerShell 7+
```

### **2. AWS Setup**

Follow the complete setup guide in [AWS_MIGRATION_GUIDE.md](AWS_MIGRATION_GUIDE.md):

```bash
# Configure AWS CLI
aws configure
aws configure set default.region ap-southeast-2

# Create AWS resources
aws s3 mb s3://phagevirus-logs --region ap-southeast-2
aws dynamodb create-table --table-name phagevirus-endpoints --region ap-southeast-2
aws logs create-log-group --log-group-name "/aws/phagevirus/agent" --region ap-southeast-2
```

### **3. Azure Key Vault Setup**

```bash
# Create Key Vault
az keyvault create --name phagevirus-secrets --resource-group phagevirus-rg --location australiaeast

# Store secrets
az keyvault secret set --vault-name phagevirus-secrets --name smtp-username --value "your-smtp-username"
az keyvault secret set --vault-name phagevirus-secrets --name smtp-password --value "your-smtp-password"
```

### **4. Build and Deploy Agent**

```powershell
# Navigate to agent directory
cd phagevirus-agent

# Build for AWS
dotnet build -c Release

# Create deployment package
dotnet publish -c Release -o ./publish

# Run in cloud mode
./publish/PhageVirusAgent.exe --mode cloud
```

### **5. Configure Agent**

Edit `config/cloud.json`:

```json
{
  "mode": "cloud",
  "cloud": {
    "aws": {
      "region": "ap-southeast-2",
      "s3_bucket": "phagevirus-logs",
      "dynamodb_table": "phagevirus-endpoints",
      "lambda_function": "phagevirus-telemetry-processor",
      "cloudwatch_log_group": "/aws/phagevirus/agent"
    },
    "azure": {
      "key_vault": {
        "enabled": true,
        "vault_url": "https://phagevirus-secrets.vault.azure.net/"
      }
    }
  }
}
```

## 📊 **Features**

### **Endpoint Agent**
- ✅ **Lightweight Design**: Minimal resource usage
- ✅ **Multi-Mode Support**: Cloud, hybrid, and local modes
- ✅ **Real-time Telemetry**: Continuous system monitoring
- ✅ **Threat Detection**: Local and AWS-based analysis
- ✅ **Automatic Updates**: Configuration and module updates
- ✅ **Health Monitoring**: Self-diagnosis and reporting

### **AWS Cloud Services**
- ✅ **Scalable Architecture**: Auto-scaling based on load
- ✅ **Real-time Processing**: Sub-second threat detection
- ✅ **Machine Learning**: Advanced threat analysis via Lambda
- ✅ **Threat Intelligence**: Global threat sharing
- ✅ **Compliance**: SOC 2, GDPR, HIPAA ready
- ✅ **Multi-tenant**: Enterprise-grade isolation

### **Security Features**
- ✅ **Zero Trust**: Continuous verification
- ✅ **Encryption**: End-to-end data protection
- ✅ **Audit Logging**: Complete activity tracking
- ✅ **Access Control**: Role-based permissions
- ✅ **Incident Response**: Automated threat handling
- ✅ **Forensics**: Detailed investigation capabilities

## 🔧 **Configuration**

### **Agent Configuration**

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
        "batch_size": 50,
        "retry_attempts": 3
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
    "scan_interval": 60,
    "max_memory_usage": 100
  },
  "telemetry": {
    "enabled": true,
    "heartbeat_interval": 60,
    "compression": true,
    "encryption": true
  }
}
```

## 📈 **Monitoring & Analytics**

### **Key Metrics**
- **Agent Health**: Uptime, response time, error rates
- **Threat Detection**: Detection rate, false positives, response time
- **System Performance**: CPU, memory, network usage
- **AWS Services**: API latency, throughput, availability

### **AWS Dashboards**
- **Real-time Threat Map**: Global threat visualization
- **Agent Status**: Endpoint health and status
- **Performance Analytics**: System and AWS performance
- **Incident Management**: Threat investigation and response

## 🔒 **Security**

### **Data Protection**
- **Encryption at Rest**: AES-256 for stored data
- **Encryption in Transit**: TLS 1.3 for all communications
- **Key Management**: AWS KMS and Azure Key Vault
- **Data Residency**: Configurable data location (ap-southeast-2)

### **Access Control**
- **Authentication**: AWS IAM and Azure AD
- **Authorization**: Role-based access control (RBAC)
- **Audit Logging**: Complete access and activity logs
- **Multi-factor Authentication**: Required for admin access

## 🚨 **Incident Response**

### **Automated Response**
1. **Threat Detection**: Real-time threat identification
2. **Risk Assessment**: ML-powered risk scoring via Lambda
3. **Response Selection**: Automated or manual response
4. **Action Execution**: Immediate threat neutralization
5. **Post-Incident**: Analysis and reporting

### **Response Actions**
- **Process Termination**: Kill malicious processes
- **Network Isolation**: Block suspicious connections
- **File Quarantine**: Move suspicious files
- **System Rollback**: Restore from safe state
- **Alert Escalation**: Notify security team

## 📚 **Documentation**

### **Setup Guides**
- [AWS Migration Guide](AWS_MIGRATION_GUIDE.md) - Complete AWS setup instructions
- [Implementation Summary](IMPLEMENTATION_SUMMARY.md) - Technical implementation details

### **Configuration**
- [Agent Configuration](phagevirus-agent/config/) - Configuration files for all modes
- [Deployment Scripts](phagevirus-agent/deployment/) - Automated deployment tools

## 🤝 **Contributing**

1. **Fork** the repository
2. **Create** a feature branch
3. **Make** your changes
4. **Test** thoroughly
5. **Submit** a pull request

### **Development Setup**

```bash
# Clone the repository
git clone https://github.com/your-org/phagevirus-cloud-implementation.git

# Set up development environment
cd phagevirus-cloud-implementation
./scripts/setup-dev.ps1

# Run tests
./scripts/run-tests.ps1

# Build all components
./scripts/build-all.ps1
```

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ **Disclaimer**

**This is a powerful security tool for educational and research purposes only.**

- **REAL SYSTEM OPERATIONS**: Uses actual Windows APIs and AWS services
- **REQUIRES ADMINISTRATOR PRIVILEGES**: Must run with elevated permissions
- **NEVER USE ON PRODUCTION SYSTEMS** without explicit permission
- **Use only in controlled environments** (VM, sandbox, test lab)
- **Not intended as a replacement for real security solutions**

## 📞 **Support**

- **Documentation**: [docs.phagevirus.com](https://docs.phagevirus.com)
- **Issues**: [GitHub Issues](https://github.com/your-org/phagevirus-cloud-implementation/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/phagevirus-cloud-implementation/discussions)
- **Email**: support@phagevirus.com

---

**PhageVirus Hybrid Cloud** - Advanced Threat Detection & Response System
*Built with .NET 8, AWS (ap-southeast-2), and Azure Key Vault* 

## 🆕 **Expanded Cloud-Enabled Modules (2025)**

The following modules now offload heavy analysis to AWS Lambda:
- **RansomwareProtection**
- **DeviceIsolation**
- **CSPMScanner**
- **CWPPMonitor**
- **CloudAPIThreatDetector**
- **IAMMisconfigDetector**
- **ServerlessContainerMonitor**
- **IaCScanner**
- **CloudMetricsCollector**
- **ADMonitor**
- **MFAAnomalyDetector**
- **TokenTheftDetector**
- **ITDR**

### Lambda Backend
- The Lambda function (`phagevirus-telemetry-processor`) now parses telemetry from all these modules, performs risk scoring, pattern detection, and returns structured analysis and recommendations.
- See [phagevirus-lambda/README.md](phagevirus-lambda/README.md) for Lambda details. 
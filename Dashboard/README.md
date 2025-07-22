# 🦠 PhageVirus Dashboard

A modern, responsive web dashboard for the PhageVirus EDR (Endpoint Detection and Response) system. Built with ASP.NET Core MVC, this dashboard provides real-time monitoring, threat management, and system administration capabilities.

## 🚀 Features

### 📊 Executive Summary (Top Cards Panel)
- **🟢 Active Endpoints**: Real-time endpoint status (online/offline/total)
- **🛑 Threats Detected Today**: New threats and critical alerts
- **☁️ Cloud Misconfig Alerts**: AWS/Azure security posture issues
- **👤 Identity Threats**: Suspicious logins and token misuse
- **⚙️ Agent Health Status**: System health and agent status
- **🧪 Last Test Run**: Testing framework results and status

### 🔍 Threat Feed (Live + Historical)
- Real-time threat monitoring with severity classification
- Historical threat analysis and trends
- Threat type categorization (Ransomware, Token Theft, Exploit, etc.)
- Action tracking (Blocked, Quarantined, Logged, Isolated)

### 📡 Endpoint Overview
- Comprehensive endpoint management table
- Real-time status monitoring (Online/Offline/Unhealthy/Isolated)
- Filtering by site, department, OS, and risk level
- Performance metrics (CPU, Memory usage)
- Agent version tracking and update status

### ☁️ Cloud Posture Management
- **AWS Security**: IAM misconfigurations, public S3 buckets, exposed roles
- **Azure Security**: Function crashes, anomalous executions, security alerts
- **CSPM Status**: Compliance percentage and critical gaps
- Real-time cloud security posture monitoring

### 🧬 Identity Protection
- **MFA Bypass Detection**: Impossible travel and suspicious login attempts
- **Session Hijack Monitoring**: Token reuse and concurrent usage detection
- **Privilege Escalation**: Unauthorized privilege changes
- Identity threat metrics and alerting

### 🛠 Actions Panel (Slide-Out)
- **📡 Force Scan**: Push scans to endpoints
- **⛔ Isolate Device**: Network isolation capabilities
- **🧠 Run Red Team Sim**: Attack simulation for testing
- **🧩 Update Policy**: Security policy management
- **📄 Export Logs**: Audit trail export (CSV/JSON)
- **🔄 Update Agents**: Agent deployment and updates

### 📝 Logs & Audit Trail
- Comprehensive audit logging
- User action tracking
- Export capabilities (CSV, JSON)
- Real-time log monitoring

## 🏗️ Architecture

### Technology Stack
- **Backend**: ASP.NET Core 8.0 MVC
- **Frontend**: Bootstrap 5.3, Font Awesome 6.4
- **Data**: In-memory mock data (easily replaceable with real data sources)
- **Real-time Updates**: AJAX polling with 30-second intervals

### Project Structure
```
PhageVirusDashboard/
├── Controllers/
│   └── DashboardController.cs          # Main dashboard controller
├── Models/
│   └── DashboardModels.cs              # Data models and view models
├── Services/
│   └── DashboardService.cs             # Business logic and data services
├── Views/
│   └── Dashboard/
│       └── Index.cshtml                # Main dashboard view
├── wwwroot/                            # Static assets
├── Program.cs                          # Application configuration
└── README.md                           # This file
```

### Data Models
- **ExecutiveSummary**: Top-level dashboard metrics
- **ThreatFeed**: Threat events and historical data
- **EndpointOverview**: Endpoint information and status
- **CloudPosture**: AWS/Azure security posture
- **IdentityProtection**: Identity threat monitoring
- **DashboardAction**: Available administrative actions
- **AuditLog**: System audit trail

## 🚀 Quick Start

### Prerequisites
- .NET 8.0 SDK
- Visual Studio 2022 or VS Code
- Modern web browser

### Installation & Running

1. **Navigate to the dashboard directory**:
   ```bash
   cd Phagecloud/Dashboard/PhageVirusDashboard
   ```

2. **Restore dependencies**:
   ```bash
   dotnet restore
   ```

3. **Build the application**:
   ```bash
   dotnet build
   ```

4. **Run the dashboard**:
   ```bash
   dotnet run
   ```

5. **Access the dashboard**:
   Open your browser and navigate to `https://localhost:5001` or `http://localhost:5000`

## 📱 Dashboard Interface

### Navigation
- **Main Dashboard**: Overview with all key metrics
- **Endpoints**: Detailed endpoint management
- **Threats**: Threat feed and analysis
- **Cloud**: Cloud security posture
- **Identity**: Identity protection monitoring
- **Actions**: Administrative actions panel
- **Logs**: Audit trail and logs

### Real-time Features
- **Auto-refresh**: Dashboard updates every 30 seconds
- **Live Metrics**: Real-time endpoint and threat statistics
- **Interactive Cards**: Hover effects and clickable elements
- **Responsive Design**: Works on desktop, tablet, and mobile

### Color Coding
- **🟢 Green**: Success, online status, low severity
- **🟡 Yellow**: Warning, medium severity, unhealthy status
- **🟠 Orange**: High severity threats
- **🔴 Red**: Critical alerts, offline status, high severity
- **🔵 Blue**: Primary actions, information

## 🔧 Configuration

### Service Registration
The dashboard uses dependency injection for services:

```csharp
// Program.cs
builder.Services.AddScoped<IDashboardService, DashboardService>();
```

### Mock Data
Currently uses mock data for demonstration. To integrate with real PhageVirus system:

1. Replace `DashboardService` with real data service
2. Update data models to match actual PhageVirus data structures
3. Implement real-time data connections (SignalR, WebSockets)

### Customization
- **Styling**: Modify CSS variables in `Index.cshtml`
- **Layout**: Adjust Bootstrap grid system
- **Data Sources**: Replace mock data with real API calls
- **Authentication**: Add authentication middleware

## 🔌 Integration with PhageVirus

### Data Integration Points
- **Endpoint Data**: Connect to PhageVirus agent telemetry
- **Threat Data**: Integrate with threat detection modules
- **Cloud Data**: Connect to AWS/Azure APIs
- **Identity Data**: Integrate with AD/Entra ID monitoring
- **Audit Logs**: Connect to PhageVirus logging system

### API Endpoints
The dashboard provides REST API endpoints for integration:

- `GET /Dashboard/GetExecutiveSummary` - Dashboard metrics
- `GET /Dashboard/GetThreatFeed` - Threat data
- `GET /Dashboard/GetEndpoints` - Endpoint information
- `GET /Dashboard/GetCloudPosture` - Cloud security data
- `GET /Dashboard/GetIdentityProtection` - Identity protection data
- `POST /Dashboard/ExecuteAction` - Execute administrative actions
- `GET /Dashboard/ExportLogs` - Export audit logs

## 🛡️ Security Features

### Built-in Security
- **HTTPS**: Secure communication by default
- **Session Management**: 30-minute session timeout
- **Input Validation**: All inputs validated and sanitized
- **CSRF Protection**: Built-in ASP.NET Core protection
- **Audit Logging**: All actions logged for compliance

### Access Control
- **Role-based Access**: Ready for RBAC implementation
- **Action Confirmation**: Critical actions require confirmation
- **Audit Trail**: Complete action tracking and logging

## 📊 Performance

### Optimization Features
- **Lazy Loading**: Data loaded on demand
- **Caching**: In-memory caching for frequently accessed data
- **Minimal Dependencies**: Lightweight framework usage
- **Responsive Design**: Optimized for all screen sizes

### Scalability
- **Stateless Design**: Easy horizontal scaling
- **Service Layer**: Business logic separated from presentation
- **Async Operations**: Non-blocking data operations

## 🧪 Testing

### Test Coverage
- **Unit Tests**: Service layer testing
- **Integration Tests**: Controller and API testing
- **UI Tests**: Dashboard functionality testing

### Mock Data
The dashboard includes comprehensive mock data for testing:
- 100 simulated endpoints
- 100 historical threat events
- 50 audit log entries
- Realistic cloud posture data

## 🔄 Updates and Maintenance

### Regular Updates
- **Security Patches**: Keep .NET Core updated
- **Dependencies**: Regular dependency updates
- **Data Models**: Update models as PhageVirus evolves

### Monitoring
- **Health Checks**: Built-in health monitoring
- **Error Logging**: Comprehensive error tracking
- **Performance Metrics**: Dashboard performance monitoring

## 📞 Support

### Documentation
- **API Documentation**: REST API endpoints
- **User Guide**: Dashboard usage instructions
- **Developer Guide**: Integration and customization

### Troubleshooting
- **Common Issues**: Known problems and solutions
- **Debug Mode**: Development debugging features
- **Log Analysis**: Error log analysis tools

## 🎯 Roadmap

### Planned Features
- **Real-time Notifications**: Push notifications for critical alerts
- **Advanced Filtering**: Enhanced filtering and search capabilities
- **Custom Dashboards**: User-configurable dashboard layouts
- **Mobile App**: Native mobile application
- **API Integration**: Full PhageVirus API integration
- **Advanced Analytics**: Machine learning-powered insights

### Future Enhancements
- **Multi-tenant Support**: Enterprise multi-tenant architecture
- **Advanced Reporting**: Custom report generation
- **Workflow Automation**: Automated response workflows
- **Third-party Integrations**: SIEM and ticketing system integration

---

**PhageVirus Dashboard** - Advanced EDR Management Interface
*Built with ASP.NET Core 8.0 and Bootstrap 5.3* 
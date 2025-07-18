# PhageVirus - Quick Start Guide

## 🚀 Get Running in 5 Minutes

### Step 1: Install .NET 8.0
**Option A: Download from Microsoft**
1. Go to https://dotnet.microsoft.com/download
2. Download .NET 8.0 SDK for Windows
3. Run the installer

**Option B: Use winget (Windows 10/11)**
```powershell
winget install Microsoft.DotNet.SDK.8
```

**Option C: Use Chocolatey**
```cmd
choco install dotnet-8.0-sdk
```

### Step 2: Run the Application
**Option A: Use PowerShell Script (Recommended)**
```powershell
.\run_phagevirus.ps1
```

**Option B: Use Batch File**
```cmd
build_and_run.bat
```

**Option C: Manual Commands**
```cmd
dotnet build
dotnet run
```

### Step 3: Use the Application
1. **Launch**: The futuristic dark-themed UI will appear
2. **Scan**: Click the green "START SCAN" button
3. **Watch**: Observe real-time threat detection and neutralization
4. **Review**: Check the threat table and activity log
5. **Self-Destruct**: Use the red button if threats were found (optional)

## 🎯 What You'll See

### Main Features
- **Dark Futuristic UI**: Modern design with cyan and green accents
- **Real-time Scanning**: Live threat detection and processing
- **Threat Table**: Shows detected files and processes
- **Activity Log**: Detailed logging of all operations
- **Email Reporting**: Simulated email reports to administrators
- **Self-Destruction**: Option to remove the application after cleanup

### Sample Output
```
[2024-12-07 18:30:15.123] [INFO] PhageVirus application started
[2024-12-07 18:30:16.456] [SCAN] Starting comprehensive scan...
[2024-12-07 18:30:17.789] [INFO] Found 3 potential threats
[2024-12-07 18:30:18.012] [THREAT] Detected: C:\FakeMalware\stealer_v2.exe (Keyword match: stealer)
[2024-12-07 18:30:18.234] [SUCCESS] Successfully processed: C:\FakeMalware\stealer_v2.exe
[2024-12-07 18:30:18.567] [SCAN] Complete - Found: 3, Neutralized: 3
[2024-12-07 18:30:19.890] [SUCCESS] Email report sent successfully
```

## ⚠️ Important Notes

### Safety First
- **Simulation Only**: This is a demo application that creates fake threats
- **No Real Malware**: Only detects and processes test files
- **Safe to Run**: Won't affect your real system files
- **Educational Purpose**: Designed for learning and demonstration

### System Requirements
- Windows 10/11
- .NET 8.0 Runtime or SDK
- 100 MB free disk space
- 50 MB RAM

### Troubleshooting
**If the application won't start:**
1. Ensure .NET 8.0 is installed: `dotnet --version`
2. Check Windows compatibility
3. Run as administrator if needed

**If no threats are detected:**
1. Check if fake threat files were created
2. Verify scan paths are accessible
3. Review the activity log for details

## 🎨 Customization

### Quick UI Changes
Edit `App.xaml` to modify colors and styling:
```xml
<!-- Change title color -->
<Setter Property="Foreground" Value="LightBlue"/>

<!-- Change button color -->
<Setter Property="Background" Value="#00ff88"/>
```

### Email Configuration
Edit `MainWindow.xaml.cs` to enable real email reporting:
```csharp
var adminEmail = "your-email@company.com";
var smtpHost = "smtp.gmail.com";
var senderEmail = "your-bot@gmail.com";
var senderPassword = "your_app_password";
```

## 📁 File Locations

### Application Files
- **Executable**: `bin/Debug/net8.0-windows/PhageVirus.exe`
- **Logs**: `%LocalAppData%\PhageVirus\Logs\`
- **Configuration**: `appsettings.json`

### Test Files Created
- `C:\FakeMalware\stealer_v2.exe`
- `C:\FakeMalware\keylogger_data.txt`
- `C:\FakeMalware\trojan_backdoor.dll`
- `C:\FakeMalware\crypto_miner.bat`

## 🔧 Advanced Usage

### Command Line Options
```cmd
# Build only
dotnet build

# Run in release mode
dotnet run --configuration Release

# Clean build
dotnet clean && dotnet build
```

### Development
```cmd
# Open in Visual Studio
start PhageVirus.csproj

# Open in VS Code
code .
```

## 📞 Need Help?

1. **Check the README.md** for detailed documentation
2. **Review log files** in `%LocalAppData%\PhageVirus\Logs\`
3. **Verify .NET installation**: `dotnet --version`
4. **Check Windows compatibility**: Windows 10/11 required

---

**Enjoy exploring PhageVirus!** 🦠✨ 
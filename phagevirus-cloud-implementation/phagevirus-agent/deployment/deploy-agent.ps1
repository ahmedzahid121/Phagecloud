# PhageVirus Cloud Agent Deployment Script
# This script deploys the lightweight cloud agent

param(
    [string]$Mode = "cloud",
    [string]$ConfigPath = "config",
    [switch]$InstallService,
    [switch]$UninstallService,
    [switch]$BuildOnly
)

Write-Host "🦠 PhageVirus Cloud Agent Deployment Script" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ This script requires administrator privileges" -ForegroundColor Red
    Write-Host "Please run PowerShell as Administrator" -ForegroundColor Yellow
    exit 1
}

# Function to build the agent
function Build-Agent {
    Write-Host "🔨 Building PhageVirus Cloud Agent..." -ForegroundColor Yellow
    
    try {
        # Restore packages
        dotnet restore
        if ($LASTEXITCODE -ne 0) {
            throw "Package restore failed"
        }
        
        # Build the project
        dotnet build -c Release
        if ($LASTEXITCODE -ne 0) {
            throw "Build failed"
        }
        
        # Publish for deployment
        dotnet publish -c Release -o "bin/Release/publish" --self-contained false
        if ($LASTEXITCODE -ne 0) {
            throw "Publish failed"
        }
        
        Write-Host "✅ Build completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "❌ Build failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Function to copy configuration
function Copy-Configuration {
    param([string]$Mode)
    
    Write-Host "📋 Copying configuration for $Mode mode..." -ForegroundColor Yellow
    
    $sourceConfig = "config/$Mode.json"
    $targetConfig = "bin/Release/publish/config/agent-config.json"
    
    if (Test-Path $sourceConfig) {
        # Create config directory if it doesn't exist
        $configDir = Split-Path $targetConfig -Parent
        if (!(Test-Path $configDir)) {
            New-Item -ItemType Directory -Path $configDir -Force | Out-Null
        }
        
        Copy-Item $sourceConfig $targetConfig -Force
        Write-Host "✅ Configuration copied successfully" -ForegroundColor Green
    }
    else {
        Write-Host "⚠️  Configuration file $sourceConfig not found" -ForegroundColor Yellow
    }
}

# Function to install as Windows service
function Install-Service {
    Write-Host "🔧 Installing as Windows service..." -ForegroundColor Yellow
    
    try {
        $serviceName = "PhageVirusCloudAgent"
        $displayName = "PhageVirus Cloud Agent"
        $description = "Lightweight cloud security agent for threat detection and prevention"
        $exePath = (Resolve-Path "bin/Release/publish/PhageVirusAgent.exe").Path
        
        # Check if service already exists
        $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($existingService) {
            Write-Host "⚠️  Service already exists. Stopping and removing..." -ForegroundColor Yellow
            Stop-Service $serviceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Remove-Service $serviceName -Force
        }
        
        # Create the service
        New-Service -Name $serviceName -DisplayName $displayName -Description $description -BinaryPathName $exePath -StartupType Automatic
        
        # Set service to run as LocalSystem
        $service = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'"
        $service.Change($null, $null, $null, $null, $null, $null, $null, "LocalSystem", $null, $null, $null)
        
        Write-Host "✅ Service installed successfully" -ForegroundColor Green
        Write-Host "📝 Service name: $serviceName" -ForegroundColor Cyan
        Write-Host "📝 Executable: $exePath" -ForegroundColor Cyan
        
        # Start the service
        Write-Host "🚀 Starting service..." -ForegroundColor Yellow
        Start-Service $serviceName
        Write-Host "✅ Service started successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "❌ Service installation failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Function to uninstall service
function Uninstall-Service {
    Write-Host "🗑️  Uninstalling Windows service..." -ForegroundColor Yellow
    
    try {
        $serviceName = "PhageVirusCloudAgent"
        
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            # Stop the service
            if ($service.Status -eq "Running") {
                Stop-Service $serviceName -Force
                Start-Sleep -Seconds 2
            }
            
            # Remove the service
            Remove-Service $serviceName -Force
            Write-Host "✅ Service uninstalled successfully" -ForegroundColor Green
        }
        else {
            Write-Host "ℹ️  Service not found" -ForegroundColor Cyan
        }
    }
    catch {
        Write-Host "❌ Service uninstallation failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to create deployment package
function Create-DeploymentPackage {
    Write-Host "📦 Creating deployment package..." -ForegroundColor Yellow
    
    try {
        $packageDir = "deployment/package"
        $publishDir = "bin/Release/publish"
        
        # Create package directory
        if (Test-Path $packageDir) {
            Remove-Item $packageDir -Recurse -Force
        }
        New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
        
        # Copy published files
        Copy-Item "$publishDir/*" $packageDir -Recurse -Force
        
        # Create deployment script
        $deployScript = @"
@echo off
echo 🦠 PhageVirus Cloud Agent Deployment
echo ====================================

REM Check for administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ❌ This script requires administrator privileges
    echo Please run Command Prompt as Administrator
    pause
    exit /b 1
)

echo 🔧 Installing PhageVirus Cloud Agent...

REM Create installation directory
set INSTALL_DIR=C:\Program Files\PhageVirus\Agent
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

REM Copy files
xcopy /E /I /Y . "%INSTALL_DIR%"

REM Install service
sc create "PhageVirusCloudAgent" binPath="%INSTALL_DIR%\PhageVirusAgent.exe" start=auto DisplayName="PhageVirus Cloud Agent"
sc description "PhageVirusCloudAgent" "Lightweight cloud security agent for threat detection and prevention"

REM Start service
sc start "PhageVirusCloudAgent"

echo ✅ Installation completed successfully
echo 📝 Service name: PhageVirusCloudAgent
echo 📝 Installation directory: %INSTALL_DIR%
pause
"@
        
        Set-Content -Path "$packageDir/install.bat" -Value $deployScript -Encoding ASCII
        
        # Create uninstall script
        $uninstallScript = @"
@echo off
echo 🗑️  Uninstalling PhageVirus Cloud Agent...

REM Stop and remove service
sc stop "PhageVirusCloudAgent"
sc delete "PhageVirusCloudAgent"

REM Remove installation directory
rmdir /S /Q "C:\Program Files\PhageVirus\Agent"

echo ✅ Uninstallation completed successfully
pause
"@
        
        Set-Content -Path "$packageDir/uninstall.bat" -Value $uninstallScript -Encoding ASCII
        
        # Create README
        $readme = @"
# PhageVirus Cloud Agent

## Installation

1. Run `install.bat` as Administrator
2. The service will be installed and started automatically

## Uninstallation

1. Run `uninstall.bat` as Administrator
2. The service will be stopped and removed

## Configuration

Edit `config/agent-config.json` to modify agent settings.

## Logs

Service logs are available in Windows Event Viewer under "Windows Logs" > "Application".

## Support

For issues or questions, check the logs or contact your system administrator.
"@
        
        Set-Content -Path "$packageDir/README.md" -Value $readme -Encoding UTF8
        
        Write-Host "✅ Deployment package created at: $packageDir" -ForegroundColor Green
    }
    catch {
        Write-Host "❌ Package creation failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Main execution
try {
    # Validate mode parameter
    $validModes = @("cloud", "hybrid", "local")
    if ($Mode -notin $validModes) {
        Write-Host "❌ Invalid mode. Valid modes are: $($validModes -join ', ')" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "🎯 Deployment mode: $Mode" -ForegroundColor Cyan
    
    # Build the agent
    Build-Agent
    
    if ($BuildOnly) {
        Write-Host "✅ Build completed. Skipping deployment." -ForegroundColor Green
        exit 0
    }
    
    # Copy configuration
    Copy-Configuration -Mode $Mode
    
    # Handle service operations
    if ($UninstallService) {
        Uninstall-Service
    }
    elseif ($InstallService) {
        Install-Service
    }
    else {
        # Create deployment package
        Create-DeploymentPackage
    }
    
    Write-Host "🎉 Deployment completed successfully!" -ForegroundColor Green
}
catch {
    Write-Host "❌ Deployment failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} 
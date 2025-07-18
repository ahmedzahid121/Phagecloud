# PhageVirus Cloud Implementation - Build and Test Script
# This script builds and tests the lightweight agent

param(
    [string]$Mode = "hybrid",
    [switch]$SkipTests,
    [switch]$Verbose
)

Write-Host "🦠 PhageVirus Cloud Implementation - Build and Test" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# Function to check prerequisites
function Test-Prerequisites {
    Write-Host "🔍 Checking prerequisites..." -ForegroundColor Yellow
    
    $prerequisiteErrors = @()
    
    # Check .NET 8
    try {
        $dotnetVersion = dotnet --version
        if ($dotnetVersion -notlike "8.*") {
            $prerequisiteErrors += ".NET 8.0 SDK is required. Found: $dotnetVersion"
        }
        else {
            Write-Host "✅ .NET 8.0 SDK: $dotnetVersion" -ForegroundColor Green
        }
    }
    catch {
        $prerequisiteErrors += ".NET 8.0 SDK not found"
    }
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        $prerequisiteErrors += "PowerShell 7+ is required. Found: $($PSVersionTable.PSVersion)"
    }
    else {
        Write-Host "✅ PowerShell: $($PSVersionTable.PSVersion)" -ForegroundColor Green
    }
    
    if ($prerequisiteErrors.Count -gt 0) {
        Write-Host "❌ Prerequisites not met:" -ForegroundColor Red
        foreach ($prerequisiteError in $prerequisiteErrors) {
            Write-Host "   - $prerequisiteError" -ForegroundColor Red
        }
        return $false
    }
    
    return $true
}

# Function to build the agent
function Build-Agent {
    param([string]$Mode)
    
    Write-Host "🔨 Building PhageVirus Agent ($Mode mode)..." -ForegroundColor Yellow
    
    try {
        Push-Location "phagevirus-agent"
        
        # Clean previous builds
        if (Test-Path "bin") {
            Remove-Item "bin" -Recurse -Force
        }
        if (Test-Path "obj") {
            Remove-Item "obj" -Recurse -Force
        }
        
        # Restore packages
        Write-Host "📦 Restoring packages..." -ForegroundColor Cyan
        dotnet restore
        if ($LASTEXITCODE -ne 0) {
            throw "Package restore failed"
        }
        
        # Build the project
        Write-Host "🔨 Building project..." -ForegroundColor Cyan
        dotnet build -c Release
        if ($LASTEXITCODE -ne 0) {
            throw "Build failed"
        }
        
        # Publish for deployment
        Write-Host "📦 Publishing for deployment..." -ForegroundColor Cyan
        dotnet publish -c Release -o "bin/Release/publish" --self-contained false
        if ($LASTEXITCODE -ne 0) {
            throw "Publish failed"
        }
        
        # Copy configuration
        Write-Host "📋 Copying configuration..." -ForegroundColor Cyan
        $configDir = "bin/Release/publish/config"
        if (!(Test-Path $configDir)) {
            New-Item -ItemType Directory -Path $configDir -Force | Out-Null
        }
        
        $sourceConfig = "config/$Mode.json"
        $targetConfig = "$configDir/agent-config.json"
        
        if (Test-Path $sourceConfig) {
            Copy-Item $sourceConfig $targetConfig -Force
            Write-Host "✅ Configuration copied: $sourceConfig -> $targetConfig" -ForegroundColor Green
        }
        else {
            Write-Host "⚠️  Configuration file not found: $sourceConfig" -ForegroundColor Yellow
        }
        
        Write-Host "✅ Agent build completed successfully" -ForegroundColor Green
        Write-Host "📁 Output directory: $(Resolve-Path 'bin/Release/publish')" -ForegroundColor Cyan
        
        Pop-Location
        return $true
    }
    catch {
        Write-Host "❌ Agent build failed: $($_.Exception.Message)" -ForegroundColor Red
        Pop-Location
        return $false
    }
}

# Function to test the agent
function Test-Agent {
    param([string]$Mode)
    
    Write-Host "🧪 Testing PhageVirus Agent..." -ForegroundColor Yellow
    
    try {
        Push-Location "phagevirus-agent"
        
        $exePath = "bin/Release/publish/PhageVirusAgent.exe"
        
        if (!(Test-Path $exePath)) {
            throw "Agent executable not found: $exePath"
        }
        
        Write-Host "🚀 Starting agent test..." -ForegroundColor Cyan
        
        # Start the agent process
        $process = Start-Process -FilePath $exePath -ArgumentList "--test-mode" -PassThru -NoNewWindow
        
        # Wait a few seconds for startup
        Start-Sleep -Seconds 5
        
        # Check if process is still running
        if (!$process.HasExited) {
            Write-Host "✅ Agent started successfully" -ForegroundColor Green
            
            # Stop the process
            $process.Kill()
            $process.WaitForExit(5000)
            
            Write-Host "✅ Agent test completed successfully" -ForegroundColor Green
        }
        else {
            throw "Agent process exited unexpectedly"
        }
        
        Pop-Location
        return $true
    }
    catch {
        Write-Host "❌ Agent test failed: $($_.Exception.Message)" -ForegroundColor Red
        Pop-Location
        return $false
    }
}

# Function to create deployment package
function Create-DeploymentPackage {
    Write-Host "📦 Creating deployment package..." -ForegroundColor Yellow
    
    try {
        $packageDir = "deployment/package"
        $publishDir = "phagevirus-agent/bin/Release/publish"
        
        # Create package directory
        if (Test-Path $packageDir) {
            Remove-Item $packageDir -Recurse -Force
        }
        New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
        
        # Copy published files
        Copy-Item "$publishDir/*" $packageDir -Recurse -Force
        
        # Create simple test script
        $testScript = @"
@echo off
echo 🦠 PhageVirus Cloud Agent Test
echo ==============================

echo Starting agent in test mode...
PhageVirusAgent.exe --test-mode

echo.
echo Test completed. Press any key to exit...
pause >nul
"@
        
        Set-Content -Path "$packageDir/test-agent.bat" -Value $testScript -Encoding ASCII
        
        Write-Host "✅ Deployment package created at: $packageDir" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "❌ Package creation failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to show summary
function Show-Summary {
    param([string]$Mode, [bool]$BuildSuccess, [bool]$TestSuccess)
    
    Write-Host ""
    Write-Host "📊 Build Summary" -ForegroundColor Cyan
    Write-Host "================" -ForegroundColor Cyan
    Write-Host "Mode: $Mode" -ForegroundColor White
    Write-Host "Build: $(if ($BuildSuccess) { '✅ Success' } else { '❌ Failed' })" -ForegroundColor $(if ($BuildSuccess) { 'Green' } else { 'Red' })
    Write-Host "Test: $(if ($TestSuccess) { '✅ Success' } else { '❌ Failed' })" -ForegroundColor $(if ($TestSuccess) { 'Green' } else { 'Red' })
    
    if ($BuildSuccess) {
        Write-Host ""
        Write-Host "📁 Output Locations:" -ForegroundColor Cyan
        Write-Host "   Agent: phagevirus-agent/bin/Release/publish/" -ForegroundColor White
        Write-Host "   Package: deployment/package/" -ForegroundColor White
        Write-Host ""
        Write-Host "🚀 Next Steps:" -ForegroundColor Cyan
        Write-Host "   1. Configure cloud endpoints in config/agent-config.json" -ForegroundColor White
        Write-Host "   2. Deploy cloud infrastructure (Azure/AWS)" -ForegroundColor White
        Write-Host "   3. Install agent using: .\phagevirus-agent\deployment\deploy-agent.ps1 -Mode $Mode -InstallService" -ForegroundColor White
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
    
    Write-Host "🎯 Build mode: $Mode" -ForegroundColor Cyan
    Write-Host ""
    
    # Check prerequisites
    if (!(Test-Prerequisites)) {
        exit 1
    }
    
    Write-Host ""
    
    # Build the agent
    $buildSuccess = Build-Agent -Mode $Mode
    
    if (!$buildSuccess) {
        exit 1
    }
    
    Write-Host ""
    
    # Test the agent (if not skipped)
    $testSuccess = $true
    if (!$SkipTests) {
        $testSuccess = Test-Agent -Mode $Mode
    }
    else {
        Write-Host "⏭️  Skipping tests (--SkipTests specified)" -ForegroundColor Yellow
    }
    
    Write-Host ""
    
    # Create deployment package
    if ($buildSuccess) {
        Create-DeploymentPackage
    }
    
    Write-Host ""
    
    # Show summary
    Show-Summary -Mode $Mode -BuildSuccess $buildSuccess -TestSuccess $testSuccess
    
    if ($buildSuccess) {
        Write-Host "🎉 Build and test completed successfully!" -ForegroundColor Green
        exit 0
    }
    else {
        Write-Host "❌ Build and test failed!" -ForegroundColor Red
        exit 1
    }
}
catch {
    Write-Host "❌ Unexpected error: $($_.Exception.Message)" -ForegroundColor Red
    if ($Verbose) {
        Write-Host "Stack trace: $($_.Exception.StackTrace)" -ForegroundColor Red
    }
    exit 1
} 
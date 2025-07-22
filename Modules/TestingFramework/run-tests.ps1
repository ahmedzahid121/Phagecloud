# PhageVirus EDR System - Industry Standard Testing Framework
# PowerShell script to run comprehensive tests and generate reports

param(
    [switch]$All, [switch]$Unit, [switch]$Integration, [switch]$Functional,
    [switch]$Performance, [switch]$Security, [switch]$Regression, [switch]$Manual,
    [int]$Duration = 30, [int]$Iterations = 1000, [double]$Memory = 500, [double]$Cpu = 80,
    [switch]$Help
)

# Display help if requested
if ($Help) {
    Write-Host "PhageVirus Testing Framework" -ForegroundColor Cyan
    Write-Host "Usage: .\run-tests.ps1 [options]" -ForegroundColor White
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Yellow
    Write-Host "  -All                    Run all test categories" -ForegroundColor White
    Write-Host "  -Unit                   Run unit tests only" -ForegroundColor White
    Write-Host "  -Integration            Run integration tests only" -ForegroundColor White
    Write-Host "  -Functional             Run functional tests only" -ForegroundColor White
    Write-Host "  -Performance            Run performance tests only" -ForegroundColor White
    Write-Host "  -Security               Run security tests only" -ForegroundColor White
    Write-Host "  -Regression             Run regression tests only" -ForegroundColor White
    Write-Host "  -Manual                 Run manual QA tests only" -ForegroundColor White
    Write-Host "  -Duration <seconds>     Performance test duration (default: 30)" -ForegroundColor White
    Write-Host "  -Iterations <count>     Performance test iterations (default: 1000)" -ForegroundColor White
    Write-Host "  -Memory <MB>            Memory threshold for performance tests (default: 500)" -ForegroundColor White
    Write-Host "  -Cpu <percent>          CPU threshold for performance tests (default: 80)" -ForegroundColor White
    Write-Host "  -Help                   Show this help message" -ForegroundColor White
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Yellow
    Write-Host "  .\run-tests.ps1 -All" -ForegroundColor White
    Write-Host "  .\run-tests.ps1 -Unit -Integration" -ForegroundColor White
    Write-Host "  .\run-tests.ps1 -Performance -Duration 60 -Iterations 2000" -ForegroundColor White
    exit 0
}

# Build arguments array
$args = @()
if ($All) { $args += "--all" }
if ($Unit) { $args += "--unit" }
if ($Integration) { $args += "--integration" }
if ($Functional) { $args += "--functional" }
if ($Performance) { $args += "--performance" }
if ($Security) { $args += "--security" }
if ($Regression) { $args += "--regression" }
if ($Manual) { $args += "--manual" }

# Add performance parameters if specified
if ($Duration -ne 30) { $args += "--duration"; $args += $Duration.ToString() }
if ($Iterations -ne 1000) { $args += "--iterations"; $args += $Iterations.ToString() }
if ($Memory -ne 500) { $args += "--memory"; $args += $Memory.ToString() }
if ($Cpu -ne 80) { $args += "--cpu"; $args += $Cpu.ToString() }

# If no test categories specified, run all
if ($args.Count -eq 0) {
    $args = @("--all")
}

# Check if .NET 8 is available
try {
    $dotnetVersion = dotnet --version
    Write-Host "OK .NET Version: $dotnetVersion" -ForegroundColor Green
} catch {
    Write-Host "ERROR .NET 8 is required but not found. Please install .NET 8 SDK." -ForegroundColor Red
    exit 1
}

# Navigate to the testing framework directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

Write-Host "Working Directory: $(Get-Location)" -ForegroundColor Yellow
Write-Host ""

# Build the testing framework
Write-Host "Building testing framework..." -ForegroundColor Yellow
try {
    dotnet build -c Release
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR Build failed!" -ForegroundColor Red
        exit 1
    }
    Write-Host "OK Build completed successfully" -ForegroundColor Green
} catch {
    Write-Host "ERROR Build failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""

# Run the tests
Write-Host "Running tests with arguments: $($args -join ' ')" -ForegroundColor Yellow
Write-Host ""

try {
    # Run the test runner
    dotnet run -c Release -- $args
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "OK All tests completed successfully!" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "ERROR Some tests failed. Check the detailed report above." -ForegroundColor Red
    }
} catch {
    Write-Host "ERROR Test execution failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Test execution completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White

# Find and display the report file
$desktopPath = [Environment]::GetFolderPath("Desktop")
$reportFiles = Get-ChildItem -Path $desktopPath -Filter "phagevirus_test_results_*.txt" | Sort-Object LastWriteTime -Descending

if ($reportFiles.Count -gt 0) {
    $latestReport = $reportFiles[0]
    Write-Host "Detailed test report saved to: $($latestReport.FullName)" -ForegroundColor Cyan
    
    # Ask if user wants to view the report
    Write-Host ""
    $viewReport = Read-Host "Would you like to view the detailed test report? (y/n)"
    if ($viewReport -eq 'y' -or $viewReport -eq 'Y') {
        Write-Host ""
        Write-Host "DETAILED TEST REPORT" -ForegroundColor Cyan
        Write-Host "-" * 50 -ForegroundColor Cyan
        Get-Content $latestReport.FullName | ForEach-Object {
            if ($_ -match "OK") {
                Write-Host $_ -ForegroundColor Green
            } elseif ($_ -match "ERROR") {
                Write-Host $_ -ForegroundColor Red
            } elseif ($_ -match "WARNING") {
                Write-Host $_ -ForegroundColor Yellow
            } elseif ($_ -match "CRITICAL") {
                Write-Host $_ -ForegroundColor Red
            } elseif ($_ -match "HIGH") {
                Write-Host $_ -ForegroundColor DarkYellow
            } elseif ($_ -match "MEDIUM") {
                Write-Host $_ -ForegroundColor Yellow
            } elseif ($_ -match "LOW") {
                Write-Host $_ -ForegroundColor Green
            } elseif ($_ -match "INFO|SUMMARY|DETAILS|ANALYSIS|METRICS|SECURITY") {
                Write-Host $_ -ForegroundColor Cyan
            } else {
                Write-Host $_
            }
        }
    }
} else {
    Write-Host "WARNING No test report file found on desktop" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Testing framework execution completed!" -ForegroundColor Green 
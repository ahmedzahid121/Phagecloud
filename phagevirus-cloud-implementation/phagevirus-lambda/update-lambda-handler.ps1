#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Update PhageVirus Lambda function handler and deploy correct code
    
.DESCRIPTION
    This script updates the Lambda function to use the correct handler
    and deploys the PhageVirus telemetry processing code.
#>

param(
    [string]$Region = "ap-southeast-2",
    [string]$FunctionName = "phagevirus-telemetry-processor"
)

Write-Host "🦠 Updating PhageVirus Lambda Function" -ForegroundColor Cyan
Write-Host "Function: $FunctionName" -ForegroundColor Yellow
Write-Host "Region: $Region" -ForegroundColor Yellow
Write-Host ""

# Build the correct PhageVirus Lambda function
Write-Host "Building PhageVirus Lambda function..." -ForegroundColor Green
try {
    dotnet build -c Release
    Write-Host "✅ Build completed" -ForegroundColor Green
} catch {
    Write-Host "❌ Build failed" -ForegroundColor Red
    exit 1
}

# Package the Lambda function
Write-Host "Packaging Lambda function..." -ForegroundColor Green
try {
    dotnet lambda package --output-package phagevirus-lambda.zip
    Write-Host "✅ Package created: phagevirus-lambda.zip" -ForegroundColor Green
} catch {
    Write-Host "❌ Package creation failed" -ForegroundColor Red
    exit 1
}

# Update the Lambda function code
Write-Host "Updating Lambda function code..." -ForegroundColor Green
try {
    aws lambda update-function-code `
        --function-name $FunctionName `
        --zip-file fileb://phagevirus-lambda.zip `
        --region $Region
    Write-Host "✅ Lambda function code updated" -ForegroundColor Green
} catch {
    Write-Host "❌ Lambda function code update failed" -ForegroundColor Red
    exit 1
}

# Update the Lambda function configuration
Write-Host "Updating Lambda function configuration..." -ForegroundColor Green
try {
    aws lambda update-function-configuration `
        --function-name $FunctionName `
        --handler "PhageVirusLambda::PhageVirus.Lambda.Function::FunctionHandler" `
        --runtime "dotnet8" `
        --timeout 30 `
        --memory-size 512 `
        --region $Region
    Write-Host "✅ Lambda function configuration updated" -ForegroundColor Green
} catch {
    Write-Host "❌ Lambda function configuration update failed" -ForegroundColor Red
    exit 1
}

# Wait for update to complete
Write-Host "Waiting for Lambda function update to complete..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Test the updated function
Write-Host "Testing updated Lambda function..." -ForegroundColor Green
try {
    aws lambda invoke `
        --function-name $FunctionName `
        --payload file://test-payload.json `
        --region $Region `
        response.json

    Write-Host "✅ Lambda function test completed" -ForegroundColor Green
    Write-Host "Response:" -ForegroundColor Yellow
    Get-Content response.json | Write-Host -ForegroundColor Cyan

    # Clean up test files
    Remove-Item "response.json" -ErrorAction SilentlyContinue
} catch {
    Write-Host "❌ Lambda function test failed" -ForegroundColor Red
}

Write-Host ""
Write-Host "🎉 PhageVirus Lambda Function Updated Successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Update Summary:" -ForegroundColor Cyan
Write-Host "  • Handler: PhageVirusLambda::PhageVirus.Lambda.Function::FunctionHandler" -ForegroundColor White
Write-Host "  • Runtime: .NET 8" -ForegroundColor White
Write-Host "  • Timeout: 30 seconds" -ForegroundColor White
Write-Host "  • Memory: 512 MB" -ForegroundColor White
Write-Host ""
Write-Host "📝 Next Steps:" -ForegroundColor Cyan
Write-Host "  1. Test the telemetry processing with your PhageVirus agents" -ForegroundColor White
Write-Host "  2. Monitor CloudWatch logs for any issues" -ForegroundColor White
Write-Host "  3. Check S3, DynamoDB, and CloudWatch for data storage" -ForegroundColor White
Write-Host "" 
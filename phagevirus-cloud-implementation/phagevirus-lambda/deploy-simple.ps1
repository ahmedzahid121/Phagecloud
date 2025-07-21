# Simple PhageVirus Lambda Deployment Script
Write-Host "🚀 Deploying PhageVirus Lambda Function..." -ForegroundColor Cyan

# Add AWS CLI to PATH
$env:PATH += ";C:\Program Files\Amazon\AWSCLIV2"

# Check if deployment package exists
if (-not (Test-Path "PhageVirusLambda.zip")) {
    Write-Host "❌ Error: PhageVirusLambda.zip not found!" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Deployment package found" -ForegroundColor Green

# Update existing function (assuming it exists)
Write-Host "🔄 Updating Lambda function code..." -ForegroundColor Yellow
aws lambda update-function-code --function-name phagevirus-telemetry-processor --zip-file fileb://PhageVirusLambda.zip --region ap-southeast-2

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Lambda function code updated successfully!" -ForegroundColor Green
    
    # Update configuration
    Write-Host "⚙️  Updating function configuration..." -ForegroundColor Yellow
    aws lambda update-function-configuration --function-name phagevirus-telemetry-processor --runtime dotnet8 --handler "PhageVirusLambda::PhageVirus.Lambda.Function::FunctionHandler" --timeout 30 --memory-size 512 --region ap-southeast-2
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Lambda function configuration updated!" -ForegroundColor Green
    }
} else {
    Write-Host "❌ Failed to update Lambda function" -ForegroundColor Red
    exit 1
}

Write-Host "🎉 Deployment Complete!" -ForegroundColor Green 
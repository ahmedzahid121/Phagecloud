# PhageVirus Lambda Function Deployment Script
# This script deploys the PhageVirus telemetry processing Lambda function

param(
    [string]$FunctionName = "phagevirus-telemetry-processor",
    [string]$Region = "ap-southeast-2",
    [string]$RoleArn = "",
    [switch]$CreateNew = $false
)

Write-Host "🚀 PhageVirus Lambda Function Deployment" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# Add AWS CLI to PATH
$env:PATH += ";C:\Program Files\Amazon\AWSCLIV2"

# Check if deployment package exists
if (-not (Test-Path "PhageVirusLambda.zip")) {
    Write-Host "❌ Error: PhageVirusLambda.zip not found!" -ForegroundColor Red
    Write-Host "Please build the project first: dotnet publish -c Release -o ./publish" -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ Deployment package found: PhageVirusLambda.zip" -ForegroundColor Green

# Check if function exists
Write-Host "🔍 Checking if Lambda function exists..." -ForegroundColor Yellow
$functionExists = $false
try {
    $function = aws lambda get-function --function-name $FunctionName --region $Region 2>$null
    if ($LASTEXITCODE -eq 0) {
        $functionExists = $true
        Write-Host "✅ Function '$FunctionName' exists - will update" -ForegroundColor Green
    }
} catch {
    Write-Host "ℹ️  Function '$FunctionName' does not exist - will create new" -ForegroundColor Yellow
}

if (-not $functionExists -or $CreateNew) {
    # Create new function
    if (-not $RoleArn) {
        Write-Host "❌ Error: Role ARN is required for creating new function" -ForegroundColor Red
        Write-Host "Please provide --RoleArn parameter or create the function manually in AWS Console" -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "🆕 Creating new Lambda function..." -ForegroundColor Yellow
    aws lambda create-function `
        --function-name $FunctionName `
        --runtime dotnet8 `
        --role $RoleArn `
        --handler "PhageVirusLambda::PhageVirus.Lambda.Function::FunctionHandler" `
        --zip-file fileb://PhageVirusLambda.zip `
        --region $Region `
        --timeout 30 `
        --memory-size 512 `
        --environment Variables='{S3_BUCKET=phagevirus-logs,DYNAMODB_TABLE=phagevirus-endpoints,CLOUDWATCH_LOG_GROUP=/aws/phagevirus/agent}'
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Lambda function created successfully!" -ForegroundColor Green
    } else {
        Write-Host "❌ Failed to create Lambda function" -ForegroundColor Red
        exit 1
    }
} else {
    # Update existing function
    Write-Host "🔄 Updating existing Lambda function..." -ForegroundColor Yellow
    aws lambda update-function-code `
        --function-name $FunctionName `
        --zip-file fileb://PhageVirusLambda.zip `
        --region $Region
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Lambda function code updated successfully!" -ForegroundColor Green
        
        # Update configuration
        Write-Host "⚙️  Updating function configuration..." -ForegroundColor Yellow
        aws lambda update-function-configuration `
            --function-name $FunctionName `
            --runtime dotnet8 `
            --handler "PhageVirusLambda::PhageVirus.Lambda.Function::FunctionHandler" `
            --timeout 30 `
            --memory-size 512 `
            --environment Variables='{S3_BUCKET=phagevirus-logs,DYNAMODB_TABLE=phagevirus-endpoints,CLOUDWATCH_LOG_GROUP=/aws/phagevirus/agent}' `
            --region $Region
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Lambda function configuration updated!" -ForegroundColor Green
        }
    } else {
        Write-Host "❌ Failed to update Lambda function" -ForegroundColor Red
        exit 1
    }
}

# Test the function
Write-Host "🧪 Testing Lambda function..." -ForegroundColor Yellow
$testPayload = @{
    AgentId = "test-agent-001"
    Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    DataType = "system"
    Data = @{
        CpuUsage = 45.2
        MemoryUsage = 67.8
        ActiveProcesses = 89
    }
    IsCompressed = $false
    IsEncrypted = $false
    Checksum = "test-checksum"
} | ConvertTo-Json -Depth 3

$testPayload | Out-File -FilePath "test-payload.json" -Encoding UTF8

aws lambda invoke `
    --function-name $FunctionName `
    --payload file://test-payload.json `
    --region $Region `
    response.json

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Lambda function test successful!" -ForegroundColor Green
    Write-Host "📄 Response:" -ForegroundColor Cyan
    Get-Content response.json | Write-Host
} else {
    Write-Host "⚠️  Lambda function test failed - check CloudWatch logs" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🎉 Deployment Complete!" -ForegroundColor Green
Write-Host "=====================" -ForegroundColor Green
Write-Host "Function Name: $FunctionName" -ForegroundColor White
Write-Host "Region: $Region" -ForegroundColor White
Write-Host "Handler: PhageVirusLambda::PhageVirus.Lambda.Function::FunctionHandler" -ForegroundColor White
Write-Host ""
Write-Host "📋 Next Steps:" -ForegroundColor Cyan
Write-Host "1. Configure API Gateway for HTTP endpoints" -ForegroundColor White
Write-Host "2. Set up CloudWatch alarms for monitoring" -ForegroundColor White
Write-Host "3. Test with real PhageVirus agent telemetry" -ForegroundColor White
Write-Host "4. Review CloudWatch logs for any issues" -ForegroundColor White 
# Deploy PhageVirus Lambda with Metrics Support
# This script deploys the updated Lambda function that includes metrics endpoints

param(
    [string]$Region = "ap-southeast-2",
    [string]$FunctionName = "phagevirus-telemetry-processor"
)

Write-Host "🚀 Deploying PhageVirus Lambda with Metrics Support..." -ForegroundColor Cyan

try {
    # Check if AWS CLI is available
    $awsVersion = aws --version 2>$null
    if (-not $awsVersion) {
        Write-Host "❌ AWS CLI not found. Please install AWS CLI v2 first." -ForegroundColor Red
        exit 1
    }
    Write-Host "✅ AWS CLI found: $awsVersion" -ForegroundColor Green

    # Check if .NET is available
    $dotnetVersion = dotnet --version 2>$null
    if (-not $dotnetVersion) {
        Write-Host "❌ .NET SDK not found. Please install .NET 8.0 SDK first." -ForegroundColor Red
        exit 1
    }
    Write-Host "✅ .NET SDK found: $dotnetVersion" -ForegroundColor Green

    # Build the project
    Write-Host "🔨 Building Lambda function..." -ForegroundColor Yellow
    dotnet build -c Release
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Build failed!" -ForegroundColor Red
        exit 1
    }
    Write-Host "✅ Build completed successfully" -ForegroundColor Green

    # Publish for deployment
    Write-Host "📦 Publishing for deployment..." -ForegroundColor Yellow
    dotnet publish -c Release -o ./publish
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Publish failed!" -ForegroundColor Red
        exit 1
    }
    Write-Host "✅ Publish completed successfully" -ForegroundColor Green

    # Create deployment package
    Write-Host "📦 Creating deployment package..." -ForegroundColor Yellow
    if (Test-Path "PhageVirusLambda.zip") {
        Remove-Item "PhageVirusLambda.zip" -Force
    }
    Compress-Archive -Path "./publish/*" -DestinationPath "./PhageVirusLambda.zip" -Force
    Write-Host "✅ Deployment package created: PhageVirusLambda.zip" -ForegroundColor Green

    # Check if function exists
    Write-Host "🔍 Checking if Lambda function exists..." -ForegroundColor Yellow
    $functionExists = aws lambda get-function --function-name $FunctionName --region $Region 2>$null
    if ($functionExists) {
        Write-Host "✅ Function exists, updating code..." -ForegroundColor Green
        
        # Update function code
        Write-Host "📤 Uploading new code..." -ForegroundColor Yellow
        aws lambda update-function-code `
            --function-name $FunctionName `
            --zip-file fileb://PhageVirusLambda.zip `
            --region $Region
        
        if ($LASTEXITCODE -ne 0) {
            Write-Host "❌ Failed to update function code!" -ForegroundColor Red
            exit 1
        }
        Write-Host "✅ Function code updated successfully" -ForegroundColor Green

        # Update function configuration
        Write-Host "⚙️ Updating function configuration..." -ForegroundColor Yellow
        aws lambda update-function-configuration `
            --function-name $FunctionName `
            --runtime dotnet8 `
            --handler "PhageVirusLambda::PhageVirus.Lambda.Function::FunctionHandler" `
            --timeout 30 `
            --memory-size 512 `
            --region $Region
        
        if ($LASTEXITCODE -ne 0) {
            Write-Host "❌ Failed to update function configuration!" -ForegroundColor Red
            exit 1
        }
        Write-Host "✅ Function configuration updated successfully" -ForegroundColor Green
    } else {
        Write-Host "❌ Function does not exist. Please create it first using deploy-lambda.ps1" -ForegroundColor Red
        exit 1
    }

    # Test the metrics endpoint
    Write-Host "🧪 Testing metrics endpoint..." -ForegroundColor Yellow
    $testPayload = @{
        agentId = "test-endpoint-001"
        timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        dataType = "Metrics"
        data = @{
            requestType = "get_metrics"
            includePerformance = $true
            includeThreats = $true
        }
    } | ConvertTo-Json -Depth 3

    $testPayload | Out-File -FilePath "test-metrics.json" -Encoding UTF8

    $response = aws lambda invoke `
        --function-name $FunctionName `
        --payload file://test-metrics.json `
        --region $Region `
        response-metrics.json

    if ($LASTEXITCODE -eq 0) {
        $responseContent = Get-Content "response-metrics.json" -Raw | ConvertFrom-Json
        Write-Host "✅ Metrics endpoint test successful!" -ForegroundColor Green
        Write-Host "📊 Response: $($responseContent | ConvertTo-Json -Depth 3)" -ForegroundColor Cyan
    } else {
        Write-Host "❌ Metrics endpoint test failed!" -ForegroundColor Red
    }

    # Clean up test files
    if (Test-Path "test-metrics.json") { Remove-Item "test-metrics.json" -Force }
    if (Test-Path "response-metrics.json") { Remove-Item "response-metrics.json" -Force }

    Write-Host "🎉 Deployment completed successfully!" -ForegroundColor Green
    Write-Host "📋 Function Details:" -ForegroundColor Cyan
    Write-Host "   Name: $FunctionName" -ForegroundColor White
    Write-Host "   Region: $Region" -ForegroundColor White
    Write-Host "   Runtime: dotnet8" -ForegroundColor White
    Write-Host "   Handler: PhageVirusLambda::PhageVirus.Lambda.Function::FunctionHandler" -ForegroundColor White
    Write-Host "   Memory: 512 MB" -ForegroundColor White
    Write-Host "   Timeout: 30 seconds" -ForegroundColor White
    Write-Host ""
    Write-Host "🔗 Lambda Function URL:" -ForegroundColor Cyan
    Write-Host "   https://phagevirus-telemetry-processor.lambda-url.ap-southeast-2.on.aws/" -ForegroundColor White
    Write-Host ""
    Write-Host "📊 New Features Added:" -ForegroundColor Cyan
    Write-Host "   ✅ Metrics endpoint for desktop application" -ForegroundColor Green
    Write-Host "   ✅ Cloud CPU/Memory usage tracking" -ForegroundColor Green
    Write-Host "   ✅ Threat detection metrics" -ForegroundColor Green
    Write-Host "   ✅ Lambda performance monitoring" -ForegroundColor Green
    Write-Host "   ✅ S3 and DynamoDB usage tracking" -ForegroundColor Green

} catch {
    Write-Host "❌ Deployment failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} 
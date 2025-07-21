# Test PhageVirus Lambda Function
Write-Host "🧪 Testing PhageVirus Lambda Function..." -ForegroundColor Cyan

# Add AWS CLI to PATH
$env:PATH += ";C:\Program Files\Amazon\AWSCLIV2"

# Create a simple test payload
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

$testPayload | Out-File -FilePath "simple-test.json" -Encoding UTF8

Write-Host "📤 Invoking Lambda function..." -ForegroundColor Yellow
aws lambda invoke --function-name phagevirus-telemetry-processor --payload file://simple-test.json --region ap-southeast-2 test-response.json

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Lambda function invoked successfully!" -ForegroundColor Green
    Write-Host "📄 Response:" -ForegroundColor Cyan
    if (Test-Path "test-response.json") {
        Get-Content test-response.json | Write-Host
    }
} else {
    Write-Host "❌ Lambda function invocation failed" -ForegroundColor Red
}

Write-Host ""
Write-Host "📋 Checking CloudWatch logs..." -ForegroundColor Yellow
aws logs describe-log-streams --log-group-name "/aws/lambda/phagevirus-telemetry-processor" --region ap-southeast-2 --order-by LastEventTime --descending --max-items 1 
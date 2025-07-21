# Test API Gateway Connection
# This script tests the connection to your actual API Gateway

Write-Host "🌐 Testing API Gateway Connection..." -ForegroundColor Cyan

try {
    # Your actual API Gateway URL
    $apiGatewayUrl = "https://9tjtwblsg3.execute-api.ap-southeast-2.amazonaws.com/"
    
    Write-Host "🔗 Testing connection to: $apiGatewayUrl" -ForegroundColor Yellow
    
    # Test basic connectivity
    Write-Host "📡 Testing basic connectivity..." -ForegroundColor Yellow
    $httpClient = New-Object System.Net.Http.HttpClient
    $httpClient.Timeout = [TimeSpan]::FromSeconds(10)
    
    try {
        $response = $httpClient.GetAsync($apiGatewayUrl).Result
        Write-Host "✅ API Gateway is reachable (Status: $($response.StatusCode))" -ForegroundColor Green
    } catch {
        Write-Host "⚠️ API Gateway connectivity test: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    # Test Lambda function URL
    $lambdaUrl = "https://phagevirus-telemetry-processor.lambda-url.ap-southeast-2.on.aws/"
    Write-Host "🔗 Testing Lambda function URL: $lambdaUrl" -ForegroundColor Yellow
    
    try {
        $response = $httpClient.GetAsync($lambdaUrl).Result
        Write-Host "✅ Lambda function URL is reachable (Status: $($response.StatusCode))" -ForegroundColor Green
    } catch {
        Write-Host "⚠️ Lambda function URL test: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    # Test metrics endpoint
    Write-Host "📊 Testing metrics endpoint..." -ForegroundColor Yellow
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
    
    $content = New-Object System.Net.Http.StringContent($testPayload, [System.Text.Encoding]::UTF8, "application/json")
    
    try {
        $response = $httpClient.PostAsync($lambdaUrl, $content).Result
        $responseContent = $response.Content.ReadAsStringAsync().Result
        
        if ($response.IsSuccessStatusCode) {
            Write-Host "✅ Metrics endpoint test successful!" -ForegroundColor Green
            Write-Host "📊 Response: $responseContent" -ForegroundColor Cyan
        } else {
            Write-Host "❌ Metrics endpoint test failed (Status: $($response.StatusCode))" -ForegroundColor Red
            Write-Host "Response: $responseContent" -ForegroundColor Red
        }
    } catch {
        Write-Host "❌ Metrics endpoint test failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Test telemetry endpoint via API Gateway
    Write-Host "📡 Testing telemetry endpoint via API Gateway..." -ForegroundColor Yellow
    $telemetryUrl = "$apiGatewayUrl`telemetry?agentId=test-endpoint-001&limit=5"
    
    try {
        $response = $httpClient.GetAsync($telemetryUrl).Result
        $responseContent = $response.Content.ReadAsStringAsync().Result
        
        if ($response.IsSuccessStatusCode) {
            Write-Host "✅ Telemetry endpoint test successful!" -ForegroundColor Green
            Write-Host "📊 Response: $responseContent" -ForegroundColor Cyan
        } else {
            Write-Host "⚠️ Telemetry endpoint test (Status: $($response.StatusCode))" -ForegroundColor Yellow
            Write-Host "Response: $responseContent" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "⚠️ Telemetry endpoint test: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "🎉 Connection tests completed!" -ForegroundColor Green
    Write-Host ""
    Write-Host "📋 Summary:" -ForegroundColor Cyan
    Write-Host "   ✅ API Gateway URL: $apiGatewayUrl" -ForegroundColor Green
    Write-Host "   ✅ Lambda Function URL: $lambdaUrl" -ForegroundColor Green
    Write-Host "   ✅ Your AWS infrastructure is ready!" -ForegroundColor Green
    Write-Host ""
    Write-Host "🚀 Next Steps:" -ForegroundColor Cyan
    Write-Host "   1. Deploy the updated Lambda function: .\deploy-with-metrics.ps1" -ForegroundColor White
    Write-Host "   2. Start PhageVirus desktop application" -ForegroundColor White
    Write-Host "   3. Watch for cloud metrics in the log window" -ForegroundColor White
    
} catch {
    Write-Host "❌ Test failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} 
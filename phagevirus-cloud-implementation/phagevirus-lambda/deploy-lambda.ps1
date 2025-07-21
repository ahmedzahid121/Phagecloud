#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Deploy PhageVirus Lambda function to AWS
    
.DESCRIPTION
    This script builds and deploys the PhageVirus telemetry processing Lambda function
    to AWS with all necessary IAM roles, policies, and configurations.
    
.PARAMETER Region
    AWS region (default: ap-southeast-2)
    
.PARAMETER FunctionName
    Lambda function name (default: phagevirus-telemetry-processor)
    
.PARAMETER S3Bucket
    S3 bucket for logs (default: phagevirus-logs)
    
.PARAMETER DynamoDBTable
    DynamoDB table name (default: phagevirus-endpoints)
    
.PARAMETER CloudWatchLogGroup
    CloudWatch log group (default: /aws/phagevirus/agent)
    
.EXAMPLE
    .\deploy-lambda.ps1
    
.EXAMPLE
    .\deploy-lambda.ps1 -Region us-east-1 -FunctionName my-phagevirus-lambda
#>

param(
    [string]$Region = "ap-southeast-2",
    [string]$FunctionName = "phagevirus-telemetry-processor",
    [string]$S3Bucket = "phagevirus-logs",
    [string]$DynamoDBTable = "phagevirus-endpoints",
    [string]$CloudWatchLogGroup = "/aws/phagevirus/agent"
)

# Set error action preference
$ErrorActionPreference = "Stop"

Write-Host "🦠 PhageVirus Lambda Deployment" -ForegroundColor Cyan
Write-Host "Region: $Region" -ForegroundColor Yellow
Write-Host "Function: $FunctionName" -ForegroundColor Yellow
Write-Host ""

# Check AWS CLI
Write-Host "Checking AWS CLI..." -ForegroundColor Green
try {
    $awsVersion = aws --version
    Write-Host "✅ AWS CLI found: $awsVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ AWS CLI not found. Please install AWS CLI first." -ForegroundColor Red
    exit 1
}

# Check .NET SDK
Write-Host "Checking .NET SDK..." -ForegroundColor Green
try {
    $dotnetVersion = dotnet --version
    Write-Host "✅ .NET SDK found: $dotnetVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ .NET SDK not found. Please install .NET 8.0 SDK first." -ForegroundColor Red
    exit 1
}

# Check AWS Lambda Tools
Write-Host "Checking AWS Lambda Tools..." -ForegroundColor Green
try {
    dotnet tool install -g Amazon.Lambda.Tools
    Write-Host "✅ AWS Lambda Tools installed" -ForegroundColor Green
} catch {
    Write-Host "ℹ️ AWS Lambda Tools already installed" -ForegroundColor Yellow
}

# Create IAM role and policies
Write-Host "Creating IAM role and policies..." -ForegroundColor Green

$roleName = "phagevirus-lambda-role"
$policyName = "phagevirus-lambda-policy"

# Create trust policy for Lambda
$trustPolicy = @{
    Version = "2012-10-17"
    Statement = @(
        @{
            Effect = "Allow"
            Principal = @{
                Service = "lambda.amazonaws.com"
            }
            Action = "sts:AssumeRole"
        }
    )
} | ConvertTo-Json -Depth 10

# Create IAM policy for Lambda permissions
$policyDocument = @{
    Version = "2012-10-17"
    Statement = @(
        @{
            Effect = "Allow"
            Action = @(
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            )
            Resource = "arn:aws:logs:$Region`:*:*"
        },
        @{
            Effect = "Allow"
            Action = @(
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:ListBucket"
            )
            Resource = @(
                "arn:aws:s3:::$S3Bucket",
                "arn:aws:s3:::$S3Bucket/*"
            )
        },
        @{
            Effect = "Allow"
            Action = @(
                "dynamodb:GetItem",
                "dynamodb:PutItem",
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:UpdateItem",
                "dynamodb:DeleteItem"
            )
            Resource = "arn:aws:dynamodb:$Region`:*:table/$DynamoDBTable"
        },
        @{
            Effect = "Allow"
            Action = @(
                "kinesis:GetRecords",
                "kinesis:GetShardIterator",
                "kinesis:DescribeStream",
                "kinesis:ListStreams"
            )
            Resource = "*"
        },
        @{
            Effect = "Allow"
            Action = @(
                "sqs:ReceiveMessage",
                "sqs:DeleteMessage",
                "sqs:GetQueueAttributes"
            )
            Resource = "*"
        }
    )
} | ConvertTo-Json -Depth 10

# Create IAM role
Write-Host "Creating IAM role: $roleName" -ForegroundColor Yellow
try {
    aws iam create-role --role-name $roleName --assume-role-policy-document $trustPolicy --region $Region
    Write-Host "✅ IAM role created" -ForegroundColor Green
} catch {
    Write-Host "ℹ️ IAM role already exists" -ForegroundColor Yellow
}

# Create IAM policy
Write-Host "Creating IAM policy: $policyName" -ForegroundColor Yellow
try {
    aws iam create-policy --policy-name $policyName --policy-document $policyDocument --region $Region
    Write-Host "✅ IAM policy created" -ForegroundColor Green
} catch {
    Write-Host "ℹ️ IAM policy already exists" -ForegroundColor Yellow
}

# Attach policy to role
Write-Host "Attaching policy to role..." -ForegroundColor Yellow
try {
    aws iam attach-role-policy --role-name $roleName --policy-arn "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/$policyName" --region $Region
    Write-Host "✅ Policy attached to role" -ForegroundColor Green
} catch {
    Write-Host "ℹ️ Policy already attached" -ForegroundColor Yellow
}

# Attach basic Lambda execution role
Write-Host "Attaching Lambda execution role..." -ForegroundColor Yellow
try {
    aws iam attach-role-policy --role-name $roleName --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole" --region $Region
    Write-Host "✅ Lambda execution role attached" -ForegroundColor Green
} catch {
    Write-Host "ℹ️ Lambda execution role already attached" -ForegroundColor Yellow
}

# Wait for IAM role to propagate
Write-Host "Waiting for IAM role to propagate..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Build the Lambda function
Write-Host "Building Lambda function..." -ForegroundColor Green
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

# Deploy the Lambda function
Write-Host "Deploying Lambda function..." -ForegroundColor Green
try {
    dotnet lambda deploy-function $FunctionName --function-role $roleName --region $Region
    Write-Host "✅ Lambda function deployed successfully" -ForegroundColor Green
} catch {
    Write-Host "❌ Lambda deployment failed" -ForegroundColor Red
    exit 1
}

# Configure Lambda environment variables
Write-Host "Configuring Lambda environment variables..." -ForegroundColor Green
try {
    aws lambda update-function-configuration `
        --function-name $FunctionName `
        --environment "Variables={AWS_REGION=$Region,S3_BUCKET=$S3Bucket,DYNAMODB_TABLE=$DynamoDBTable,CLOUDWATCH_LOG_GROUP=$CloudWatchLogGroup}" `
        --region $Region
    Write-Host "✅ Environment variables configured" -ForegroundColor Green
} catch {
    Write-Host "❌ Environment variable configuration failed" -ForegroundColor Red
}

# Test the Lambda function
Write-Host "Testing Lambda function..." -ForegroundColor Green
try {
    $testPayload = @{
        AgentId = "test-agent-001"
        Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        DataType = "System"
        Data = @{
            CpuUsage = 25.5
            MemoryUsage = 45.2
            ProcessCount = 150
        }
        IsCompressed = $false
        IsEncrypted = $false
        Checksum = "test-checksum"
    } | ConvertTo-Json -Depth 10

    $testPayload | Out-File -FilePath "test-payload.json" -Encoding UTF8

    aws lambda invoke `
        --function-name $FunctionName `
        --payload file://test-payload.json `
        --region $Region `
        response.json

    Write-Host "✅ Lambda function test completed" -ForegroundColor Green
    Write-Host "Response:" -ForegroundColor Yellow
    Get-Content response.json | Write-Host -ForegroundColor Cyan

    # Clean up test files
    Remove-Item "test-payload.json" -ErrorAction SilentlyContinue
    Remove-Item "response.json" -ErrorAction SilentlyContinue
} catch {
    Write-Host "❌ Lambda function test failed" -ForegroundColor Red
}

# Create API Gateway (optional)
Write-Host "Creating API Gateway..." -ForegroundColor Green
try {
    # Create REST API
    $apiName = "phagevirus-api"
    $apiId = aws apigateway create-rest-api --name $apiName --region $Region --query 'id' --output text
    
    # Get root resource ID
    $rootId = aws apigateway get-resources --rest-api-id $apiId --region $Region --query 'items[?path==`/`].id' --output text
    
    # Create resource
    $resourceId = aws apigateway create-resource --rest-api-id $apiId --parent-id $rootId --path-part "telemetry" --region $Region --query 'id' --output text
    
    # Create POST method
    aws apigateway put-method --rest-api-id $apiId --resource-id $resourceId --http-method POST --authorization-type NONE --region $Region
    
    # Create GET method
    aws apigateway put-method --rest-api-id $apiId --resource-id $resourceId --http-method GET --authorization-type NONE --region $Region
    
    # Set Lambda integration for POST
    aws apigateway put-integration --rest-api-id $apiId --resource-id $resourceId --http-method POST --type AWS_PROXY --integration-http-method POST --uri "arn:aws:apigateway:${Region}:lambda:path/2015-03-31/functions/arn:aws:lambda:${Region}:$(aws sts get-caller-identity --query Account --output text):function:$FunctionName/invocations" --region $Region
    
    # Set Lambda integration for GET
    aws apigateway put-integration --rest-api-id $apiId --resource-id $resourceId --http-method GET --type AWS_PROXY --integration-http-method POST --uri "arn:aws:apigateway:${Region}:lambda:path/2015-03-31/functions/arn:aws:lambda:${Region}:$(aws sts get-caller-identity --query Account --output text):function:$FunctionName/invocations" --region $Region
    
    # Deploy API
    aws apigateway create-deployment --rest-api-id $apiId --stage-name prod --region $Region
    
    $apiUrl = "https://$apiId.execute-api.$Region.amazonaws.com/prod/telemetry"
    Write-Host "✅ API Gateway created: $apiUrl" -ForegroundColor Green
    
    # Add Lambda permission for API Gateway
    aws lambda add-permission --function-name $FunctionName --statement-id apigateway-prod --action lambda:InvokeFunction --principal apigateway.amazonaws.com --source-arn "arn:aws:execute-api:${Region}:$(aws sts get-caller-identity --query Account --output text):$apiId/*/*/telemetry" --region $Region
    
} catch {
    Write-Host "❌ API Gateway creation failed" -ForegroundColor Red
}

Write-Host ""
Write-Host "🎉 PhageVirus Lambda Deployment Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Deployment Summary:" -ForegroundColor Cyan
Write-Host "  • Lambda Function: $FunctionName" -ForegroundColor White
Write-Host "  • Region: $Region" -ForegroundColor White
Write-Host "  • IAM Role: $roleName" -ForegroundColor White
Write-Host "  • S3 Bucket: $S3Bucket" -ForegroundColor White
Write-Host "  • DynamoDB Table: $DynamoDBTable" -ForegroundColor White
Write-Host "  • CloudWatch Log Group: $CloudWatchLogGroup" -ForegroundColor White
Write-Host ""
Write-Host "🔗 API Endpoint: $apiUrl" -ForegroundColor Yellow
Write-Host ""
Write-Host "📝 Next Steps:" -ForegroundColor Cyan
Write-Host "  1. Update your PhageVirus agent configuration with the API endpoint" -ForegroundColor White
Write-Host "  2. Test the telemetry flow from your agents" -ForegroundColor White
Write-Host "  3. Monitor CloudWatch logs for any issues" -ForegroundColor White
Write-Host "  4. Set up CloudWatch alarms for monitoring" -ForegroundColor White
Write-Host "" 
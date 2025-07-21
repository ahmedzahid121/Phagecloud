using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Amazon.Kinesis;
using Amazon.Kinesis.Model;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.Lambda;
using Amazon.Lambda.Model;
using Amazon.CloudWatchLogs;
using Amazon.CloudWatchLogs.Model;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using PhageVirus.Agent.Shared;

namespace PhageVirus.Agent.Cloud
{
    /// <summary>
    /// Primary AWS cloud communicator for PhageVirus agent
    /// Handles all AWS service interactions including S3, DynamoDB, Lambda, and CloudWatch Logs
    /// </summary>
    public class AWSCommunicator
    {
        private readonly ILogger<AWSCommunicator> _logger;
        private readonly IConfiguration _configuration;
        private readonly JsonSerializerOptions _jsonOptions;
        
        // AWS Service Clients
        private AmazonKinesisClient? _kinesisClient;
        private AmazonDynamoDBClient? _dynamoDbClient;
        private AmazonS3Client? _s3Client;
        private AmazonLambdaClient? _lambdaClient;
        private AmazonCloudWatchLogsClient? _cloudWatchLogsClient;
        
        // Configuration
        private string _region = "ap-southeast-2"; // Sydney region (closest to NZ)
        private string _kinesisStream = string.Empty;
        private string _dynamoDbTable = string.Empty;
        private string _s3Bucket = string.Empty;
        private string _lambdaFunction = string.Empty;
        private string _cloudWatchLogGroup = string.Empty;
        private string _apiGateway = string.Empty;
        
        public bool IsInitialized { get; private set; } = false;

        public AWSCommunicator(IConfiguration configuration, ILogger<AWSCommunicator> logger)
        {
            _configuration = configuration;
            _logger = logger;
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = false
            };
        }

        public async Task InitializeAsync()
        {
            try
            {
                _logger.LogInformation("Initializing AWS communicator for ap-southeast-2 region");

                // Load configuration
                _region = _configuration["cloud:aws:region"] ?? "ap-southeast-2";
                _kinesisStream = _configuration["cloud:aws:kinesis_stream"] ?? "phagevirus-telemetry";
                _dynamoDbTable = _configuration["cloud:aws:dynamodb_table"] ?? "phagevirus-endpoints";
                _s3Bucket = _configuration["cloud:aws:s3_bucket"] ?? "phagevirus-logs";
                _lambdaFunction = _configuration["cloud:aws:lambda_function"] ?? "phagevirus-telemetry-processor";
                _cloudWatchLogGroup = _configuration["cloud:aws:cloudwatch_log_group"] ?? "/aws/phagevirus/agent";
                _apiGateway = _configuration["cloud:aws:api_gateway"] ?? string.Empty;

                // Initialize AWS clients with Sydney region
                var awsConfig = new AmazonKinesisConfig
                {
                    RegionEndpoint = Amazon.RegionEndpoint.GetBySystemName(_region)
                };

                _kinesisClient = new AmazonKinesisClient(awsConfig);
                _dynamoDbClient = new AmazonDynamoDBClient(awsConfig);
                _s3Client = new AmazonS3Client(awsConfig);
                _lambdaClient = new AmazonLambdaClient(awsConfig);
                _cloudWatchLogsClient = new AmazonCloudWatchLogsClient(awsConfig);

                // Test connections
                await TestConnectionsAsync();

                IsInitialized = true;
                _logger.LogInformation("AWS communicator initialized successfully for ap-southeast-2");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize AWS communicator");
                throw;
            }
        }

        private async Task TestConnectionsAsync()
        {
            try
            {
                _logger.LogInformation("Testing AWS service connections...");

                // Test S3 (Primary storage)
                if (_s3Client != null)
                {
                    var headBucketRequest = new HeadBucketRequest
                    {
                        BucketName = _s3Bucket
                    };
                    await _s3Client.HeadBucketAsync(headBucketRequest);
                    _logger.LogInformation($"S3 bucket '{_s3Bucket}' connection successful");
                }

                // Test DynamoDB (Agent status and threat data)
                if (_dynamoDbClient != null)
                {
                    var describeTableRequest = new DescribeTableRequest
                    {
                        TableName = _dynamoDbTable
                    };
                    await _dynamoDbClient.DescribeTableAsync(describeTableRequest);
                    _logger.LogInformation($"DynamoDB table '{_dynamoDbTable}' connection successful");
                }

                // Test CloudWatch Logs (Logging and diagnostics)
                if (_cloudWatchLogsClient != null)
                {
                    var describeLogGroupsRequest = new DescribeLogGroupsRequest
                    {
                        LogGroupNamePrefix = _cloudWatchLogGroup
                    };
                    await _cloudWatchLogsClient.DescribeLogGroupsAsync(describeLogGroupsRequest);
                    _logger.LogInformation($"CloudWatch Logs group '{_cloudWatchLogGroup}' connection successful");
                }

                // Test Lambda (Telemetry processing and ML logic)
                if (_lambdaClient != null)
                {
                    var getFunctionRequest = new GetFunctionRequest
                    {
                        FunctionName = _lambdaFunction
                    };
                    await _lambdaClient.GetFunctionAsync(getFunctionRequest);
                    _logger.LogInformation($"Lambda function '{_lambdaFunction}' connection successful");
                }

                // Test Kinesis (if configured)
                if (_kinesisClient != null && !string.IsNullOrEmpty(_kinesisStream))
                {
                    var describeStreamRequest = new DescribeStreamRequest
                    {
                        StreamName = _kinesisStream
                    };
                    await _kinesisClient.DescribeStreamAsync(describeStreamRequest);
                    _logger.LogInformation($"Kinesis stream '{_kinesisStream}' connection successful");
                }

                _logger.LogInformation("All AWS service connections tested successfully");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "AWS connection test failed - some services may not be available");
                // Don't throw here - allow partial initialization
            }
        }

        public async Task SendHeartbeatAsync(HeartbeatData heartbeat)
        {
            if (!IsInitialized)
            {
                _logger.LogWarning("AWS communicator not initialized");
                return;
            }

            try
            {
                // Store heartbeat in DynamoDB
                await StoreEndpointDataAsync(heartbeat.AgentId, new Dictionary<string, object>
                {
                    ["Type"] = "Heartbeat",
                    ["Status"] = heartbeat.Status,
                    ["Mode"] = heartbeat.Mode,
                    ["Version"] = heartbeat.Version,
                    ["SystemInfo"] = heartbeat.SystemInfo
                });

                // Send to Lambda for processing
                if (_lambdaClient != null)
                {
                    await InvokeLambdaAsync("heartbeat", heartbeat);
                }

                _logger.LogDebug("Heartbeat sent to AWS services");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending heartbeat to AWS");
            }
        }

        public async Task SendTelemetryAsync(TelemetryData telemetry)
        {
            if (!IsInitialized)
            {
                _logger.LogWarning("AWS communicator not initialized");
                return;
            }

            try
            {
                // Store telemetry in S3
                await StoreTelemetryInS3Async(telemetry);

                // Send to Lambda for processing
                if (_lambdaClient != null)
                {
                    await InvokeLambdaAsync("telemetry", telemetry);
                }

                // Log to CloudWatch
                await LogToCloudWatchAsync(telemetry);

                _logger.LogDebug("Telemetry sent to AWS services");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending telemetry to AWS");
            }
        }

        public async Task StoreEndpointDataAsync(string agentId, Dictionary<string, object> data)
        {
            if (!IsInitialized || _dynamoDbClient == null)
            {
                _logger.LogWarning("AWS communicator not initialized");
                return;
            }

            try
            {
                var item = new Dictionary<string, AttributeValue>
                {
                    ["AgentId"] = new AttributeValue { S = agentId },
                    ["Timestamp"] = new AttributeValue { S = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") },
                    ["Data"] = new AttributeValue { S = JsonSerializer.Serialize(data, _jsonOptions) }
                };

                var putItemRequest = new PutItemRequest
                {
                    TableName = _dynamoDbTable,
                    Item = item
                };

                await _dynamoDbClient.PutItemAsync(putItemRequest);
                _logger.LogDebug("Endpoint data stored in DynamoDB");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error storing endpoint data in DynamoDB");
            }
        }

        public async Task StoreLogsAsync(string agentId, string logData)
        {
            if (!IsInitialized || _s3Client == null)
            {
                _logger.LogWarning("AWS communicator not initialized");
                return;
            }

            try
            {
                var key = $"logs/{agentId}/{DateTime.UtcNow:yyyy/MM/dd}/log_{DateTime.UtcNow:HHmmss}.json";
                var data = Encoding.UTF8.GetBytes(logData);

                var putObjectRequest = new PutObjectRequest
                {
                    BucketName = _s3Bucket,
                    Key = key,
                    InputStream = new System.IO.MemoryStream(data),
                    ContentType = "application/json"
                };

                await _s3Client.PutObjectAsync(putObjectRequest);
                _logger.LogDebug($"Logs stored in S3: {key}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error storing logs in AWS S3");
            }
        }

        public async Task StoreScanReportAsync(string agentId, string reportData, string reportType = "scan")
        {
            if (!IsInitialized || _s3Client == null)
            {
                _logger.LogWarning("AWS communicator not initialized");
                return;
            }

            try
            {
                var key = $"reports/{agentId}/{DateTime.UtcNow:yyyy/MM/dd}/{reportType}_{DateTime.UtcNow:HHmmss}.json";
                var data = Encoding.UTF8.GetBytes(reportData);

                var putObjectRequest = new PutObjectRequest
                {
                    BucketName = _s3Bucket,
                    Key = key,
                    InputStream = new System.IO.MemoryStream(data),
                    ContentType = "application/json"
                };

                await _s3Client.PutObjectAsync(putObjectRequest);
                _logger.LogDebug($"Scan report stored in S3: {key}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error storing scan report in AWS S3");
            }
        }

        private async Task StoreTelemetryInS3Async(TelemetryData telemetry)
        {
            if (_s3Client == null) return;

            try
            {
                var key = $"telemetry/{telemetry.AgentId}/{DateTime.UtcNow:yyyy/MM/dd}/telemetry_{DateTime.UtcNow:HHmmss}.json";
                var data = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(telemetry, _jsonOptions));

                var putObjectRequest = new PutObjectRequest
                {
                    BucketName = _s3Bucket,
                    Key = key,
                    InputStream = new System.IO.MemoryStream(data),
                    ContentType = "application/json"
                };

                await _s3Client.PutObjectAsync(putObjectRequest);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error storing telemetry in S3");
            }
        }

        private async Task InvokeLambdaAsync(string eventType, object payload)
        {
            if (_lambdaClient == null) return;

            try
            {
                var payloadJson = JsonSerializer.Serialize(new
                {
                    EventType = eventType,
                    Timestamp = DateTime.UtcNow,
                    Payload = payload
                }, _jsonOptions);

                var invokeRequest = new InvokeRequest
                {
                    FunctionName = _lambdaFunction,
                    Payload = payloadJson,
                    InvocationType = InvocationType.Event // Asynchronous
                };

                await _lambdaClient.InvokeAsync(invokeRequest);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error invoking Lambda function");
            }
        }

        private async Task LogToCloudWatchAsync(TelemetryData telemetry)
        {
            if (_cloudWatchLogsClient == null) return;

            try
            {
                var logStreamName = $"{telemetry.AgentId}/{DateTime.UtcNow:yyyy/MM/dd}";
                var logMessage = JsonSerializer.Serialize(telemetry, _jsonOptions);

                var putLogEventsRequest = new PutLogEventsRequest
                {
                    LogGroupName = _cloudWatchLogGroup,
                    LogStreamName = logStreamName,
                    LogEvents = new List<InputLogEvent>
                    {
                        new InputLogEvent
                        {
                            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            Message = logMessage
                        }
                    }
                };

                await _cloudWatchLogsClient.PutLogEventsAsync(putLogEventsRequest);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging to CloudWatch");
            }
        }

        public async Task<Dictionary<string, object>?> GetEndpointDataAsync(string agentId)
        {
            if (!IsInitialized || _dynamoDbClient == null)
            {
                _logger.LogWarning("AWS communicator not initialized");
                return null;
            }

            try
            {
                var queryRequest = new QueryRequest
                {
                    TableName = _dynamoDbTable,
                    KeyConditionExpression = "AgentId = :agentId",
                    ExpressionAttributeValues = new Dictionary<string, AttributeValue>
                    {
                        [":agentId"] = new AttributeValue { S = agentId }
                    },
                    ScanIndexForward = false,
                    Limit = 1
                };

                var response = await _dynamoDbClient.QueryAsync(queryRequest);

                if (response.Items.Count > 0)
                {
                    var item = response.Items[0];
                    if (item.ContainsKey("Data"))
                    {
                        var dataJson = item["Data"].S;
                        return JsonSerializer.Deserialize<Dictionary<string, object>>(dataJson, _jsonOptions);
                    }
                }

                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting endpoint data from DynamoDB");
                return null;
            }
        }

        public async Task<List<Dictionary<string, object>>> GetEndpointHistoryAsync(string agentId, int limit = 100)
        {
            if (!IsInitialized || _dynamoDbClient == null)
            {
                _logger.LogWarning("AWS communicator not initialized");
                return new List<Dictionary<string, object>>();
            }

            try
            {
                var queryRequest = new QueryRequest
                {
                    TableName = _dynamoDbTable,
                    KeyConditionExpression = "AgentId = :agentId",
                    ExpressionAttributeValues = new Dictionary<string, AttributeValue>
                    {
                        [":agentId"] = new AttributeValue { S = agentId }
                    },
                    ScanIndexForward = false,
                    Limit = limit
                };

                var response = await _dynamoDbClient.QueryAsync(queryRequest);
                var results = new List<Dictionary<string, object>>();

                foreach (var item in response.Items)
                {
                    if (item.ContainsKey("Data"))
                    {
                        var dataJson = item["Data"].S;
                        var data = JsonSerializer.Deserialize<Dictionary<string, object>>(dataJson, _jsonOptions);
                        if (data != null)
                        {
                            results.Add(data);
                        }
                    }
                }

                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting endpoint history from DynamoDB");
                return new List<Dictionary<string, object>>();
            }
        }

        public async Task<bool> SendBatchTelemetryAsync(List<TelemetryData> telemetryBatch)
        {
            if (!IsInitialized || telemetryBatch == null || telemetryBatch.Count == 0)
            {
                return false;
            }

            try
            {
                // Store batch in S3
                var batchKey = $"telemetry/batch/{DateTime.UtcNow:yyyy/MM/dd}/batch_{DateTime.UtcNow:HHmmss}.json";
                var batchData = JsonSerializer.Serialize(telemetryBatch, _jsonOptions);
                var data = Encoding.UTF8.GetBytes(batchData);

                if (_s3Client != null)
                {
                    var putObjectRequest = new PutObjectRequest
                    {
                        BucketName = _s3Bucket,
                        Key = batchKey,
                        InputStream = new System.IO.MemoryStream(data),
                        ContentType = "application/json"
                    };

                    await _s3Client.PutObjectAsync(putObjectRequest);
                }

                // Send to Lambda for batch processing
                if (_lambdaClient != null)
                {
                    await InvokeLambdaAsync("batch_telemetry", telemetryBatch);
                }

                _logger.LogDebug($"Batch telemetry sent: {telemetryBatch.Count} items");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending batch telemetry to AWS");
                return false;
            }
        }

        public void Dispose()
        {
            _kinesisClient?.Dispose();
            _dynamoDbClient?.Dispose();
            _s3Client?.Dispose();
            _lambdaClient?.Dispose();
            _cloudWatchLogsClient?.Dispose();
        }
    }
} 
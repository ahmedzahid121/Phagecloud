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
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using PhageVirus.Agent.Shared;

namespace PhageVirus.Agent.Cloud
{
    public class AWSCommunicator
    {
        private readonly ILogger<AWSCommunicator> _logger;
        private readonly IConfiguration _configuration;
        private readonly JsonSerializerOptions _jsonOptions;
        
        private AmazonKinesisClient? _kinesisClient;
        private AmazonDynamoDBClient? _dynamoDbClient;
        private AmazonS3Client? _s3Client;
        
        private string _region = string.Empty;
        private string _kinesisStream = string.Empty;
        private string _dynamoDbTable = string.Empty;
        private string _s3Bucket = string.Empty;
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
                _logger.LogInformation("Initializing AWS communicator");

                // Load configuration
                _region = _configuration["cloud:aws:region"] ?? "us-east-1";
                _kinesisStream = _configuration["cloud:aws:kinesis_stream"] ?? string.Empty;
                _dynamoDbTable = _configuration["cloud:aws:dynamodb_table"] ?? string.Empty;
                _s3Bucket = _configuration["cloud:aws:s3_bucket"] ?? string.Empty;
                _apiGateway = _configuration["cloud:aws:api_gateway"] ?? string.Empty;

                if (string.IsNullOrEmpty(_kinesisStream))
                {
                    throw new InvalidOperationException("AWS Kinesis stream not configured");
                }

                // Initialize AWS clients
                var awsConfig = new AmazonKinesisConfig
                {
                    RegionEndpoint = Amazon.RegionEndpoint.GetBySystemName(_region)
                };

                _kinesisClient = new AmazonKinesisClient(awsConfig);
                _dynamoDbClient = new AmazonDynamoDBClient(awsConfig);
                _s3Client = new AmazonS3Client(awsConfig);

                // Test connections
                await TestConnectionsAsync();

                IsInitialized = true;
                _logger.LogInformation("AWS communicator initialized successfully");
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
                // Test Kinesis
                if (_kinesisClient != null)
                {
                    var describeStreamRequest = new DescribeStreamRequest
                    {
                        StreamName = _kinesisStream
                    };
                    await _kinesisClient.DescribeStreamAsync(describeStreamRequest);
                }

                // Test DynamoDB
                if (_dynamoDbClient != null)
                {
                    var describeTableRequest = new DescribeTableRequest
                    {
                        TableName = _dynamoDbTable
                    };
                    await _dynamoDbClient.DescribeTableAsync(describeTableRequest);
                }

                // Test S3
                if (_s3Client != null)
                {
                    var headBucketRequest = new HeadBucketRequest
                    {
                        BucketName = _s3Bucket
                    };
                    await _s3Client.HeadBucketAsync(headBucketRequest);
                }

                _logger.LogInformation("AWS connections tested successfully");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "AWS connection test failed");
                throw;
            }
        }

        public async Task SendHeartbeatAsync(HeartbeatData heartbeat)
        {
            if (!IsInitialized || _kinesisClient == null)
            {
                _logger.LogWarning("AWS communicator not initialized");
                return;
            }

            try
            {
                var json = JsonSerializer.Serialize(heartbeat, _jsonOptions);
                var data = Encoding.UTF8.GetBytes(json);

                var putRecordRequest = new PutRecordRequest
                {
                    StreamName = _kinesisStream,
                    Data = new System.IO.MemoryStream(data),
                    PartitionKey = heartbeat.AgentId
                };

                await _kinesisClient.PutRecordAsync(putRecordRequest);
                _logger.LogDebug("Heartbeat sent to AWS Kinesis");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending heartbeat to AWS");
            }
        }

        public async Task SendTelemetryAsync(TelemetryData telemetry)
        {
            if (!IsInitialized || _kinesisClient == null)
            {
                _logger.LogWarning("AWS communicator not initialized");
                return;
            }

            try
            {
                var json = JsonSerializer.Serialize(telemetry, _jsonOptions);
                var data = Encoding.UTF8.GetBytes(json);

                var putRecordRequest = new PutRecordRequest
                {
                    StreamName = _kinesisStream,
                    Data = new System.IO.MemoryStream(data),
                    PartitionKey = telemetry.AgentId
                };

                await _kinesisClient.PutRecordAsync(putRecordRequest);
                _logger.LogDebug("Telemetry sent to AWS Kinesis");
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
                _logger.LogError(ex, "Error storing endpoint data in AWS");
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

        public async Task<Dictionary<string, object>?> GetEndpointDataAsync(string agentId)
        {
            if (!IsInitialized || _dynamoDbClient == null)
            {
                _logger.LogWarning("AWS communicator not initialized");
                return null;
            }

            try
            {
                var key = new Dictionary<string, AttributeValue>
                {
                    ["AgentId"] = new AttributeValue { S = agentId }
                };

                var getItemRequest = new GetItemRequest
                {
                    TableName = _dynamoDbTable,
                    Key = key
                };

                var response = await _dynamoDbClient.GetItemAsync(getItemRequest);

                if (response.Item != null && response.Item.ContainsKey("Data"))
                {
                    var dataJson = response.Item["Data"].S;
                    return JsonSerializer.Deserialize<Dictionary<string, object>>(dataJson, _jsonOptions);
                }

                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting endpoint data from AWS");
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
                _logger.LogError(ex, "Error getting endpoint history from AWS");
                return new List<Dictionary<string, object>>();
            }
        }

        public async Task<bool> SendBatchTelemetryAsync(List<TelemetryData> telemetryBatch)
        {
            if (!IsInitialized || _kinesisClient == null)
            {
                _logger.LogWarning("AWS communicator not initialized");
                return false;
            }

            try
            {
                var records = new List<PutRecordsRequestEntry>();

                foreach (var telemetry in telemetryBatch)
                {
                    var json = JsonSerializer.Serialize(telemetry, _jsonOptions);
                    var data = Encoding.UTF8.GetBytes(json);

                    records.Add(new PutRecordsRequestEntry
                    {
                        Data = new System.IO.MemoryStream(data),
                        PartitionKey = telemetry.AgentId
                    });
                }

                var putRecordsRequest = new PutRecordsRequest
                {
                    StreamName = _kinesisStream,
                    Records = records
                };

                var response = await _kinesisClient.PutRecordsAsync(putRecordsRequest);

                if (response.FailedRecordCount > 0)
                {
                    _logger.LogWarning($"Failed to send {response.FailedRecordCount} records to Kinesis");
                    return false;
                }

                _logger.LogDebug($"Successfully sent {records.Count} telemetry records to AWS Kinesis");
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
        }
    }
} 
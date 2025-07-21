using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.CloudWatchLogs;
using Amazon.CloudWatchLogs.Model;
using Amazon.Lambda.Core;
using Amazon.Lambda.KinesisEvents;
using Amazon.Lambda.SQSEvents;
using Amazon.Lambda.APIGatewayEvents;

namespace PhageVirus.Lambda
{
    /// <summary>
    /// AWS Lambda function for processing PhageVirus agent telemetry
    /// Handles data from S3, DynamoDB, CloudWatch, and Kinesis
    /// </summary>
    public class Function
    {
        private readonly IAmazonDynamoDB _dynamoDbClient;
        private readonly IAmazonS3 _s3Client;
        private readonly IAmazonCloudWatchLogs _cloudWatchClient;
        private readonly JsonSerializerOptions _jsonOptions;
        private readonly string _region = "ap-southeast-2";
        private readonly string _s3Bucket = "phagevirus-logs";
        private readonly string _dynamoDbTable = "phagevirus-endpoints";
        private readonly string _cloudWatchLogGroup = "/aws/phagevirus/agent";

        public Function()
        {
            _dynamoDbClient = new AmazonDynamoDBClient(Amazon.RegionEndpoint.GetBySystemName(_region));
            _s3Client = new AmazonS3Client(Amazon.RegionEndpoint.GetBySystemName(_region));
            _cloudWatchClient = new AmazonCloudWatchLogsClient(Amazon.RegionEndpoint.GetBySystemName(_region));
            
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = false
            };
        }

        /// <summary>
        /// Main Lambda function handler for telemetry processing
        /// </summary>
        [LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]
        public async Task<APIGatewayProxyResponse> FunctionHandler(APIGatewayProxyRequest request, ILambdaContext context)
        {
            try
            {
                context.Logger.LogInformation($"Processing telemetry request: {request.HttpMethod} {request.Path}");

                switch (request.HttpMethod.ToUpper())
                {
                    case "POST":
                        return await HandleTelemetryPost(request, context);
                    case "GET":
                        return await HandleTelemetryGet(request, context);
                    default:
                        return new APIGatewayProxyResponse
                        {
                            StatusCode = 405,
                            Body = JsonSerializer.Serialize(new { error = "Method not allowed" })
                        };
                }
            }
            catch (Exception ex)
            {
                context.Logger.LogError($"Error processing request: {ex.Message}");
                return new APIGatewayProxyResponse
                {
                    StatusCode = 500,
                    Body = JsonSerializer.Serialize(new { error = "Internal server error" })
                };
            }
        }

        /// <summary>
        /// Handle Kinesis stream events for real-time telemetry
        /// </summary>
        public async Task FunctionHandler(KinesisEvent kinesisEvent, ILambdaContext context)
        {
            context.Logger.LogInformation($"Processing {kinesisEvent.Records.Count} Kinesis records");

            foreach (var record in kinesisEvent.Records)
            {
                try
                {
                    var telemetryData = JsonSerializer.Deserialize<TelemetryData>(
                        Encoding.UTF8.GetString(record.Kinesis.Data.ToArray()), _jsonOptions);

                    if (telemetryData != null)
                    {
                        await ProcessTelemetryData(telemetryData, context);
                    }
                }
                catch (Exception ex)
                {
                    context.Logger.LogError($"Error processing Kinesis record: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Handle SQS events for batch telemetry processing
        /// </summary>
        public async Task FunctionHandler(SQSEvent sqsEvent, ILambdaContext context)
        {
            context.Logger.LogInformation($"Processing {sqsEvent.Records.Count} SQS records");

            foreach (var record in sqsEvent.Records)
            {
                try
                {
                    var telemetryData = JsonSerializer.Deserialize<TelemetryData>(record.Body, _jsonOptions);

                    if (telemetryData != null)
                    {
                        await ProcessTelemetryData(telemetryData, context);
                    }
                }
                catch (Exception ex)
                {
                    context.Logger.LogError($"Error processing SQS record: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Handle POST requests for telemetry data
        /// </summary>
        private async Task<APIGatewayProxyResponse> HandleTelemetryPost(APIGatewayProxyRequest request, ILambdaContext context)
        {
            try
            {
                var telemetryData = JsonSerializer.Deserialize<TelemetryData>(request.Body, _jsonOptions);

                if (telemetryData == null)
                {
                    return new APIGatewayProxyResponse
                    {
                        StatusCode = 400,
                        Body = JsonSerializer.Serialize(new { error = "Invalid telemetry data" })
                    };
                }

                // Check if this is a metrics request
                if (telemetryData.DataType == "Metrics" && 
                    telemetryData.Data.ContainsKey("requestType") && 
                    telemetryData.Data["requestType"].ToString() == "get_metrics")
                {
                    return await HandleMetricsRequest(telemetryData, context);
                }

                await ProcessTelemetryData(telemetryData, context);

                return new APIGatewayProxyResponse
                {
                    StatusCode = 200,
                    Body = JsonSerializer.Serialize(new { 
                        message = "Telemetry processed successfully",
                        analysisId = Guid.NewGuid().ToString()
                    })
                };
            }
            catch (Exception ex)
            {
                context.Logger.LogError($"Error processing telemetry POST: {ex.Message}");
                return new APIGatewayProxyResponse
                {
                    StatusCode = 500,
                    Body = JsonSerializer.Serialize(new { error = "Failed to process telemetry" })
                };
            }
        }

        /// <summary>
        /// Handle metrics requests from desktop application
        /// </summary>
        private async Task<APIGatewayProxyResponse> HandleMetricsRequest(TelemetryData request, ILambdaContext context)
        {
            try
            {
                context.Logger.LogInformation($"Processing metrics request for agent: {request.AgentId}");

                // Get Lambda function metrics
                var lambdaMetrics = await GetLambdaMetricsAsync(context);
                
                // Get DynamoDB metrics
                var dynamoDbMetrics = await GetDynamoDBMetricsAsync(request.AgentId, context);
                
                // Get S3 metrics
                var s3Metrics = await GetS3MetricsAsync(request.AgentId, context);
                
                // Get CloudWatch metrics
                var cloudWatchMetrics = await GetCloudWatchMetricsAsync(request.AgentId, context);

                var response = new
                {
                    cloudCpuUsage = lambdaMetrics.CpuUsage,
                    cloudMemoryUsage = lambdaMetrics.MemoryUsage,
                    lambdaInvocations = lambdaMetrics.InvocationCount,
                    lambdaDuration = lambdaMetrics.AverageDuration,
                    lambdaStatus = lambdaMetrics.Status,
                    threatsDetected = dynamoDbMetrics.ThreatsDetected,
                    threatsBlocked = dynamoDbMetrics.ThreatsBlocked,
                    telemetryProcessed = dynamoDbMetrics.TelemetryRecordsProcessed,
                    riskScore = dynamoDbMetrics.AverageRiskScore,
                    severity = dynamoDbMetrics.HighestSeverity,
                    s3StorageUsed = s3Metrics.StorageUsed,
                    s3ObjectsCount = s3Metrics.ObjectsCount,
                    cloudWatchLogsCount = cloudWatchMetrics.LogEventsCount,
                    lastUpdate = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
                };

                return new APIGatewayProxyResponse
                {
                    StatusCode = 200,
                    Body = JsonSerializer.Serialize(response, _jsonOptions)
                };
            }
            catch (Exception ex)
            {
                context.Logger.LogError($"Error processing metrics request: {ex.Message}");
                return new APIGatewayProxyResponse
                {
                    StatusCode = 500,
                    Body = JsonSerializer.Serialize(new { error = "Failed to get metrics" })
                };
            }
        }

        /// <summary>
        /// Handle GET requests for telemetry data
        /// </summary>
        private async Task<APIGatewayProxyResponse> HandleTelemetryGet(APIGatewayProxyRequest request, ILambdaContext context)
        {
            try
            {
                var agentId = request.QueryStringParameters?.ContainsKey("agentId") == true ? request.QueryStringParameters["agentId"] : null;
                var limitStr = request.QueryStringParameters?.ContainsKey("limit") == true ? request.QueryStringParameters["limit"] : "100";
                var limit = int.TryParse(limitStr, out var limitValue) ? limitValue : 100;

                if (string.IsNullOrEmpty(agentId))
                {
                    return new APIGatewayProxyResponse
                    {
                        StatusCode = 400,
                        Body = JsonSerializer.Serialize(new { error = "AgentId is required" })
                    };
                }

                var telemetryHistory = await GetTelemetryHistoryAsync(agentId, limit, context);

                return new APIGatewayProxyResponse
                {
                    StatusCode = 200,
                    Body = JsonSerializer.Serialize(telemetryHistory)
                };
            }
            catch (Exception ex)
            {
                context.Logger.LogError($"Error processing telemetry GET: {ex.Message}");
                return new APIGatewayProxyResponse
                {
                    StatusCode = 500,
                    Body = JsonSerializer.Serialize(new { error = "Failed to retrieve telemetry" })
                };
            }
        }

        /// <summary>
        /// Process telemetry data and store in AWS services
        /// </summary>
        private async Task ProcessTelemetryData(TelemetryData telemetryData, ILambdaContext context)
        {
            context.Logger.LogInformation($"Processing telemetry for agent: {telemetryData.AgentId}");

            // 1. Store in DynamoDB
            await StoreTelemetryInDynamoDBAsync(telemetryData, context);

            // 2. Store in S3
            await StoreTelemetryInS3Async(telemetryData, context);

            // 3. Log to CloudWatch
            await LogToCloudWatchAsync(telemetryData, context);

            // 4. Perform threat analysis
            var analysisResult = await PerformThreatAnalysisAsync(telemetryData, context);

            // 5. Store analysis results
            await StoreAnalysisResultsAsync(telemetryData.AgentId, analysisResult, context);

            context.Logger.LogInformation($"Telemetry processing completed for agent: {telemetryData.AgentId}");
        }

        /// <summary>
        /// Store telemetry data in DynamoDB
        /// </summary>
        private async Task StoreTelemetryInDynamoDBAsync(TelemetryData telemetryData, ILambdaContext context)
        {
            try
            {
                var item = new Dictionary<string, AttributeValue>
                {
                    ["AgentId"] = new AttributeValue { S = telemetryData.AgentId },
                    ["Timestamp"] = new AttributeValue { S = telemetryData.Timestamp.ToString("yyyy-MM-ddTHH:mm:ssZ") },
                    ["DataType"] = new AttributeValue { S = telemetryData.DataType },
                    ["Data"] = new AttributeValue { S = JsonSerializer.Serialize(telemetryData.Data, _jsonOptions) },
                    ["IsCompressed"] = new AttributeValue { BOOL = telemetryData.IsCompressed },
                    ["IsEncrypted"] = new AttributeValue { BOOL = telemetryData.IsEncrypted },
                    ["Checksum"] = new AttributeValue { S = telemetryData.Checksum },
                    ["ProcessingTimestamp"] = new AttributeValue { S = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") }
                };

                var putRequest = new PutItemRequest
                {
                    TableName = _dynamoDbTable,
                    Item = item
                };

                await _dynamoDbClient.PutItemAsync(putRequest);
                context.Logger.LogInformation($"Stored telemetry in DynamoDB for agent: {telemetryData.AgentId}");
            }
            catch (Exception ex)
            {
                context.Logger.LogError($"Error storing telemetry in DynamoDB: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Store telemetry data in S3
        /// </summary>
        private async Task StoreTelemetryInS3Async(TelemetryData telemetryData, ILambdaContext context)
        {
            try
            {
                var key = $"telemetry/{telemetryData.AgentId}/{telemetryData.Timestamp:yyyy/MM/dd}/{telemetryData.Timestamp:HHmmss}-{Guid.NewGuid()}.json";
                var jsonData = JsonSerializer.Serialize(telemetryData, _jsonOptions);

                var putRequest = new PutObjectRequest
                {
                    BucketName = _s3Bucket,
                    Key = key,
                    ContentBody = jsonData,
                    ContentType = "application/json",
                    Metadata =
                    {
                        ["AgentId"] = telemetryData.AgentId,
                        ["DataType"] = telemetryData.DataType,
                        ["Timestamp"] = telemetryData.Timestamp.ToString("yyyy-MM-ddTHH:mm:ssZ")
                    }
                };

                await _s3Client.PutObjectAsync(putRequest);
                context.Logger.LogInformation($"Stored telemetry in S3: {key}");
            }
            catch (Exception ex)
            {
                context.Logger.LogError($"Error storing telemetry in S3: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Log telemetry data to CloudWatch
        /// </summary>
        private async Task LogToCloudWatchAsync(TelemetryData telemetryData, ILambdaContext context)
        {
            try
            {
                var logStreamName = $"{telemetryData.AgentId}/{telemetryData.Timestamp:yyyy/MM/dd}";
                var logMessage = JsonSerializer.Serialize(new
                {
                    AgentId = telemetryData.AgentId,
                    DataType = telemetryData.DataType,
                    Timestamp = telemetryData.Timestamp,
                    Data = telemetryData.Data,
                    ProcessingTimestamp = DateTime.UtcNow
                }, _jsonOptions);

                var putLogRequest = new PutLogEventsRequest
                {
                    LogGroupName = _cloudWatchLogGroup,
                    LogStreamName = logStreamName,
                    LogEvents = new List<InputLogEvent>
                    {
                        new InputLogEvent
                        {
                            Timestamp = DateTime.UtcNow,
                            Message = logMessage
                        }
                    }
                };

                await _cloudWatchClient.PutLogEventsAsync(putLogRequest);
                context.Logger.LogInformation($"Logged telemetry to CloudWatch for agent: {telemetryData.AgentId}");
            }
            catch (Exception ex)
            {
                context.Logger.LogError($"Error logging to CloudWatch: {ex.Message}");
                // Don't throw here - CloudWatch logging is not critical
            }
        }

        /// <summary>
        /// Perform threat analysis on telemetry data (now supports all new modules)
        /// </summary>
        private Task<ThreatAnalysisResult> PerformThreatAnalysisAsync(TelemetryData telemetryData, ILambdaContext context)
        {
            try
            {
                ThreatAnalysisResult analysisResult;
                switch (telemetryData.DataType?.ToLower())
                {
                    case "iammisconfigdetector":
                        analysisResult = AnalyzeIAMMisconfig(telemetryData, context);
                        break;
                    case "serverlesscontainermonitor":
                        analysisResult = AnalyzeServerlessContainer(telemetryData, context);
                        break;
                    case "cspmscanner":
                        analysisResult = AnalyzeCSPM(telemetryData, context);
                        break;
                    case "cwppmonitor":
                        analysisResult = AnalyzeCWPP(telemetryData, context);
                        break;
                    case "cloudapithreatdetector":
                        analysisResult = AnalyzeCloudAPIThreat(telemetryData, context);
                        break;
                    case "iacscanner":
                        analysisResult = AnalyzeIaC(telemetryData, context);
                        break;
                    case "cloudmetricscollector":
                        analysisResult = AnalyzeCloudMetrics(telemetryData, context);
                        break;
                    case "admonitor":
                        analysisResult = AnalyzeAD(telemetryData, context);
                        break;
                    case "mfaanomalydetector":
                        analysisResult = AnalyzeMFAAnomaly(telemetryData, context);
                        break;
                    case "tokentheftdetector":
                        analysisResult = AnalyzeTokenTheft(telemetryData, context);
                        break;
                    case "itdr":
                        analysisResult = AnalyzeITDR(telemetryData, context);
                        break;
                    case "ransomwareprotection":
                        analysisResult = AnalyzeRansomware(telemetryData, context);
                        break;
                    case "deviceisolation":
                        analysisResult = AnalyzeDeviceIsolation(telemetryData, context);
                        break;
                    // Existing types
                    case "process":
                        analysisResult = new ThreatAnalysisResult
                        {
                            AnalysisId = Guid.NewGuid().ToString(),
                            Timestamp = DateTime.UtcNow,
                            RiskScore = AnalyzeProcessData(telemetryData.Data),
                            Confidence = CalculateConfidence(telemetryData),
                            DetectedPatterns = DetectThreatPatterns(telemetryData),
                            Recommendations = GenerateRecommendations(telemetryData),
                            AnalysisSource = "aws-lambda",
                            CalculatedSeverity = DetermineThreatSeverity(telemetryData),
                            RequiresImmediateAction = false,
                            AnalysisMetadata = new Dictionary<string, object>()
                        };
                        break;
                    case "memory":
                        analysisResult = new ThreatAnalysisResult
                        {
                            AnalysisId = Guid.NewGuid().ToString(),
                            Timestamp = DateTime.UtcNow,
                            RiskScore = AnalyzeMemoryData(telemetryData.Data),
                            Confidence = CalculateConfidence(telemetryData),
                            DetectedPatterns = DetectThreatPatterns(telemetryData),
                            Recommendations = GenerateRecommendations(telemetryData),
                            AnalysisSource = "aws-lambda",
                            CalculatedSeverity = DetermineThreatSeverity(telemetryData),
                            RequiresImmediateAction = false,
                            AnalysisMetadata = new Dictionary<string, object>()
                        };
                        break;
                    case "network":
                        analysisResult = new ThreatAnalysisResult
                        {
                            AnalysisId = Guid.NewGuid().ToString(),
                            Timestamp = DateTime.UtcNow,
                            RiskScore = AnalyzeNetworkData(telemetryData.Data),
                            Confidence = CalculateConfidence(telemetryData),
                            DetectedPatterns = DetectThreatPatterns(telemetryData),
                            Recommendations = GenerateRecommendations(telemetryData),
                            AnalysisSource = "aws-lambda",
                            CalculatedSeverity = DetermineThreatSeverity(telemetryData),
                            RequiresImmediateAction = false,
                            AnalysisMetadata = new Dictionary<string, object>()
                        };
                        break;
                    case "system":
                        analysisResult = new ThreatAnalysisResult
                        {
                            AnalysisId = Guid.NewGuid().ToString(),
                            Timestamp = DateTime.UtcNow,
                            RiskScore = AnalyzeSystemData(telemetryData.Data),
                            Confidence = CalculateConfidence(telemetryData),
                            DetectedPatterns = DetectThreatPatterns(telemetryData),
                            Recommendations = GenerateRecommendations(telemetryData),
                            AnalysisSource = "aws-lambda",
                            CalculatedSeverity = DetermineThreatSeverity(telemetryData),
                            RequiresImmediateAction = false,
                            AnalysisMetadata = new Dictionary<string, object>()
                        };
                        break;
                    default:
                        analysisResult = new ThreatAnalysisResult
                        {
                            AnalysisId = Guid.NewGuid().ToString(),
                            Timestamp = DateTime.UtcNow,
                            RiskScore = 0.0,
                            Confidence = 0.0,
                            DetectedPatterns = new List<string> { "Unknown DataType" },
                            Recommendations = new List<string> { "Review telemetry data manually" },
                            AnalysisSource = "aws-lambda",
                            CalculatedSeverity = ThreatSeverity.Info,
                            RequiresImmediateAction = false,
                            AnalysisMetadata = new Dictionary<string, object>()
                        };
                        break;
                }
                return Task.FromResult(analysisResult);
            }
            catch (Exception ex)
            {
                context.Logger.LogError($"Error performing threat analysis: {ex.Message}");
                return Task.FromResult(new ThreatAnalysisResult
                {
                    AnalysisId = Guid.NewGuid().ToString(),
                    Timestamp = DateTime.UtcNow,
                    RiskScore = 0.0,
                    Confidence = 0.0,
                    DetectedPatterns = new List<string> { "Analysis failed" },
                    Recommendations = new List<string> { "Review telemetry data manually" },
                    AnalysisSource = "aws-lambda",
                    CalculatedSeverity = ThreatSeverity.Low,
                    RequiresImmediateAction = false,
                    AnalysisMetadata = new Dictionary<string, object>()
                });
            }
        }

        // --- New analysis methods for each new module ---
        private ThreatAnalysisResult AnalyzeIAMMisconfig(TelemetryData telemetryData, ILambdaContext context)
        {
            // Example: parse alerts, risk score, recommendations from telemetryData.Data
            var risk = telemetryData.Data.TryGetValue("overall_risk_score", out var r) ? Convert.ToDouble(r) : 0.0;
            var alerts = telemetryData.Data.TryGetValue("alerts_summary", out var a) ? a.ToString() : "";
            return new ThreatAnalysisResult
            {
                AnalysisId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                RiskScore = risk,
                Confidence = 0.9,
                DetectedPatterns = new List<string> { "IAM Misconfiguration" },
                Recommendations = new List<string> { "Review IAM policies and restrict wildcards" },
                AnalysisSource = "aws-lambda",
                CalculatedSeverity = risk >= 0.8 ? ThreatSeverity.Critical : risk >= 0.6 ? ThreatSeverity.High : ThreatSeverity.Medium,
                RequiresImmediateAction = risk >= 0.8,
                AnalysisMetadata = new Dictionary<string, object> { ["alerts"] = alerts }
            };
        }
        private ThreatAnalysisResult AnalyzeServerlessContainer(TelemetryData telemetryData, ILambdaContext context)
        {
            var risk = telemetryData.Data.TryGetValue("overall_risk_score", out var r) ? Convert.ToDouble(r) : 0.0;
            var alerts = telemetryData.Data.TryGetValue("alerts_summary", out var a) ? a.ToString() : "";
            return new ThreatAnalysisResult
            {
                AnalysisId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                RiskScore = risk,
                Confidence = 0.9,
                DetectedPatterns = new List<string> { "Serverless/Container Issue" },
                Recommendations = new List<string> { "Review workload security configuration" },
                AnalysisSource = "aws-lambda",
                CalculatedSeverity = risk >= 0.8 ? ThreatSeverity.Critical : risk >= 0.6 ? ThreatSeverity.High : ThreatSeverity.Medium,
                RequiresImmediateAction = risk >= 0.8,
                AnalysisMetadata = new Dictionary<string, object> { ["alerts"] = alerts }
            };
        }
        private ThreatAnalysisResult AnalyzeCSPM(TelemetryData telemetryData, ILambdaContext context)
        {
            var risk = telemetryData.Data.TryGetValue("overall_risk_score", out var r) ? Convert.ToDouble(r) : 0.0;
            return new ThreatAnalysisResult
            {
                AnalysisId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                RiskScore = risk,
                Confidence = 0.9,
                DetectedPatterns = new List<string> { "CSPM Issue" },
                Recommendations = new List<string> { "Remediate cloud posture findings" },
                AnalysisSource = "aws-lambda",
                CalculatedSeverity = risk >= 0.8 ? ThreatSeverity.Critical : risk >= 0.6 ? ThreatSeverity.High : ThreatSeverity.Medium,
                RequiresImmediateAction = risk >= 0.8,
                AnalysisMetadata = new Dictionary<string, object>()
            };
        }
        private ThreatAnalysisResult AnalyzeCWPP(TelemetryData telemetryData, ILambdaContext context)
        {
            var risk = telemetryData.Data.TryGetValue("overall_risk_score", out var r) ? Convert.ToDouble(r) : 0.0;
            return new ThreatAnalysisResult
            {
                AnalysisId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                RiskScore = risk,
                Confidence = 0.9,
                DetectedPatterns = new List<string> { "CWPP Issue" },
                Recommendations = new List<string> { "Review workload protection findings" },
                AnalysisSource = "aws-lambda",
                CalculatedSeverity = risk >= 0.8 ? ThreatSeverity.Critical : risk >= 0.6 ? ThreatSeverity.High : ThreatSeverity.Medium,
                RequiresImmediateAction = risk >= 0.8,
                AnalysisMetadata = new Dictionary<string, object>()
            };
        }
        private ThreatAnalysisResult AnalyzeCloudAPIThreat(TelemetryData telemetryData, ILambdaContext context)
        {
            var risk = telemetryData.Data.TryGetValue("overall_risk_score", out var r) ? Convert.ToDouble(r) : 0.0;
            return new ThreatAnalysisResult
            {
                AnalysisId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                RiskScore = risk,
                Confidence = 0.9,
                DetectedPatterns = new List<string> { "Cloud API Threat" },
                Recommendations = new List<string> { "Investigate API anomalies" },
                AnalysisSource = "aws-lambda",
                CalculatedSeverity = risk >= 0.8 ? ThreatSeverity.Critical : risk >= 0.6 ? ThreatSeverity.High : ThreatSeverity.Medium,
                RequiresImmediateAction = risk >= 0.8,
                AnalysisMetadata = new Dictionary<string, object>()
            };
        }
        private ThreatAnalysisResult AnalyzeIaC(TelemetryData telemetryData, ILambdaContext context)
        {
            var risk = telemetryData.Data.TryGetValue("overall_risk_score", out var r) ? Convert.ToDouble(r) : 0.0;
            return new ThreatAnalysisResult
            {
                AnalysisId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                RiskScore = risk,
                Confidence = 0.9,
                DetectedPatterns = new List<string> { "IaC Misconfiguration" },
                Recommendations = new List<string> { "Fix IaC security issues" },
                AnalysisSource = "aws-lambda",
                CalculatedSeverity = risk >= 0.8 ? ThreatSeverity.Critical : risk >= 0.6 ? ThreatSeverity.High : ThreatSeverity.Medium,
                RequiresImmediateAction = risk >= 0.8,
                AnalysisMetadata = new Dictionary<string, object>()
            };
        }
        private ThreatAnalysisResult AnalyzeCloudMetrics(TelemetryData telemetryData, ILambdaContext context)
        {
            var health = telemetryData.Data.TryGetValue("overall_health_score", out var h) ? Convert.ToDouble(h) : 1.0;
            return new ThreatAnalysisResult
            {
                AnalysisId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                RiskScore = 1.0 - health / 100.0,
                Confidence = 0.9,
                DetectedPatterns = new List<string> { "Cloud Metrics" },
                Recommendations = new List<string> { "Review cloud metrics dashboard" },
                AnalysisSource = "aws-lambda",
                CalculatedSeverity = health < 80 ? ThreatSeverity.High : ThreatSeverity.Info,
                RequiresImmediateAction = health < 60,
                AnalysisMetadata = new Dictionary<string, object>()
            };
        }
        private ThreatAnalysisResult AnalyzeAD(TelemetryData telemetryData, ILambdaContext context)
        {
            var risk = telemetryData.Data.TryGetValue("overall_risk_score", out var r) ? Convert.ToDouble(r) : 0.0;
            return new ThreatAnalysisResult
            {
                AnalysisId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                RiskScore = risk,
                Confidence = 0.9,
                DetectedPatterns = new List<string> { "AD/Entra ID Anomaly" },
                Recommendations = new List<string> { "Investigate AD/Entra ID alerts" },
                AnalysisSource = "aws-lambda",
                CalculatedSeverity = risk >= 0.8 ? ThreatSeverity.Critical : risk >= 0.6 ? ThreatSeverity.High : ThreatSeverity.Medium,
                RequiresImmediateAction = risk >= 0.8,
                AnalysisMetadata = new Dictionary<string, object>()
            };
        }
        private ThreatAnalysisResult AnalyzeMFAAnomaly(TelemetryData telemetryData, ILambdaContext context)
        {
            var risk = telemetryData.Data.TryGetValue("overall_risk_score", out var r) ? Convert.ToDouble(r) : 0.0;
            return new ThreatAnalysisResult
            {
                AnalysisId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                RiskScore = risk,
                Confidence = 0.9,
                DetectedPatterns = new List<string> { "MFA/SSO Anomaly" },
                Recommendations = new List<string> { "Review MFA/SSO anomalies" },
                AnalysisSource = "aws-lambda",
                CalculatedSeverity = risk >= 0.8 ? ThreatSeverity.Critical : risk >= 0.6 ? ThreatSeverity.High : ThreatSeverity.Medium,
                RequiresImmediateAction = risk >= 0.8,
                AnalysisMetadata = new Dictionary<string, object>()
            };
        }
        private ThreatAnalysisResult AnalyzeTokenTheft(TelemetryData telemetryData, ILambdaContext context)
        {
            var risk = telemetryData.Data.TryGetValue("overall_risk_score", out var r) ? Convert.ToDouble(r) : 0.0;
            return new ThreatAnalysisResult
            {
                AnalysisId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                RiskScore = risk,
                Confidence = 0.9,
                DetectedPatterns = new List<string> { "Token Theft/Session Hijack" },
                Recommendations = new List<string> { "Investigate token/session anomalies" },
                AnalysisSource = "aws-lambda",
                CalculatedSeverity = risk >= 0.8 ? ThreatSeverity.Critical : risk >= 0.6 ? ThreatSeverity.High : ThreatSeverity.Medium,
                RequiresImmediateAction = risk >= 0.8,
                AnalysisMetadata = new Dictionary<string, object>()
            };
        }
        private ThreatAnalysisResult AnalyzeITDR(TelemetryData telemetryData, ILambdaContext context)
        {
            var risk = telemetryData.Data.TryGetValue("overall_risk_score", out var r) ? Convert.ToDouble(r) : 0.0;
            return new ThreatAnalysisResult
            {
                AnalysisId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                RiskScore = risk,
                Confidence = 0.9,
                DetectedPatterns = new List<string> { "Identity Threat" },
                Recommendations = new List<string> { "Review ITDR alerts and automate response" },
                AnalysisSource = "aws-lambda",
                CalculatedSeverity = risk >= 0.8 ? ThreatSeverity.Critical : risk >= 0.6 ? ThreatSeverity.High : ThreatSeverity.Medium,
                RequiresImmediateAction = risk >= 0.8,
                AnalysisMetadata = new Dictionary<string, object>()
            };
        }
        private ThreatAnalysisResult AnalyzeRansomware(TelemetryData telemetryData, ILambdaContext context)
        {
            var risk = telemetryData.Data.TryGetValue("risk_score", out var r) ? Convert.ToDouble(r) : 0.0;
            return new ThreatAnalysisResult
            {
                AnalysisId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                RiskScore = risk,
                Confidence = 0.9,
                DetectedPatterns = new List<string> { "Ransomware Activity" },
                Recommendations = new List<string> { "Isolate device, block process, restore from backup" },
                AnalysisSource = "aws-lambda",
                CalculatedSeverity = risk >= 0.8 ? ThreatSeverity.Critical : risk >= 0.6 ? ThreatSeverity.High : ThreatSeverity.Medium,
                RequiresImmediateAction = risk >= 0.8,
                AnalysisMetadata = new Dictionary<string, object>()
            };
        }
        private ThreatAnalysisResult AnalyzeDeviceIsolation(TelemetryData telemetryData, ILambdaContext context)
        {
            var risk = telemetryData.Data.TryGetValue("risk_score", out var r) ? Convert.ToDouble(r) : 0.0;
            return new ThreatAnalysisResult
            {
                AnalysisId = Guid.NewGuid().ToString(),
                Timestamp = DateTime.UtcNow,
                RiskScore = risk,
                Confidence = 0.9,
                DetectedPatterns = new List<string> { "Device Isolation" },
                Recommendations = new List<string> { "Confirm isolation, monitor for recovery" },
                AnalysisSource = "aws-lambda",
                CalculatedSeverity = risk >= 0.8 ? ThreatSeverity.Critical : risk >= 0.6 ? ThreatSeverity.High : ThreatSeverity.Medium,
                RequiresImmediateAction = risk >= 0.8,
                AnalysisMetadata = new Dictionary<string, object>()
            };
        }

        /// <summary>
        /// Calculate risk score based on telemetry data
        /// </summary>
        private double CalculateRiskScore(TelemetryData telemetryData)
        {
            var riskScore = 0.0;

            // Analyze data type
            switch (telemetryData.DataType?.ToLower())
            {
                case "process":
                    riskScore += AnalyzeProcessData(telemetryData.Data);
                    break;
                case "memory":
                    riskScore += AnalyzeMemoryData(telemetryData.Data);
                    break;
                case "network":
                    riskScore += AnalyzeNetworkData(telemetryData.Data);
                    break;
                case "system":
                    riskScore += AnalyzeSystemData(telemetryData.Data);
                    break;
            }

            // Check for suspicious patterns
            if (telemetryData.Data != null)
            {
                var dataJson = JsonSerializer.Serialize(telemetryData.Data);
                if (dataJson.Contains("suspicious") || dataJson.Contains("malicious") || dataJson.Contains("threat"))
                {
                    riskScore += 0.3;
                }
            }

            return Math.Min(riskScore, 1.0); // Cap at 1.0
        }

        /// <summary>
        /// Analyze process data for risk assessment
        /// </summary>
        private double AnalyzeProcessData(Dictionary<string, object> data)
        {
            var riskScore = 0.0;

            if (data.TryGetValue("SuspiciousProcesses", out var suspiciousCount) && 
                int.TryParse(suspiciousCount.ToString(), out var count))
            {
                riskScore += count * 0.1;
            }

            if (data.TryGetValue("HighCpuProcesses", out var highCpuCount) && 
                int.TryParse(highCpuCount.ToString(), out var cpuCount))
            {
                riskScore += cpuCount * 0.05;
            }

            return Math.Min(riskScore, 0.5);
        }

        /// <summary>
        /// Analyze memory data for risk assessment
        /// </summary>
        private double AnalyzeMemoryData(Dictionary<string, object> data)
        {
            var riskScore = 0.0;

            if (data.TryGetValue("SuspiciousRegions", out var suspiciousCount) && 
                int.TryParse(suspiciousCount.ToString(), out var count))
            {
                riskScore += count * 0.2;
            }

            if (data.TryGetValue("HighEntropyRegions", out var entropyCount) && 
                int.TryParse(entropyCount.ToString(), out var entropy))
            {
                riskScore += entropy * 0.1;
            }

            return Math.Min(riskScore, 0.5);
        }

        /// <summary>
        /// Analyze network data for risk assessment
        /// </summary>
        private double AnalyzeNetworkData(Dictionary<string, object> data)
        {
            var riskScore = 0.0;

            if (data.TryGetValue("SuspiciousConnections", out var suspiciousCount) && 
                int.TryParse(suspiciousCount.ToString(), out var count))
            {
                riskScore += count * 0.15;
            }

            return Math.Min(riskScore, 0.5);
        }

        /// <summary>
        /// Analyze system data for risk assessment
        /// </summary>
        private double AnalyzeSystemData(Dictionary<string, object> data)
        {
            var riskScore = 0.0;

            if (data.TryGetValue("CpuUsage", out var cpuUsage) && 
                double.TryParse(cpuUsage.ToString(), out var cpu))
            {
                if (cpu > 80) riskScore += 0.2;
                else if (cpu > 60) riskScore += 0.1;
            }

            if (data.TryGetValue("MemoryUsage", out var memoryUsage) && 
                double.TryParse(memoryUsage.ToString(), out var memory))
            {
                if (memory > 80) riskScore += 0.1;
            }

            return Math.Min(riskScore, 0.3);
        }

        /// <summary>
        /// Calculate confidence level in the analysis
        /// </summary>
        private double CalculateConfidence(TelemetryData telemetryData)
        {
            var confidence = 0.5; // Base confidence

            // Increase confidence based on data quality
            if (!string.IsNullOrEmpty(telemetryData.Checksum))
            {
                confidence += 0.2;
            }

            if (telemetryData.Data != null && telemetryData.Data.Count > 0)
            {
                confidence += 0.2;
            }

            if (telemetryData.Timestamp > DateTime.UtcNow.AddMinutes(-5))
            {
                confidence += 0.1;
            }

            return Math.Min(confidence, 1.0);
        }

        /// <summary>
        /// Detect threat patterns in telemetry data
        /// </summary>
        private List<string> DetectThreatPatterns(TelemetryData telemetryData)
        {
            var patterns = new List<string>();

            if (telemetryData.Data == null) return patterns;

            var dataJson = JsonSerializer.Serialize(telemetryData.Data);

            // Check for common threat patterns
            if (dataJson.Contains("powershell") && dataJson.Contains("-enc"))
            {
                patterns.Add("PowerShell encoded command execution");
            }

            if (dataJson.Contains("suspicious") || dataJson.Contains("malicious"))
            {
                patterns.Add("Suspicious activity detected");
            }

            if (dataJson.Contains("high entropy") || dataJson.Contains("HighEntropy"))
            {
                patterns.Add("High entropy memory regions");
            }

            if (dataJson.Contains("injection") || dataJson.Contains("Injection"))
            {
                patterns.Add("Code injection attempt");
            }

            return patterns;
        }

        /// <summary>
        /// Generate recommendations based on telemetry data
        /// </summary>
        private List<string> GenerateRecommendations(TelemetryData telemetryData)
        {
            var recommendations = new List<string>();

            if (telemetryData.Data == null) return recommendations;

            var dataJson = JsonSerializer.Serialize(telemetryData.Data);

            if (dataJson.Contains("suspicious"))
            {
                recommendations.Add("Investigate suspicious processes immediately");
                recommendations.Add("Review system logs for additional context");
            }

            if (dataJson.Contains("high entropy"))
            {
                recommendations.Add("Scan for packed or encrypted malware");
                recommendations.Add("Check for unauthorized code injection");
            }

            if (dataJson.Contains("network"))
            {
                recommendations.Add("Review network connections and firewall rules");
                recommendations.Add("Check for unauthorized outbound connections");
            }

            if (recommendations.Count == 0)
            {
                recommendations.Add("Continue monitoring system activity");
                recommendations.Add("Review telemetry data for trends");
            }

            return recommendations;
        }

        /// <summary>
        /// Determine threat severity level
        /// </summary>
        private ThreatSeverity DetermineThreatSeverity(TelemetryData telemetryData)
        {
            var riskScore = CalculateRiskScore(telemetryData);

            if (riskScore >= 0.8) return ThreatSeverity.Critical;
            if (riskScore >= 0.6) return ThreatSeverity.High;
            if (riskScore >= 0.4) return ThreatSeverity.Medium;
            if (riskScore >= 0.2) return ThreatSeverity.Low;
            return ThreatSeverity.Info;
        }

        /// <summary>
        /// Store analysis results in DynamoDB
        /// </summary>
        private async Task StoreAnalysisResultsAsync(string agentId, ThreatAnalysisResult analysisResult, ILambdaContext context)
        {
            try
            {
                var item = new Dictionary<string, AttributeValue>
                {
                    ["AgentId"] = new AttributeValue { S = agentId },
                    ["AnalysisId"] = new AttributeValue { S = analysisResult.AnalysisId },
                    ["Timestamp"] = new AttributeValue { S = analysisResult.Timestamp.ToString("yyyy-MM-ddTHH:mm:ssZ") },
                    ["RiskScore"] = new AttributeValue { N = analysisResult.RiskScore.ToString() },
                    ["Confidence"] = new AttributeValue { N = analysisResult.Confidence.ToString() },
                    ["Severity"] = new AttributeValue { S = analysisResult.CalculatedSeverity.ToString() },
                    ["RequiresImmediateAction"] = new AttributeValue { BOOL = analysisResult.RequiresImmediateAction },
                    ["DetectedPatterns"] = new AttributeValue { S = JsonSerializer.Serialize(analysisResult.DetectedPatterns, _jsonOptions) },
                    ["Recommendations"] = new AttributeValue { S = JsonSerializer.Serialize(analysisResult.Recommendations, _jsonOptions) },
                    ["AnalysisMetadata"] = new AttributeValue { S = JsonSerializer.Serialize(analysisResult.AnalysisMetadata, _jsonOptions) }
                };

                var putRequest = new PutItemRequest
                {
                    TableName = _dynamoDbTable,
                    Item = item
                };

                await _dynamoDbClient.PutItemAsync(putRequest);
                context.Logger.LogInformation($"Stored analysis results for agent: {agentId}");
            }
            catch (Exception ex)
            {
                context.Logger.LogError($"Error storing analysis results: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Get telemetry history for an agent
        /// </summary>
        private async Task<List<Dictionary<string, object>>> GetTelemetryHistoryAsync(string agentId, int limit, ILambdaContext context)
        {
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
                    ScanIndexForward = false, // Most recent first
                    Limit = limit
                };

                var response = await _dynamoDbClient.QueryAsync(queryRequest);
                var results = new List<Dictionary<string, object>>();

                foreach (var item in response.Items)
                {
                    var result = new Dictionary<string, object>();
                    foreach (var kvp in item)
                    {
                        if (kvp.Value.S != null) result[kvp.Key] = kvp.Value.S;
                        else if (kvp.Value.N != null) result[kvp.Key] = double.Parse(kvp.Value.N);
                        else if (kvp.Value.BOOL != null) result[kvp.Key] = kvp.Value.BOOL;
                    }
                    results.Add(result);
                }

                context.Logger.LogInformation($"Retrieved {results.Count} telemetry records for agent: {agentId}");
                return results;
            }
            catch (Exception ex)
            {
                context.Logger.LogError($"Error retrieving telemetry history: {ex.Message}");
                throw;
            }
        }

        // Metrics helper methods
        private async Task<LambdaMetrics> GetLambdaMetricsAsync(ILambdaContext context)
        {
            try
            {
                // For now, return simulated metrics since we don't have CloudWatch Metrics client
                // In a real implementation, you would use AmazonCloudWatchClient to get actual metrics
                return new LambdaMetrics
                {
                    CpuUsage = 15.5, // Simulated CPU usage percentage
                    MemoryUsage = 45.2, // Simulated memory usage percentage
                    InvocationCount = context.RemainingTime.TotalSeconds > 0 ? 1 : 0,
                    AverageDuration = 150.0, // milliseconds
                    Status = "Active"
                };
            }
            catch (Exception ex)
            {
                context.Logger.LogError($"Error getting Lambda metrics: {ex.Message}");
                return new LambdaMetrics();
            }
        }

        private async Task<DynamoDBMetrics> GetDynamoDBMetricsAsync(string agentId, ILambdaContext context)
        {
            try
            {
                var request = new QueryRequest
                {
                    TableName = _dynamoDbTable,
                    KeyConditionExpression = "AgentId = :agentId",
                    ExpressionAttributeValues = new Dictionary<string, AttributeValue>
                    {
                        { ":agentId", new AttributeValue { S = agentId } }
                    },
                    Select = Select.COUNT
                };

                var response = await _dynamoDbClient.QueryAsync(request);
                var totalRecords = response.Count;

                // Get threat-related records
                var threatRequest = new QueryRequest
                {
                    TableName = _dynamoDbTable,
                    KeyConditionExpression = "AgentId = :agentId",
                    FilterExpression = "contains(DataType, :threatType)",
                    ExpressionAttributeValues = new Dictionary<string, AttributeValue>
                    {
                        { ":agentId", new AttributeValue { S = agentId } },
                        { ":threatType", new AttributeValue { S = "Threat" } }
                    },
                    Select = Select.COUNT
                };

                var threatResponse = await _dynamoDbClient.QueryAsync(threatRequest);
                var threatCount = threatResponse.Count;

                return new DynamoDBMetrics
                {
                    TelemetryRecordsProcessed = totalRecords,
                    ThreatsDetected = threatCount,
                    ThreatsBlocked = threatCount > 0 ? threatCount - 1 : 0, // Simulated
                    AverageRiskScore = threatCount > 0 ? 65.5 : 0.0,
                    HighestSeverity = threatCount > 0 ? "Medium" : "Info"
                };
            }
            catch (Exception ex)
            {
                context.Logger.LogError($"Error getting DynamoDB metrics: {ex.Message}");
                return new DynamoDBMetrics();
            }
        }

        private async Task<S3Metrics> GetS3MetricsAsync(string agentId, ILambdaContext context)
        {
            try
            {
                var request = new ListObjectsV2Request
                {
                    BucketName = _s3Bucket,
                    Prefix = $"telemetry/{agentId}/"
                };

                var response = await _s3Client.ListObjectsV2Async(request);
                var objectsCount = response.S3Objects.Count;
                var storageUsed = response.S3Objects.Sum(obj => obj.Size);

                return new S3Metrics
                {
                    ObjectsCount = objectsCount,
                    StorageUsed = storageUsed
                };
            }
            catch (Exception ex)
            {
                context.Logger.LogError($"Error getting S3 metrics: {ex.Message}");
                return new S3Metrics();
            }
        }

        private async Task<CloudWatchMetrics> GetCloudWatchMetricsAsync(string agentId, ILambdaContext context)
        {
            try
            {
                // For now, return simulated metrics
                // In a real implementation, you would use CloudWatch client to get actual log metrics
                return new CloudWatchMetrics
                {
                    LogEventsCount = 150, // Simulated
                    LogStreamsCount = 5, // Simulated
                    LastLogTime = DateTime.UtcNow.AddMinutes(-5)
                };
            }
            catch (Exception ex)
            {
                context.Logger.LogError($"Error getting CloudWatch metrics: {ex.Message}");
                return new CloudWatchMetrics();
            }
        }
    }

    /// <summary>
    /// Data models for telemetry processing
    /// </summary>
    public class TelemetryData
    {
        public string AgentId { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string DataType { get; set; } = string.Empty;
        public Dictionary<string, object> Data { get; set; } = new();
        public bool IsCompressed { get; set; }
        public bool IsEncrypted { get; set; }
        public string Checksum { get; set; } = string.Empty;
    }

    public class ThreatAnalysisResult
    {
        public string AnalysisId { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public double RiskScore { get; set; }
        public double Confidence { get; set; }
        public List<string> DetectedPatterns { get; set; } = new();
        public List<string> Recommendations { get; set; } = new();
        public string AnalysisSource { get; set; } = string.Empty;
        public ThreatSeverity CalculatedSeverity { get; set; }
        public bool RequiresImmediateAction { get; set; }
        public Dictionary<string, object> AnalysisMetadata { get; set; } = new();
    }

    public enum ThreatSeverity
    {
        Info,
        Low,
        Medium,
        High,
        Critical
    }

    // Metrics data classes
    public class LambdaMetrics
    {
        public double CpuUsage { get; set; }
        public double MemoryUsage { get; set; }
        public int InvocationCount { get; set; }
        public double AverageDuration { get; set; }
        public string Status { get; set; } = "Unknown";
    }

    public class DynamoDBMetrics
    {
        public int TelemetryRecordsProcessed { get; set; }
        public int ThreatsDetected { get; set; }
        public int ThreatsBlocked { get; set; }
        public double AverageRiskScore { get; set; }
        public string HighestSeverity { get; set; } = "Info";
    }

    public class S3Metrics
    {
        public int ObjectsCount { get; set; }
        public long StorageUsed { get; set; }
    }

    public class CloudWatchMetrics
    {
        public int LogEventsCount { get; set; }
        public int LogStreamsCount { get; set; }
        public DateTime LastLogTime { get; set; }
    }
} 
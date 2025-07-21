using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Threading;
using System.Linq;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using PhageVirus.Modules.CloudSecurity;

namespace PhageVirus.Modules.IdentityProtection
{
    /// <summary>
    /// Comprehensive Token Theft and Session Hijacking Detection Module
    /// Monitors for suspicious token usage patterns and session hijacking attempts
    /// Provides real-time alerting for token-based security threats
    /// Offloads heavy analysis to AWS Lambda for scalable processing
    /// </summary>
    public class TokenTheftDetector
    {
        private static readonly object detectorLock = new object();
        private static bool isActive = false;
        private static Timer? detectionTimer;
        private static readonly ConcurrentDictionary<string, TokenSession> activeTokens = new();
        private static readonly List<TokenAlert> activeAlerts = new();
        
        // Configuration
        private static int detectionIntervalSeconds = 30;
        private static double criticalRiskThreshold = 0.8;
        private static double highRiskThreshold = 0.6;
        private static double mediumRiskThreshold = 0.4;
        
        // Token security thresholds
        private static int maxConcurrentTokens = 5;
        private static TimeSpan tokenLifetime = TimeSpan.FromHours(1);
        private static int maxFailedValidations = 3;
        private static double suspiciousLocationThreshold = 0.8;
        
        // Token types
        private static readonly string[] TokenTypes = {
            "JWT", "OAuth", "SAML", "Bearer", "Session", "Refresh", "Access"
        };
        
        // Suspicious patterns
        private static readonly string[] SuspiciousHeaders = {
            "x-forwarded-for", "x-real-ip", "x-client-ip", "cf-connecting-ip"
        };

        public class TokenSession
        {
            public string TokenId { get; set; } = "";
            public string TokenType { get; set; } = "";
            public string UserId { get; set; } = "";
            public string UserName { get; set; } = "";
            public string TokenHash { get; set; } = "";
            public string IpAddress { get; set; } = "";
            public string UserAgent { get; set; } = "";
            public string Location { get; set; } = "";
            public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
            public DateTime ExpiresAt { get; set; } = DateTime.UtcNow;
            public DateTime LastUsed { get; set; } = DateTime.UtcNow;
            public bool IsValid { get; set; } = true;
            public int UsageCount { get; set; } = 0;
            public List<string> UsedEndpoints { get; set; } = new();
            public Dictionary<string, object> Metadata { get; set; } = new();
        }

        public class TokenAlert
        {
            public string AlertId { get; set; } = Guid.NewGuid().ToString();
            public string TokenId { get; set; } = "";
            public string AlertType { get; set; } = "";
            public string Description { get; set; } = "";
            public ThreatLevel Severity { get; set; } = ThreatLevel.Medium;
            public double RiskScore { get; set; } = 0.0;
            public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
            public bool IsAcknowledged { get; set; } = false;
            public string? RemediationGuidance { get; set; }
            public Dictionary<string, object> Context { get; set; } = new();
        }

        public class TokenAnalysisResult
        {
            public bool Success { get; set; }
            public string Message { get; set; } = "";
            public List<TokenAlert> Alerts { get; set; } = new();
            public double OverallRiskScore { get; set; } = 0.0;
            public int TotalTokens { get; set; } = 0;
            public int CriticalThefts { get; set; } = 0;
            public int HighThefts { get; set; } = 0;
            public int MediumThefts { get; set; } = 0;
            public List<string> Recommendations { get; set; } = new();
            public Dictionary<string, object> Metrics { get; set; } = new();
        }

        /// <summary>
        /// Initialize the Token Theft Detector
        /// </summary>
        public static async Task InitializeAsync()
        {
            if (isActive) return;

            lock (detectorLock)
            {
                if (isActive) return;

                try
                {
                    EnhancedLogger.LogInfo("Initializing Token Theft Detector...");
                    
                    // Load configuration
                    LoadConfiguration();
                    
                    // Initialize token tracking
                    InitializeTokenTracking();
                    
                    // Start detection
                    StartDetection();
                    
                    isActive = true;
                    EnhancedLogger.LogSuccess("Token Theft Detector initialized successfully");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Failed to initialize Token Theft Detector: {ex.Message}");
                    throw;
                }
            }
        }

        /// <summary>
        /// Start detecting token theft and session hijacking
        /// </summary>
        public static async Task DetectTokenTheftAsync()
        {
            if (!isActive)
            {
                await InitializeAsync();
            }

            try
            {
                EnhancedLogger.LogInfo("Starting token theft and session hijacking detection...");
                
                // Perform initial comprehensive scan
                await PerformComprehensiveTokenScanAsync();
                
                // Start continuous detection
                await StartContinuousTokenDetectionAsync();
                
                EnhancedLogger.LogSuccess("Token theft detection started successfully");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start token theft detection: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Stop the token theft detector
        /// </summary>
        public static void StopDetection()
        {
            lock (detectorLock)
            {
                if (!isActive) return;

                try
                {
                    detectionTimer?.Dispose();
                    detectionTimer = null;
                    isActive = false;
                    
                    EnhancedLogger.LogInfo("Token Theft Detector stopped");
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Error stopping Token Theft Detector: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Perform comprehensive token theft detection scan
        /// </summary>
        public static async Task<TokenAnalysisResult> PerformComprehensiveTokenScanAsync()
        {
            var result = new TokenAnalysisResult();
            
            try
            {
                EnhancedLogger.LogInfo("Starting comprehensive token theft detection...");
                
                // Collect active tokens
                var activeTokens = await CollectActiveTokensAsync();
                
                // Analyze each token for theft indicators
                var analysisTasks = activeTokens.Select(token => AnalyzeTokenAsync(token));
                var analysisResults = await Task.WhenAll(analysisTasks);
                
                // Aggregate results
                foreach (var analysis in analysisResults)
                {
                    if (analysis != null)
                    {
                        result.Alerts.Add(analysis);
                        result.TotalTokens++;
                        
                        if (analysis.Severity == ThreatLevel.Critical)
                            result.CriticalThefts++;
                        else if (analysis.Severity == ThreatLevel.High)
                            result.HighThefts++;
                        else if (analysis.Severity == ThreatLevel.Medium)
                            result.MediumThefts++;
                    }
                }
                
                // Calculate overall risk score
                result.OverallRiskScore = result.Alerts.Any() ? 
                    result.Alerts.Average(a => a.RiskScore) : 0.0;
                
                // Generate recommendations
                result.Recommendations = GenerateTokenRecommendations(result.Alerts);
                
                // Send analysis to cloud for additional processing
                await SendTokenAnalysisToCloudAsync(result);
                
                // Log results
                LogTokenAnalysisResults(result);
                
                result.Success = true;
                result.Message = "Comprehensive token theft detection completed successfully";
                
                EnhancedLogger.LogSuccess($"Token theft detection completed: {result.TotalTokens} tokens, {result.Alerts.Count} thefts detected");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"Token theft detection failed: {ex.Message}";
                EnhancedLogger.LogError($"Comprehensive token theft detection failed: {ex.Message}");
            }
            
            return result;
        }

        /// <summary>
        /// Collect active tokens (simulated for demonstration)
        /// </summary>
        private static async Task<List<TokenSession>> CollectActiveTokensAsync()
        {
            var tokens = new List<TokenSession>();
            
            try
            {
                // Simulate collecting active tokens
                // In a real implementation, this would query token stores and session databases
                
                tokens.Add(new TokenSession
                {
                    TokenId = "token-001",
                    TokenType = "JWT",
                    UserId = "user-001",
                    UserName = "john.doe",
                    TokenHash = ComputeTokenHash("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."),
                    IpAddress = "192.168.1.100",
                    UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    Location = "New York, NY",
                    CreatedAt = DateTime.UtcNow.AddMinutes(-30),
                    ExpiresAt = DateTime.UtcNow.AddMinutes(30),
                    LastUsed = DateTime.UtcNow.AddMinutes(-2),
                    IsValid = true,
                    UsageCount = 15,
                    UsedEndpoints = new List<string> { "/api/users", "/api/profile", "/api/settings" },
                    Metadata = new Dictionary<string, object>
                    {
                        { "Issuer", "auth-service" },
                        { "Audience", "api-gateway" },
                        { "Scopes", new[] { "read", "write" } }
                    }
                });
                
                tokens.Add(new TokenSession
                {
                    TokenId = "token-002",
                    TokenType = "OAuth",
                    UserId = "user-001",
                    UserName = "john.doe",
                    TokenHash = ComputeTokenHash("ya29.a0AfH6SMC..."),
                    IpAddress = "203.0.113.50",
                    UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    Location = "London, UK",
                    CreatedAt = DateTime.UtcNow.AddMinutes(-15),
                    ExpiresAt = DateTime.UtcNow.AddMinutes(45),
                    LastUsed = DateTime.UtcNow.AddMinutes(-1),
                    IsValid = true,
                    UsageCount = 8,
                    UsedEndpoints = new List<string> { "/api/admin", "/api/users" },
                    Metadata = new Dictionary<string, object>
                    {
                        { "Provider", "google" },
                        { "Scopes", new[] { "admin", "read", "write" } }
                    }
                });
                
                tokens.Add(new TokenSession
                {
                    TokenId = "token-003",
                    TokenType = "Session",
                    UserId = "user-002",
                    UserName = "jane.smith",
                    TokenHash = ComputeTokenHash("session-abc123..."),
                    IpAddress = "10.0.0.50",
                    UserAgent = "HeadlessChrome/91.0.4472.124",
                    Location = "Unknown",
                    CreatedAt = DateTime.UtcNow.AddMinutes(-5),
                    ExpiresAt = DateTime.UtcNow.AddMinutes(55),
                    LastUsed = DateTime.UtcNow.AddMinutes(-30),
                    IsValid = false,
                    UsageCount = 25,
                    UsedEndpoints = new List<string> { "/api/admin", "/api/system", "/api/config" },
                    Metadata = new Dictionary<string, object>
                    {
                        { "SessionType", "admin" },
                        { "Permissions", new[] { "admin", "system", "config" } }
                    }
                });
                
                tokens.Add(new TokenSession
                {
                    TokenId = "token-004",
                    TokenType = "Bearer",
                    UserId = "user-003",
                    UserName = "admin.user",
                    TokenHash = ComputeTokenHash("Bearer xyz789..."),
                    IpAddress = "172.16.0.100",
                    UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    Location = "San Francisco, CA",
                    CreatedAt = DateTime.UtcNow.AddMinutes(-60),
                    ExpiresAt = DateTime.UtcNow.AddMinutes(0),
                    LastUsed = DateTime.UtcNow.AddMinutes(-5),
                    IsValid = true,
                    UsageCount = 3,
                    UsedEndpoints = new List<string> { "/api/profile" },
                    Metadata = new Dictionary<string, object>
                    {
                        { "ClientId", "web-app" },
                        { "Scopes", new[] { "read" } }
                    }
                });
                
                await Task.Delay(100); // Simulate API call delay
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error collecting active tokens: {ex.Message}");
            }
            
            return tokens;
        }

        /// <summary>
        /// Analyze a single token for theft indicators
        /// </summary>
        private static async Task<TokenAlert?> AnalyzeTokenAsync(TokenSession token)
        {
            try
            {
                var theftIndicators = new List<string>();
                var riskScore = 0.0;
                
                // Check for concurrent token usage
                riskScore += CheckConcurrentTokenUsage(token, theftIndicators);
                
                // Check for location anomalies
                riskScore += CheckLocationAnomalies(token, theftIndicators);
                
                // Check for unusual usage patterns
                riskScore += CheckUnusualUsagePatterns(token, theftIndicators);
                
                // Check for token expiration issues
                riskScore += CheckTokenExpiration(token, theftIndicators);
                
                // Check for suspicious endpoints
                riskScore += CheckSuspiciousEndpoints(token, theftIndicators);
                
                // Check for rapid token usage
                riskScore += CheckRapidTokenUsage(token, theftIndicators);
                
                // Check for token reuse
                riskScore += CheckTokenReuse(token, theftIndicators);
                
                if (theftIndicators.Any())
                {
                    var alert = new TokenAlert
                    {
                        TokenId = token.TokenId,
                        AlertType = "TOKEN_THEFT",
                        Description = string.Join("; ", theftIndicators),
                        RiskScore = Math.Min(riskScore, 1.0),
                        Severity = riskScore >= criticalRiskThreshold ? ThreatLevel.Critical :
                                  riskScore >= highRiskThreshold ? ThreatLevel.High :
                                  ThreatLevel.Medium,
                        RemediationGuidance = GenerateTokenRemediationGuidance(theftIndicators, token.TokenType),
                        Context = new Dictionary<string, object>
                        {
                            { "TokenType", token.TokenType },
                            { "UserId", token.UserId },
                            { "UserName", token.UserName },
                            { "IpAddress", token.IpAddress },
                            { "Location", token.Location },
                            { "UsageCount", token.UsageCount },
                            { "UsedEndpoints", token.UsedEndpoints },
                            { "IsValid", token.IsValid },
                            { "CreatedAt", token.CreatedAt },
                            { "ExpiresAt", token.ExpiresAt }
                        }
                    };
                    
                    return alert;
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error analyzing token {token.TokenId}: {ex.Message}");
            }
            
            return null;
        }

        /// <summary>
        /// Check for concurrent token usage
        /// </summary>
        private static double CheckConcurrentTokenUsage(TokenSession token, List<string> indicators)
        {
            var riskScore = 0.0;
            
            try
            {
                var concurrentTokens = activeTokens.Values
                    .Where(t => t.UserId == token.UserId && 
                               t.TokenId != token.TokenId &&
                               t.IsValid &&
                               t.LastUsed > token.LastUsed.AddMinutes(-30))
                    .Count();
                
                if (concurrentTokens >= maxConcurrentTokens)
                {
                    indicators.Add($"Multiple concurrent tokens detected: {concurrentTokens} active tokens");
                    riskScore += 0.5;
                }
                else if (concurrentTokens >= maxConcurrentTokens / 2)
                {
                    indicators.Add($"Suspicious concurrent tokens: {concurrentTokens} active tokens");
                    riskScore += 0.3;
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error checking concurrent token usage: {ex.Message}");
            }
            
            return riskScore;
        }

        /// <summary>
        /// Check for location anomalies
        /// </summary>
        private static double CheckLocationAnomalies(TokenSession token, List<string> indicators)
        {
            var riskScore = 0.0;
            
            try
            {
                // Get previous tokens for the same user
                var previousTokens = activeTokens.Values
                    .Where(t => t.UserId == token.UserId && 
                               t.TokenId != token.TokenId &&
                               t.CreatedAt < token.CreatedAt &&
                               t.CreatedAt > token.CreatedAt.AddHours(-24))
                    .OrderByDescending(t => t.CreatedAt)
                    .FirstOrDefault();
                
                if (previousTokens != null && 
                    previousTokens.Location != token.Location &&
                    previousTokens.Location != "Unknown" &&
                    token.Location != "Unknown")
                {
                    indicators.Add($"Token used from different location: {previousTokens.Location} -> {token.Location}");
                    riskScore += 0.4;
                }
                
                // Check for unknown locations
                if (token.Location == "Unknown")
                {
                    indicators.Add("Token used from unknown location");
                    riskScore += 0.2;
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error checking location anomalies: {ex.Message}");
            }
            
            return riskScore;
        }

        /// <summary>
        /// Check for unusual usage patterns
        /// </summary>
        private static double CheckUnusualUsagePatterns(TokenSession token, List<string> indicators)
        {
            var riskScore = 0.0;
            
            try
            {
                // Check for high usage count in short time
                var timeSpan = token.LastUsed - token.CreatedAt;
                var usageRate = token.UsageCount / timeSpan.TotalMinutes;
                
                if (usageRate > 2.0) // More than 2 uses per minute
                {
                    indicators.Add($"Unusual usage rate: {usageRate:F1} uses per minute");
                    riskScore += 0.3;
                }
                
                // Check for suspicious user agents
                if (token.UserAgent.ToLower().Contains("headless") ||
                    token.UserAgent.ToLower().Contains("bot") ||
                    token.UserAgent.ToLower().Contains("crawler"))
                {
                    indicators.Add($"Suspicious user agent: {token.UserAgent}");
                    riskScore += 0.3;
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error checking unusual usage patterns: {ex.Message}");
            }
            
            return riskScore;
        }

        /// <summary>
        /// Check for token expiration issues
        /// </summary>
        private static double CheckTokenExpiration(TokenSession token, List<string> indicators)
        {
            var riskScore = 0.0;
            
            try
            {
                // Check for expired tokens still being used
                if (token.ExpiresAt < DateTime.UtcNow && token.IsValid)
                {
                    indicators.Add("Expired token still being used");
                    riskScore += 0.4;
                }
                
                // Check for tokens near expiration with high usage
                var timeToExpiry = token.ExpiresAt - DateTime.UtcNow;
                if (timeToExpiry.TotalMinutes < 5 && token.UsageCount > 10)
                {
                    indicators.Add("High usage of token near expiration");
                    riskScore += 0.2;
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error checking token expiration: {ex.Message}");
            }
            
            return riskScore;
        }

        /// <summary>
        /// Check for suspicious endpoints
        /// </summary>
        private static double CheckSuspiciousEndpoints(TokenSession token, List<string> indicators)
        {
            var riskScore = 0.0;
            
            try
            {
                var suspiciousEndpoints = token.UsedEndpoints
                    .Where(endpoint => endpoint.Contains("admin") || 
                                     endpoint.Contains("system") || 
                                     endpoint.Contains("config") ||
                                     endpoint.Contains("root"))
                    .ToList();
                
                if (suspiciousEndpoints.Any())
                {
                    indicators.Add($"Suspicious endpoints accessed: {string.Join(", ", suspiciousEndpoints)}");
                    riskScore += 0.3;
                }
                
                // Check for unusual endpoint combinations
                if (token.UsedEndpoints.Count > 10)
                {
                    indicators.Add($"Unusual number of endpoints accessed: {token.UsedEndpoints.Count}");
                    riskScore += 0.2;
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error checking suspicious endpoints: {ex.Message}");
            }
            
            return riskScore;
        }

        /// <summary>
        /// Check for rapid token usage
        /// </summary>
        private static double CheckRapidTokenUsage(TokenSession token, List<string> indicators)
        {
            var riskScore = 0.0;
            
            try
            {
                var recentUsage = activeTokens.Values
                    .Where(t => t.TokenId == token.TokenId &&
                               t.LastUsed > token.LastUsed.AddMinutes(-5))
                    .Count();
                
                if (recentUsage > 20)
                {
                    indicators.Add($"Rapid token usage detected: {recentUsage} uses in 5 minutes");
                    riskScore += 0.4;
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error checking rapid token usage: {ex.Message}");
            }
            
            return riskScore;
        }

        /// <summary>
        /// Check for token reuse
        /// </summary>
        private static double CheckTokenReuse(TokenSession token, List<string> indicators)
        {
            var riskScore = 0.0;
            
            try
            {
                // Check if token hash has been used before
                var tokenReuse = activeTokens.Values
                    .Where(t => t.TokenHash == token.TokenHash && 
                               t.TokenId != token.TokenId)
                    .Any();
                
                if (tokenReuse)
                {
                    indicators.Add("Token reuse detected");
                    riskScore += 0.5;
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error checking token reuse: {ex.Message}");
            }
            
            return riskScore;
        }

        /// <summary>
        /// Compute hash for token
        /// </summary>
        private static string ComputeTokenHash(string token)
        {
            using (var sha256 = SHA256.Create())
            {
                var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
                return Convert.ToBase64String(hashBytes);
            }
        }

        /// <summary>
        /// Send token analysis to cloud for additional processing
        /// </summary>
        private static async Task SendTokenAnalysisToCloudAsync(TokenAnalysisResult result)
        {
            try
            {
                var telemetryData = new
                {
                    scan_timestamp = DateTime.UtcNow,
                    total_tokens = result.TotalTokens,
                    total_alerts = result.Alerts.Count,
                    critical_thefts = result.CriticalThefts,
                    high_thefts = result.HighThefts,
                    medium_thefts = result.MediumThefts,
                    overall_risk_score = result.OverallRiskScore,
                    alerts_summary = result.Alerts.Select(a => new
                    {
                        token_id = a.TokenId,
                        alert_type = a.AlertType,
                        severity = a.Severity.ToString(),
                        risk_score = a.RiskScore
                    }).ToList()
                };
                
                await CloudIntegration.SendTelemetryAsync("TokenTheftDetector", "token_analysis", telemetryData, 
                    result.OverallRiskScore >= criticalRiskThreshold ? ThreatLevel.Critical :
                    result.OverallRiskScore >= highRiskThreshold ? ThreatLevel.High : ThreatLevel.Medium);
                
                // Get cloud analysis results
                var cloudAnalysis = await CloudIntegration.GetCloudAnalysisAsync("TokenTheftDetector", telemetryData);
                if (cloudAnalysis.Success)
                {
                    EnhancedLogger.LogInfo($"Cloud token analysis: {cloudAnalysis.Analysis}");
                    
                    // Apply cloud recommendations if any
                    if (cloudAnalysis.Recommendations?.Any() == true)
                    {
                        foreach (var recommendation in cloudAnalysis.Recommendations)
                        {
                            EnhancedLogger.LogInfo($"Cloud recommendation: {recommendation}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to send token analysis to cloud: {ex.Message}");
            }
        }

        /// <summary>
        /// Generate remediation guidance for token alerts
        /// </summary>
        private static string GenerateTokenRemediationGuidance(List<string> indicators, string tokenType)
        {
            var guidance = new List<string>();
            
            foreach (var indicator in indicators)
            {
                if (indicator.Contains("concurrent tokens"))
                {
                    guidance.Add("Implement token session limits and monitoring");
                }
                else if (indicator.Contains("different location"))
                {
                    guidance.Add("Implement location-based token validation");
                }
                else if (indicator.Contains("unknown location"))
                {
                    guidance.Add("Block tokens from unknown locations");
                }
                else if (indicator.Contains("usage rate"))
                {
                    guidance.Add("Implement rate limiting for token usage");
                }
                else if (indicator.Contains("suspicious user agent"))
                {
                    guidance.Add("Block suspicious user agents");
                }
                else if (indicator.Contains("expired token"))
                {
                    guidance.Add("Immediately revoke expired tokens");
                }
                else if (indicator.Contains("suspicious endpoints"))
                {
                    guidance.Add("Review and restrict endpoint access");
                }
                else if (indicator.Contains("token reuse"))
                {
                    guidance.Add("Implement one-time token usage policies");
                }
            }
            
            return string.Join("; ", guidance.Distinct());
        }

        /// <summary>
        /// Generate security recommendations based on analysis results
        /// </summary>
        private static List<string> GenerateTokenRecommendations(List<TokenAlert> alerts)
        {
            var recommendations = new List<string>();
            
            if (alerts.Any(a => a.Severity == ThreatLevel.Critical))
            {
                recommendations.Add("Immediately investigate critical token theft incidents");
            }
            
            if (alerts.Any(a => a.Description.Contains("concurrent tokens")))
            {
                recommendations.Add("Implement strict token session management");
            }
            
            if (alerts.Any(a => a.Description.Contains("different location")))
            {
                recommendations.Add("Implement location-based token validation");
            }
            
            if (alerts.Any(a => a.Description.Contains("expired token")))
            {
                recommendations.Add("Strengthen token expiration and revocation policies");
            }
            
            recommendations.Add("Implement token rotation and short-lived tokens");
            recommendations.Add("Enable token usage monitoring and alerting");
            recommendations.Add("Implement device fingerprinting for token validation");
            recommendations.Add("Regularly audit and review token usage patterns");
            
            return recommendations;
        }

        /// <summary>
        /// Log token analysis results
        /// </summary>
        private static void LogTokenAnalysisResults(TokenAnalysisResult result)
        {
            if (result.CriticalThefts > 0)
            {
                EnhancedLogger.LogCritical($"Token Analysis: {result.CriticalThefts} critical thefts detected");
            }
            
            if (result.HighThefts > 0)
            {
                EnhancedLogger.LogWarning($"Token Analysis: {result.HighThefts} high-risk thefts detected");
            }
            
            if (result.MediumThefts > 0)
            {
                EnhancedLogger.LogInfo($"Token Analysis: {result.MediumThefts} medium-risk thefts detected");
            }
            
            EnhancedLogger.LogInfo($"Token Analysis Summary: {result.TotalTokens} tokens analyzed, " +
                                 $"Overall risk score: {result.OverallRiskScore:F2}");
        }

        /// <summary>
        /// Load configuration from UnifiedConfig
        /// </summary>
        private static void LoadConfiguration()
        {
            try
            {
                var config = UnifiedConfig.Instance;
                detectionIntervalSeconds = config.GetModulePerformanceSettings("TokenTheftDetector").ScanInterval;
                criticalRiskThreshold = 0.8;
                highRiskThreshold = 0.6;
                mediumRiskThreshold = 0.4;
                
                EnhancedLogger.LogInfo($"Token Theft Detector configuration loaded: detection interval = {detectionIntervalSeconds} seconds");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogWarning($"Failed to load Token Theft Detector configuration: {ex.Message}");
            }
        }

        /// <summary>
        /// Initialize token tracking
        /// </summary>
        private static void InitializeTokenTracking()
        {
            activeTokens.Clear();
            activeAlerts.Clear();
        }

        /// <summary>
        /// Start detection
        /// </summary>
        private static void StartDetection()
        {
            detectionTimer = new Timer(async _ => await PerformComprehensiveTokenScanAsync(), null, 
                TimeSpan.Zero, TimeSpan.FromSeconds(detectionIntervalSeconds));
        }

        /// <summary>
        /// Start continuous token detection
        /// </summary>
        private static async Task StartContinuousTokenDetectionAsync()
        {
            // In a real implementation, this would set up event-driven detection
            // For now, we rely on periodic scanning
            await Task.CompletedTask;
        }

        /// <summary>
        /// Get current status of the detector
        /// </summary>
        public static bool IsActive => isActive;

        /// <summary>
        /// Get active alerts
        /// </summary>
        public static List<TokenAlert> GetActiveAlerts() => new List<TokenAlert>(activeAlerts);

        /// <summary>
        /// Acknowledge an alert
        /// </summary>
        public static void AcknowledgeAlert(string alertId)
        {
            var alert = activeAlerts.FirstOrDefault(a => a.AlertId == alertId);
            if (alert != null)
            {
                alert.IsAcknowledged = true;
                EnhancedLogger.LogInfo($"Token alert {alertId} acknowledged");
            }
        }
    }
} 
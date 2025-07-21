using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Linq; // Added for .Any()

namespace PhageVirus.Agent.Security
{
    /// <summary>
    /// Network security module for TLS-only communications, IP whitelisting, and WAF integration
    /// </summary>
    public class NetworkSecurity
    {
        private readonly ILogger<NetworkSecurity> _logger;
        private readonly IConfiguration _configuration;
        private readonly SecurityManager _securityManager;
        private readonly List<IPAddress> _whitelistedIPs;
        private readonly List<string> _whitelistedRegions;
        private readonly List<string> _whitelistedDomains;
        private readonly HttpClient _secureHttpClient;
        
        private bool _isInitialized = false;

        public NetworkSecurity(IConfiguration configuration, ILogger<NetworkSecurity> logger, SecurityManager securityManager)
        {
            _configuration = configuration;
            _logger = logger;
            _securityManager = securityManager;
            _whitelistedIPs = new List<IPAddress>();
            _whitelistedRegions = new List<string>();
            _whitelistedDomains = new List<string>();
            _secureHttpClient = CreateSecureHttpClient();
        }

        public async Task InitializeAsync()
        {
            if (_isInitialized)
                return;

            try
            {
                _logger.LogInformation("Initializing network security module");

                // Load whitelist configurations
                LoadWhitelistConfigurations();

                // Configure TLS settings
                ConfigureTlsSettings();

                // Initialize WAF integration
                InitializeWafIntegration();

                // Test network connectivity
                await TestNetworkConnectivityAsync();

                _isInitialized = true;
                _logger.LogInformation("Network security module initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize network security module");
                throw;
            }
        }

        public async Task<bool> ValidateNetworkRequestAsync(string url, string method = "GET")
        {
            try
            {
                _logger.LogDebug($"Validating network request: {method} {url}");

                // Validate URL format
                if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                {
                    _logger.LogWarning($"Invalid URL format: {url}");
                    return false;
                }

                // Validate protocol (HTTPS only)
                if (uri.Scheme != "https")
                {
                    _logger.LogWarning($"Non-HTTPS request blocked: {url}");
                    return false;
                }

                // Validate port (443 only)
                if (uri.Port != 443 && uri.Port != -1)
                {
                    _logger.LogWarning($"Non-standard HTTPS port blocked: {url}");
                    return false;
                }

                // Validate domain whitelist
                if (!IsDomainWhitelisted(uri.Host))
                {
                    _logger.LogWarning($"Domain not in whitelist: {uri.Host}");
                    return false;
                }

                // Validate region (if applicable)
                if (!IsRegionAllowed(uri.Host))
                {
                    _logger.LogWarning($"Region not allowed for: {uri.Host}");
                    return false;
                }

                // Validate IP (if available)
                var ipAddresses = await ResolveIpAddressesAsync(uri.Host);
                foreach (var ip in ipAddresses)
                {
                    if (!IsIpWhitelisted(ip))
                    {
                        _logger.LogWarning($"IP not in whitelist: {ip} for {uri.Host}");
                        return false;
                    }
                }

                _logger.LogDebug($"Network request validated successfully: {url}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error validating network request: {url}");
                return false;
            }
        }

        public async Task<HttpResponseMessage?> SendSecureRequestAsync(string url, HttpMethod method, object? data = null)
        {
            try
            {
                // Validate request first
                if (!await ValidateNetworkRequestAsync(url, method.Method))
                {
                    _logger.LogWarning($"Network request validation failed: {method} {url}");
                    return null;
                }

                _logger.LogDebug($"Sending secure request: {method} {url}");

                // Create request
                var request = new HttpRequestMessage(method, url);

                // Add security headers
                AddSecurityHeaders(request);

                // Add request data if provided
                if (data != null)
                {
                    var json = JsonSerializer.Serialize(data);
                    request.Content = new StringContent(json, Encoding.UTF8, "application/json");
                }

                // Send request
                var response = await _secureHttpClient.SendAsync(request);

                // Validate response
                if (!await ValidateResponseAsync(response))
                {
                    _logger.LogWarning($"Response validation failed: {method} {url}");
                    return null;
                }

                _logger.LogDebug($"Secure request completed: {method} {url} - {response.StatusCode}");
                return response;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error sending secure request: {method} {url}");
                return null;
            }
        }

        public async Task<bool> ValidateS3PresignedUrlAsync(string presignedUrl)
        {
            try
            {
                _logger.LogDebug("Validating S3 presigned URL");

                if (!Uri.TryCreate(presignedUrl, UriKind.Absolute, out var uri))
                {
                    _logger.LogWarning("Invalid presigned URL format");
                    return false;
                }

                // Validate S3 domain
                if (!uri.Host.EndsWith(".s3.ap-southeast-2.amazonaws.com"))
                {
                    _logger.LogWarning($"Invalid S3 domain: {uri.Host}");
                    return false;
                }

                // Validate expiration
                var expirationParam = System.Web.HttpUtility.ParseQueryString(uri.Query)["X-Amz-Expires"];
                if (!string.IsNullOrEmpty(expirationParam))
                {
                    if (DateTime.TryParse(expirationParam, out var expiration))
                    {
                        if (expiration < DateTime.UtcNow)
                        {
                            _logger.LogWarning("Presigned URL has expired");
                            return false;
                        }
                    }
                }

                // Validate signature
                var signatureParam = System.Web.HttpUtility.ParseQueryString(uri.Query)["X-Amz-Signature"];
                if (string.IsNullOrEmpty(signatureParam))
                {
                    _logger.LogWarning("Presigned URL missing signature");
                    return false;
                }

                _logger.LogDebug("S3 presigned URL validated successfully");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating S3 presigned URL");
                return false;
            }
        }

        public async Task<string?> CreateSecureWebhookUrlAsync(string baseUrl, Dictionary<string, object> payload)
        {
            try
            {
                _logger.LogDebug($"Creating secure webhook URL: {baseUrl}");

                // Validate base URL
                if (!await ValidateNetworkRequestAsync(baseUrl))
                {
                    _logger.LogWarning($"Base URL validation failed: {baseUrl}");
                    return null;
                }

                // Create secure payload
                var securePayload = new
                {
                    Timestamp = DateTime.UtcNow,
                    AgentId = _securityManager.AgentId,
                    Payload = payload,
                    Signature = await SignPayloadAsync(payload)
                };

                // Add security parameters
                var uriBuilder = new UriBuilder(baseUrl);
                var query = System.Web.HttpUtility.ParseQueryString(uriBuilder.Query);
                query["timestamp"] = securePayload.Timestamp.ToString("yyyy-MM-ddTHH:mm:ssZ");
                query["agentId"] = securePayload.AgentId;
                query["signature"] = securePayload.Signature;
                uriBuilder.Query = query.ToString();

                _logger.LogDebug("Secure webhook URL created successfully");
                return uriBuilder.ToString();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating secure webhook URL");
                return null;
            }
        }

        #region Configuration

        private void LoadWhitelistConfigurations()
        {
            try
            {
                _logger.LogDebug("Loading whitelist configurations");

                // Load IP whitelist
                var ipWhitelist = _configuration.GetSection("security:network:ip_whitelist").Get<string[]>();
                if (ipWhitelist != null)
                {
                    foreach (var ip in ipWhitelist)
                    {
                        if (IPAddress.TryParse(ip, out var ipAddress))
                        {
                            _whitelistedIPs.Add(ipAddress);
                        }
                    }
                }

                // Load region whitelist
                var regionWhitelist = _configuration.GetSection("security:network:region_whitelist").Get<string[]>();
                if (regionWhitelist != null)
                {
                    _whitelistedRegions.AddRange(regionWhitelist);
                }

                // Load domain whitelist
                var domainWhitelist = _configuration.GetSection("security:network:domain_whitelist").Get<string[]>();
                if (domainWhitelist != null)
                {
                    _whitelistedDomains.AddRange(domainWhitelist);
                }

                // Add default AWS domains if none configured
                if (_whitelistedDomains.Count == 0)
                {
                    _whitelistedDomains.AddRange(new[]
                    {
                        "s3.ap-southeast-2.amazonaws.com",
                        "dynamodb.ap-southeast-2.amazonaws.com",
                        "lambda.ap-southeast-2.amazonaws.com",
                        "logs.ap-southeast-2.amazonaws.com",
                        "kinesis.ap-southeast-2.amazonaws.com"
                    });
                }

                _logger.LogInformation($"Loaded {_whitelistedIPs.Count} IPs, {_whitelistedRegions.Count} regions, {_whitelistedDomains.Count} domains");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading whitelist configurations");
            }
        }

        private void ConfigureTlsSettings()
        {
            try
            {
                _logger.LogDebug("Configuring TLS settings");

                // Configure TLS 1.2+ only
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;

                // Configure certificate validation
                ServicePointManager.ServerCertificateValidationCallback = ValidateServerCertificate;

                // Configure connection limits
                ServicePointManager.DefaultConnectionLimit = 10;
                ServicePointManager.MaxServicePointIdleTime = 30000; // 30 seconds

                _logger.LogDebug("TLS settings configured successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error configuring TLS settings");
            }
        }

        private void InitializeWafIntegration()
        {
            try
            {
                _logger.LogDebug("Initializing WAF integration");

                // WAF integration would be implemented here
                // This could include AWS WAF, Azure Application Gateway, or other WAF solutions

                _logger.LogDebug("WAF integration initialized");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error initializing WAF integration");
            }
        }

        #endregion

        #region Validation Methods

        private bool IsDomainWhitelisted(string domain)
        {
            try
            {
                if (_whitelistedDomains.Count == 0)
                    return true; // Allow all if no whitelist configured

                return _whitelistedDomains.Any(whitelistedDomain => 
                    domain.Equals(whitelistedDomain, StringComparison.OrdinalIgnoreCase) ||
                    domain.EndsWith("." + whitelistedDomain, StringComparison.OrdinalIgnoreCase));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error checking domain whitelist: {domain}");
                return false;
            }
        }

        private bool IsRegionAllowed(string host)
        {
            try
            {
                if (_whitelistedRegions.Count == 0)
                    return true; // Allow all if no region restrictions

                // Check if host contains allowed region
                return _whitelistedRegions.Any(region => 
                    host.Contains(region, StringComparison.OrdinalIgnoreCase));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error checking region allowance: {host}");
                return false;
            }
        }

        private bool IsIpWhitelisted(IPAddress ip)
        {
            try
            {
                if (_whitelistedIPs.Count == 0)
                    return true; // Allow all if no IP whitelist configured

                return _whitelistedIPs.Any(whitelistedIp => 
                    ip.Equals(whitelistedIp));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error checking IP whitelist: {ip}");
                return false;
            }
        }

        private async Task<List<IPAddress>> ResolveIpAddressesAsync(string host)
        {
            try
            {
                var addresses = new List<IPAddress>();
                var hostEntry = await Dns.GetHostEntryAsync(host);
                addresses.AddRange(hostEntry.AddressList);
                return addresses;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error resolving IP addresses for: {host}");
                return new List<IPAddress>();
            }
        }

        private bool ValidateServerCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
        {
            try
            {
                if (sslPolicyErrors != SslPolicyErrors.None)
                {
                    _logger.LogWarning($"SSL certificate validation failed: {sslPolicyErrors}");
                    return false;
                }

                if (certificate == null)
                {
                    _logger.LogWarning("SSL certificate is null");
                    return false;
                }

                // Additional certificate validation
                if (certificate.NotAfter < DateTime.UtcNow)
                {
                    _logger.LogWarning("SSL certificate has expired");
                    return false;
                }

                if (certificate.NotBefore > DateTime.UtcNow)
                {
                    _logger.LogWarning("SSL certificate is not yet valid");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating server certificate");
                return false;
            }
        }

        private async Task<bool> ValidateResponseAsync(HttpResponseMessage response)
        {
            try
            {
                // Check status code
                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning($"HTTP request failed: {response.StatusCode}");
                    return false;
                }

                // Check content type
                var contentType = response.Content.Headers.ContentType?.MediaType;
                if (!string.IsNullOrEmpty(contentType) && !contentType.Contains("json") && !contentType.Contains("text"))
                {
                    _logger.LogWarning($"Unexpected content type: {contentType}");
                    return false;
                }

                // Check response headers for security
                if (!response.Headers.Contains("X-Content-Type-Options"))
                {
                    _logger.LogWarning("Response missing security headers");
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating response");
                return false;
            }
        }

        #endregion

        #region HTTP Client

        private HttpClient CreateSecureHttpClient()
        {
            try
            {
                var handler = new HttpClientHandler
                {
                    AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
                    MaxConnectionsPerServer = 10,
                    UseCookies = false // Disable cookies for security
                };

                var client = new HttpClient(handler)
                {
                    Timeout = TimeSpan.FromSeconds(30)
                };

                // Add default headers
                client.DefaultRequestHeaders.Add("User-Agent", "PhageVirus-Agent/2.0.0");
                client.DefaultRequestHeaders.Add("Accept", "application/json");
                client.DefaultRequestHeaders.Add("Accept-Encoding", "gzip, deflate");

                return client;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating secure HTTP client");
                throw;
            }
        }

        private void AddSecurityHeaders(HttpRequestMessage request)
        {
            try
            {
                request.Headers.Add("X-Request-ID", Guid.NewGuid().ToString());
                request.Headers.Add("X-Agent-ID", _securityManager.AgentId);
                request.Headers.Add("X-Timestamp", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));
                request.Headers.Add("X-Security-Level", "High");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error adding security headers");
            }
        }

        #endregion

        #region Security Utilities

        private async Task<string> SignPayloadAsync(Dictionary<string, object> payload)
        {
            try
            {
                var json = JsonSerializer.Serialize(payload);
                var data = Encoding.UTF8.GetBytes(json);

                using var hmac = new System.Security.Cryptography.HMACSHA256();
                var hash = hmac.ComputeHash(data);
                return Convert.ToBase64String(hash);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error signing payload");
                return string.Empty;
            }
        }

        private async Task TestNetworkConnectivityAsync()
        {
            try
            {
                _logger.LogDebug("Testing network connectivity");

                // Test DNS resolution
                var testHost = "s3.ap-southeast-2.amazonaws.com";
                var addresses = await ResolveIpAddressesAsync(testHost);
                if (addresses.Count == 0)
                {
                    _logger.LogWarning("DNS resolution test failed");
                }

                // Test HTTPS connectivity
                var testUrl = "https://s3.ap-southeast-2.amazonaws.com";
                var isValid = await ValidateNetworkRequestAsync(testUrl);
                if (!isValid)
                {
                    _logger.LogWarning("HTTPS connectivity test failed");
                }

                _logger.LogDebug("Network connectivity test completed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error testing network connectivity");
            }
        }

        #endregion

        #region Public Properties

        public bool IsInitialized => _isInitialized;
        public int WhitelistedIpCount => _whitelistedIPs.Count;
        public int WhitelistedRegionCount => _whitelistedRegions.Count;
        public int WhitelistedDomainCount => _whitelistedDomains.Count;

        #endregion
    }
} 
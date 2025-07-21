using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using PhageVirus.Agent.Shared;

namespace PhageVirus.Agent.Security
{
    /// <summary>
    /// Secure telemetry handling with encryption, signing, and tamper protection
    /// </summary>
    public class TelemetrySecurity
    {
        private readonly ILogger<TelemetrySecurity> _logger;
        private readonly IConfiguration _configuration;
        private readonly SecurityManager _securityManager;
        private readonly byte[] _telemetryKey;
        private readonly string _endpointId;
        private int _sequenceNumber = 0;

        public TelemetrySecurity(IConfiguration configuration, ILogger<TelemetrySecurity> logger, SecurityManager securityManager)
        {
            _configuration = configuration;
            _logger = logger;
            _securityManager = securityManager;
            _telemetryKey = GenerateTelemetryKey();
            _endpointId = GenerateSecureEndpointId();
        }

        public async Task<SecureTelemetryData> CreateSecureTelemetryAsync(TelemetryData telemetry)
        {
            try
            {
                _logger.LogDebug("Creating secure telemetry data");

                // Create secure telemetry wrapper
                var secureTelemetry = new SecureTelemetryData
                {
                    EndpointId = _endpointId,
                    SequenceNumber = Interlocked.Increment(ref _sequenceNumber),
                    Timestamp = DateTime.UtcNow,
                    OriginalData = telemetry,
                    SecurityMetadata = new SecurityMetadata
                    {
                        AgentId = _securityManager.AgentId,
                        IntegrityHash = CalculateIntegrityHash(telemetry),
                        EncryptionVersion = "AES-256-GCM",
                        SigningVersion = "HMAC-SHA256",
                        TamperProtection = true
                    }
                };

                // Encrypt the telemetry data
                secureTelemetry.EncryptedData = EncryptTelemetryData(telemetry);

                // Sign the entire secure telemetry
                secureTelemetry.Signature = SignTelemetryData(secureTelemetry);

                // Add additional security headers
                AddSecurityHeaders(secureTelemetry);

                _logger.LogDebug($"Secure telemetry created: Sequence {secureTelemetry.SequenceNumber}");
                return secureTelemetry;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating secure telemetry");
                throw;
            }
        }

        public async Task<TelemetryData?> DecryptTelemetryDataAsync(SecureTelemetryData secureTelemetry)
        {
            try
            {
                _logger.LogDebug($"Decrypting telemetry data: Sequence {secureTelemetry.SequenceNumber}");

                // Verify signature first
                if (!VerifyTelemetrySignature(secureTelemetry))
                {
                    _logger.LogWarning("Telemetry signature verification failed");
                    return null;
                }

                // Verify endpoint ID
                if (secureTelemetry.EndpointId != _endpointId)
                {
                    _logger.LogWarning("Endpoint ID mismatch");
                    return null;
                }

                // Decrypt the data
                var decryptedData = DecryptTelemetryData(secureTelemetry.EncryptedData);
                if (decryptedData == null)
                {
                    _logger.LogWarning("Failed to decrypt telemetry data");
                    return null;
                }

                // Verify integrity hash
                var expectedHash = CalculateIntegrityHash(decryptedData);
                if (secureTelemetry.SecurityMetadata.IntegrityHash != expectedHash)
                {
                    _logger.LogWarning("Telemetry integrity check failed");
                    return null;
                }

                _logger.LogDebug("Telemetry data decrypted and verified successfully");
                return decryptedData;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error decrypting telemetry data");
                return null;
            }
        }

        public async Task<byte[]> CreateSignedPresignedUrlAsync(string bucketName, string objectKey, TimeSpan expiration)
        {
            try
            {
                _logger.LogDebug($"Creating signed presigned URL for {bucketName}/{objectKey}");

                // Create presigned URL request
                var presignedRequest = new PresignedUrlRequest
                {
                    BucketName = bucketName,
                    ObjectKey = objectKey,
                    Expiration = DateTime.UtcNow.Add(expiration),
                    EndpointId = _endpointId,
                    AgentId = _securityManager.AgentId,
                    Timestamp = DateTime.UtcNow
                };

                // Sign the request
                var signature = SignPresignedRequest(presignedRequest);

                // Create the presigned URL
                var url = await GeneratePresignedUrlAsync(presignedRequest, signature);

                _logger.LogDebug("Signed presigned URL created successfully");
                return Encoding.UTF8.GetBytes(url);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating signed presigned URL");
                throw;
            }
        }

        public async Task<bool> ValidateIncomingTelemetryAsync(byte[] encryptedData, byte[] signature)
        {
            try
            {
                _logger.LogDebug("Validating incoming telemetry");

                // Verify signature
                if (!VerifyIncomingSignature(encryptedData, signature))
                {
                    _logger.LogWarning("Incoming telemetry signature verification failed");
                    return false;
                }

                // Decrypt and validate
                var telemetryData = DecryptIncomingData(encryptedData);
                if (telemetryData == null)
                {
                    _logger.LogWarning("Failed to decrypt incoming telemetry");
                    return false;
                }

                // Additional validation
                if (!ValidateTelemetryContent(telemetryData))
                {
                    _logger.LogWarning("Incoming telemetry content validation failed");
                    return false;
                }

                _logger.LogDebug("Incoming telemetry validated successfully");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating incoming telemetry");
                return false;
            }
        }

        #region Encryption and Signing

        private byte[] EncryptTelemetryData(TelemetryData telemetry)
        {
            try
            {
                // Serialize telemetry data
                var json = JsonSerializer.Serialize(telemetry);
                var data = Encoding.UTF8.GetBytes(json);

                // Encrypt using AES-256-GCM
                using var aes = Aes.Create();
                aes.Key = _telemetryKey;
                aes.Mode = CipherMode.GCM;
                aes.GenerateIV();

                using var encryptor = aes.CreateEncryptor();
                var encryptedData = encryptor.TransformFinalBlock(data, 0, data.Length);

                // Get authentication tag
                var tag = aes.GetTag();

                // Combine IV, encrypted data, and tag
                var result = new byte[aes.IV.Length + encryptedData.Length + tag.Length];
                Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
                Buffer.BlockCopy(encryptedData, 0, result, aes.IV.Length, encryptedData.Length);
                Buffer.BlockCopy(tag, 0, result, aes.IV.Length + encryptedData.Length, tag.Length);

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error encrypting telemetry data");
                throw;
            }
        }

        private TelemetryData? DecryptTelemetryData(byte[] encryptedData)
        {
            try
            {
                // Extract IV, encrypted data, and tag
                var iv = new byte[12]; // GCM IV size
                var tag = new byte[16]; // GCM tag size
                var data = new byte[encryptedData.Length - iv.Length - tag.Length];

                Buffer.BlockCopy(encryptedData, 0, iv, 0, iv.Length);
                Buffer.BlockCopy(encryptedData, iv.Length, data, 0, data.Length);
                Buffer.BlockCopy(encryptedData, iv.Length + data.Length, tag, 0, tag.Length);

                // Decrypt
                using var aes = Aes.Create();
                aes.Key = _telemetryKey;
                aes.Mode = CipherMode.GCM;
                aes.IV = iv;
                aes.SetTag(tag);

                using var decryptor = aes.CreateDecryptor();
                var decryptedData = decryptor.TransformFinalBlock(data, 0, data.Length);

                // Deserialize
                var json = Encoding.UTF8.GetString(decryptedData);
                return JsonSerializer.Deserialize<TelemetryData>(json);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error decrypting telemetry data");
                return null;
            }
        }

        private byte[] SignTelemetryData(SecureTelemetryData secureTelemetry)
        {
            try
            {
                // Create data to sign (excluding signature field)
                var dataToSign = new
                {
                    secureTelemetry.EndpointId,
                    secureTelemetry.SequenceNumber,
                    secureTelemetry.Timestamp,
                    secureTelemetry.EncryptedData,
                    secureTelemetry.SecurityMetadata
                };

                var json = JsonSerializer.Serialize(dataToSign);
                var data = Encoding.UTF8.GetBytes(json);

                // Sign using HMAC-SHA256
                using var hmac = new HMACSHA256(_telemetryKey);
                return hmac.ComputeHash(data);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error signing telemetry data");
                throw;
            }
        }

        private bool VerifyTelemetrySignature(SecureTelemetryData secureTelemetry)
        {
            try
            {
                var expectedSignature = SignTelemetryData(secureTelemetry);
                return CompareHashes(secureTelemetry.Signature, expectedSignature);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying telemetry signature");
                return false;
            }
        }

        #endregion

        #region Security Utilities

        private byte[] GenerateTelemetryKey()
        {
            try
            {
                using var rng = new RNGCryptoServiceProvider();
                var key = new byte[32]; // 256-bit key
                rng.GetBytes(key);
                return key;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating telemetry key");
                throw;
            }
        }

        private string GenerateSecureEndpointId()
        {
            try
            {
                var machineName = Environment.MachineName;
                var userName = Environment.UserName;
                var processId = Environment.ProcessId;
                var timestamp = DateTime.UtcNow.Ticks;

                var combined = $"{machineName}_{userName}_{processId}_{timestamp}";
                using var sha256 = SHA256.Create();
                var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(combined));

                return Convert.ToBase64String(hash).Substring(0, 24);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating secure endpoint ID");
                return Guid.NewGuid().ToString("N").Substring(0, 24);
            }
        }

        private string CalculateIntegrityHash(TelemetryData telemetry)
        {
            try
            {
                var json = JsonSerializer.Serialize(telemetry);
                var data = Encoding.UTF8.GetBytes(json);

                using var sha256 = SHA256.Create();
                var hash = sha256.ComputeHash(data);
                return Convert.ToBase64String(hash);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calculating integrity hash");
                return string.Empty;
            }
        }

        private void AddSecurityHeaders(SecureTelemetryData secureTelemetry)
        {
            try
            {
                secureTelemetry.SecurityHeaders = new Dictionary<string, string>
                {
                    ["X-Agent-Version"] = "2.0.0",
                    ["X-Security-Level"] = "High",
                    ["X-Encryption-Method"] = "AES-256-GCM",
                    ["X-Signing-Method"] = "HMAC-SHA256",
                    ["X-Timestamp"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                    ["X-Sequence"] = secureTelemetry.SequenceNumber.ToString(),
                    ["X-Integrity-Check"] = "Enabled"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error adding security headers");
            }
        }

        private byte[] SignPresignedRequest(PresignedUrlRequest request)
        {
            try
            {
                var json = JsonSerializer.Serialize(request);
                var data = Encoding.UTF8.GetBytes(json);

                using var hmac = new HMACSHA256(_telemetryKey);
                return hmac.ComputeHash(data);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error signing presigned request");
                throw;
            }
        }

        private async Task<string> GeneratePresignedUrlAsync(PresignedUrlRequest request, byte[] signature)
        {
            try
            {
                // This would integrate with AWS SDK to generate actual presigned URL
                var baseUrl = $"https://{request.BucketName}.s3.ap-southeast-2.amazonaws.com/{request.ObjectKey}";
                var signatureB64 = Convert.ToBase64String(signature);
                
                return $"{baseUrl}?X-Amz-Signature={signatureB64}&X-Amz-Expires={request.Expiration:yyyy-MM-ddTHH:mm:ssZ}";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating presigned URL");
                throw;
            }
        }

        private bool VerifyIncomingSignature(byte[] data, byte[] signature)
        {
            try
            {
                using var hmac = new HMACSHA256(_telemetryKey);
                var expectedSignature = hmac.ComputeHash(data);
                return CompareHashes(signature, expectedSignature);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying incoming signature");
                return false;
            }
        }

        private TelemetryData? DecryptIncomingData(byte[] encryptedData)
        {
            try
            {
                return DecryptTelemetryData(encryptedData);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error decrypting incoming data");
                return null;
            }
        }

        private bool ValidateTelemetryContent(TelemetryData telemetry)
        {
            try
            {
                // Validate required fields
                if (string.IsNullOrEmpty(telemetry.AgentId))
                    return false;

                if (telemetry.Timestamp == default)
                    return false;

                // Validate timestamp (not too old, not in future)
                var now = DateTime.UtcNow;
                if (telemetry.Timestamp < now.AddHours(-24) || telemetry.Timestamp > now.AddMinutes(5))
                    return false;

                // Validate data size
                var json = JsonSerializer.Serialize(telemetry);
                if (json.Length > 1024 * 1024) // 1MB limit
                    return false;

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating telemetry content");
                return false;
            }
        }

        private bool CompareHashes(byte[] hash1, byte[] hash2)
        {
            if (hash1.Length != hash2.Length)
                return false;

            for (int i = 0; i < hash1.Length; i++)
            {
                if (hash1[i] != hash2[i])
                    return false;
            }

            return true;
        }

        #endregion

        #region Data Classes

        public class SecureTelemetryData
        {
            public string EndpointId { get; set; } = string.Empty;
            public int SequenceNumber { get; set; }
            public DateTime Timestamp { get; set; }
            public TelemetryData? OriginalData { get; set; }
            public byte[] EncryptedData { get; set; } = Array.Empty<byte>();
            public byte[] Signature { get; set; } = Array.Empty<byte>();
            public SecurityMetadata SecurityMetadata { get; set; } = new();
            public Dictionary<string, string> SecurityHeaders { get; set; } = new();
        }

        public class SecurityMetadata
        {
            public string AgentId { get; set; } = string.Empty;
            public string IntegrityHash { get; set; } = string.Empty;
            public string EncryptionVersion { get; set; } = string.Empty;
            public string SigningVersion { get; set; } = string.Empty;
            public bool TamperProtection { get; set; }
        }

        public class PresignedUrlRequest
        {
            public string BucketName { get; set; } = string.Empty;
            public string ObjectKey { get; set; } = string.Empty;
            public DateTime Expiration { get; set; }
            public string EndpointId { get; set; } = string.Empty;
            public string AgentId { get; set; } = string.Empty;
            public DateTime Timestamp { get; set; }
        }

        #endregion

        #region Public Properties

        public string EndpointId => _endpointId;
        public int SequenceNumber => _sequenceNumber;

        #endregion
    }
} 
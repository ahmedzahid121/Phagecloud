using System;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace PhageVirus.Agent.Cloud
{
    /// <summary>
    /// Azure Key Vault service for secrets management
    /// Used only for storing and retrieving sensitive configuration
    /// </summary>
    public class AzureKeyVaultService
    {
        private readonly ILogger<AzureKeyVaultService> _logger;
        private readonly IConfiguration _configuration;
        private SecretClient? _secretClient;
        private string _vaultUrl = string.Empty;
        
        public bool IsInitialized { get; private set; } = false;

        public AzureKeyVaultService(IConfiguration configuration, ILogger<AzureKeyVaultService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public async Task InitializeAsync()
        {
            try
            {
                _logger.LogInformation("Initializing Azure Key Vault service for secrets management");

                // Load configuration
                _vaultUrl = _configuration["cloud:azure:key_vault:vault_url"] ?? string.Empty;
                
                if (string.IsNullOrEmpty(_vaultUrl))
                {
                    _logger.LogWarning("Azure Key Vault URL not configured - secrets management disabled");
                    return;
                }

                // Initialize Key Vault client
                var credential = new DefaultAzureCredential();
                _secretClient = new SecretClient(new Uri(_vaultUrl), credential);

                // Test connection
                await TestConnectionAsync();

                IsInitialized = true;
                _logger.LogInformation("Azure Key Vault service initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize Azure Key Vault service");
                // Don't throw - secrets are optional
            }
        }

        private async Task TestConnectionAsync()
        {
            try
            {
                if (_secretClient != null)
                {
                    // Try to list secrets to test connection
                    await foreach (var secret in _secretClient.GetPropertiesOfSecretsAsync())
                    {
                        _logger.LogDebug($"Found secret: {secret.Name}");
                        break; // Just test one secret
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Azure Key Vault connection test failed");
                throw;
            }
        }

        public async Task<string?> GetSecretAsync(string secretName)
        {
            if (!IsInitialized || _secretClient == null)
            {
                _logger.LogWarning("Azure Key Vault service not initialized");
                return null;
            }

            try
            {
                var secret = await _secretClient.GetSecretAsync(secretName);
                _logger.LogDebug($"Retrieved secret: {secretName}");
                return secret.Value.Value;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error retrieving secret: {secretName}");
                return null;
            }
        }

        public async Task<bool> SetSecretAsync(string secretName, string secretValue)
        {
            if (!IsInitialized || _secretClient == null)
            {
                _logger.LogWarning("Azure Key Vault service not initialized");
                return false;
            }

            try
            {
                await _secretClient.SetSecretAsync(secretName, secretValue);
                _logger.LogDebug($"Stored secret: {secretName}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error storing secret: {secretName}");
                return false;
            }
        }

        public async Task<string?> GetSmtpUsernameAsync()
        {
            var secretName = _configuration["cloud:azure:key_vault:secrets:smtp_username"] ?? "smtp-username";
            return await GetSecretAsync(secretName);
        }

        public async Task<string?> GetSmtpPasswordAsync()
        {
            var secretName = _configuration["cloud:azure:key_vault:secrets:smtp_password"] ?? "smtp-password";
            return await GetSecretAsync(secretName);
        }

        public async Task<string?> GetApiTokenAsync(string tokenName = "default")
        {
            var secretName = _configuration["cloud:azure:key_vault:secrets:api_tokens"] ?? "api-tokens";
            var token = await GetSecretAsync(secretName);
            
            if (!string.IsNullOrEmpty(token))
            {
                // Parse JSON if needed
                try
                {
                    var tokens = System.Text.Json.JsonSerializer.Deserialize<System.Collections.Generic.Dictionary<string, string>>(token);
                    if (tokens != null && tokens.ContainsKey(tokenName))
                    {
                        return tokens[tokenName];
                    }
                }
                catch
                {
                    // Return as-is if not JSON
                    return token;
                }
            }
            
            return null;
        }

        public async Task<bool> SetSmtpCredentialsAsync(string username, string password)
        {
            var usernameSecret = _configuration["cloud:azure:key_vault:secrets:smtp_username"] ?? "smtp-username";
            var passwordSecret = _configuration["cloud:azure:key_vault:secrets:smtp_password"] ?? "smtp-password";

            var usernameResult = await SetSecretAsync(usernameSecret, username);
            var passwordResult = await SetSecretAsync(passwordSecret, password);

            return usernameResult && passwordResult;
        }

        public async Task<bool> SetApiTokenAsync(string tokenName, string tokenValue)
        {
            var secretName = _configuration["cloud:azure:key_vault:secrets:api_tokens"] ?? "api-tokens";
            
            try
            {
                // Get existing tokens
                var existingToken = await GetSecretAsync(secretName);
                var tokens = new System.Collections.Generic.Dictionary<string, string>();

                if (!string.IsNullOrEmpty(existingToken))
                {
                    try
                    {
                        tokens = System.Text.Json.JsonSerializer.Deserialize<System.Collections.Generic.Dictionary<string, string>>(existingToken) ?? tokens;
                    }
                    catch
                    {
                        // If not JSON, treat as single token
                        tokens["default"] = existingToken;
                    }
                }

                // Add or update token
                tokens[tokenName] = tokenValue;

                // Store updated tokens
                var tokensJson = System.Text.Json.JsonSerializer.Serialize(tokens);
                return await SetSecretAsync(secretName, tokensJson);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error setting API token: {tokenName}");
                return false;
            }
        }

        public void Dispose()
        {
            _secretClient?.Dispose();
        }
    }
} 
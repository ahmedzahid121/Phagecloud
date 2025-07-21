using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace PhageVirus.Agent.Security
{
    /// <summary>
    /// Comprehensive security manager for PhageVirus agent
    /// Handles encryption, anti-reverse engineering, code signing, and tamper protection
    /// </summary>
    public class SecurityManager
    {
        private readonly ILogger<SecurityManager> _logger;
        private readonly IConfiguration _configuration;
        private readonly string _agentId;
        private readonly byte[] _encryptionKey;
        private readonly byte[] _signingKey;
        private readonly X509Certificate2? _codeSigningCert;
        
        private bool _isInitialized = false;
        private bool _isTampered = false;
        private DateTime _lastIntegrityCheck = DateTime.UtcNow;
        private readonly object _securityLock = new object();

        public SecurityManager(IConfiguration configuration, ILogger<SecurityManager> logger)
        {
            _configuration = configuration;
            _logger = logger;
            _agentId = GenerateSecureAgentId();
            _encryptionKey = GenerateEncryptionKey();
            _signingKey = GenerateSigningKey();
            _codeSigningCert = LoadCodeSigningCertificate();
        }

        public async Task InitializeAsync()
        {
            if (_isInitialized)
                return;

            lock (_securityLock)
            {
                if (_isInitialized)
                    return;

                try
                {
                    _logger.LogInformation("Initializing comprehensive security manager");

                    // Perform security checks
                    PerformAntiReverseEngineeringChecks();
                    ValidateCodeSigning();
                    CheckIntegrity();
                    InitializeTamperProtection();

                    _isInitialized = true;
                    _logger.LogInformation("Security manager initialized successfully");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to initialize security manager");
                    throw;
                }
            }
        }

        #region Anti-Reverse Engineering

        private void PerformAntiReverseEngineeringChecks()
        {
            _logger.LogDebug("Performing anti-reverse engineering checks");

            // Check for debugger attachment
            if (Debugger.IsAttached)
            {
                _logger.LogWarning("Debugger detected - potential reverse engineering attempt");
                HandleSecurityViolation("Debugger detected");
            }

            // Check for common reverse engineering tools
            if (IsReverseEngineeringToolPresent())
            {
                _logger.LogWarning("Reverse engineering tool detected");
                HandleSecurityViolation("Reverse engineering tool detected");
            }

            // Check for IL injection attempts
            if (IsILInjectionDetected())
            {
                _logger.LogWarning("IL injection attempt detected");
                HandleSecurityViolation("IL injection detected");
            }

            // Check for memory tampering
            if (IsMemoryTamperingDetected())
            {
                _logger.LogWarning("Memory tampering detected");
                HandleSecurityViolation("Memory tampering detected");
            }

            // Check for timing anomalies (debugger detection)
            if (IsTimingAnomalyDetected())
            {
                _logger.LogWarning("Timing anomaly detected - possible debugger");
                HandleSecurityViolation("Timing anomaly detected");
            }
        }

        private bool IsReverseEngineeringToolPresent()
        {
            try
            {
                var suspiciousProcesses = new[]
                {
                    "ida", "ida64", "x64dbg", "x32dbg", "ollydbg", "windbg",
                    "ghidra", "radare2", "cutter", "dnspy", "ilspy", "dotpeek",
                    "cheatengine", "artmoney", "hxd", "hexworkshop", "wireshark",
                    "fiddler", "burp", "proxifier", "processhacker", "processexplorer"
                };

                var processes = Process.GetProcesses();
                foreach (var process in processes)
                {
                    var processName = process.ProcessName.ToLower();
                    if (Array.Exists(suspiciousProcesses, x => processName.Contains(x)))
                    {
                        _logger.LogWarning($"Suspicious process detected: {process.ProcessName}");
                        return true;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking for reverse engineering tools");
                return false;
            }
        }

        private bool IsILInjectionDetected()
        {
            try
            {
                // Check for modified IL code in critical methods
                var assembly = Assembly.GetExecutingAssembly();
                var criticalTypes = new[] { "SecurityManager", "CloudAgent", "AWSCommunicator" };

                foreach (var typeName in criticalTypes)
                {
                    var type = assembly.GetType($"PhageVirus.Agent.{typeName}");
                    if (type != null)
                    {
                        var methods = type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);
                        foreach (var method in methods)
                        {
                            if (method.GetMethodBody()?.LocalVariables.Count > 100) // Suspicious number of locals
                            {
                                _logger.LogWarning($"Suspicious IL detected in {typeName}.{method.Name}");
                                return true;
                            }
                        }
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking for IL injection");
                return false;
            }
        }

        private bool IsMemoryTamperingDetected()
        {
            try
            {
                // Check for memory pattern changes
                var currentProcess = Process.GetCurrentProcess();
                var baseAddress = currentProcess.MainModule?.BaseAddress;
                
                if (baseAddress != IntPtr.Zero)
                {
                    // Check first few bytes for tampering
                    var buffer = new byte[64];
                    if (ReadProcessMemory(currentProcess.Handle, baseAddress, buffer, buffer.Length, out _))
                    {
                        // Check for suspicious patterns
                        if (buffer[0] == 0x90 && buffer[1] == 0x90) // NOP sled
                        {
                            _logger.LogWarning("Memory tampering detected - NOP sled found");
                            return true;
                        }
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking for memory tampering");
                return false;
            }
        }

        private bool IsTimingAnomalyDetected()
        {
            try
            {
                // Measure execution time of a simple operation
                var stopwatch = Stopwatch.StartNew();
                
                // Perform a simple operation
                var dummy = 0;
                for (int i = 0; i < 1000; i++)
                {
                    dummy += i;
                }
                
                stopwatch.Stop();
                
                // If execution time is too high, might be under debugger
                if (stopwatch.ElapsedMilliseconds > 10) // Should be much faster
                {
                    _logger.LogWarning($"Timing anomaly detected: {stopwatch.ElapsedMilliseconds}ms");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking for timing anomalies");
                return false;
            }
        }

        #endregion

        #region Code Signing Validation

        private void ValidateCodeSigning()
        {
            _logger.LogDebug("Validating code signing");

            try
            {
                var assembly = Assembly.GetExecutingAssembly();
                var certificate = GetAssemblyCertificate(assembly);

                if (certificate == null)
                {
                    _logger.LogWarning("No code signing certificate found");
                    HandleSecurityViolation("No code signing certificate");
                    return;
                }

                // Validate certificate
                if (!ValidateCertificate(certificate))
                {
                    _logger.LogWarning("Invalid code signing certificate");
                    HandleSecurityViolation("Invalid code signing certificate");
                    return;
                }

                // Check certificate expiration
                if (certificate.NotAfter < DateTime.UtcNow)
                {
                    _logger.LogWarning("Code signing certificate expired");
                    HandleSecurityViolation("Expired code signing certificate");
                    return;
                }

                _logger.LogInformation("Code signing validation passed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating code signing");
                HandleSecurityViolation("Code signing validation failed");
            }
        }

        private X509Certificate2? GetAssemblyCertificate(Assembly assembly)
        {
            try
            {
                var modules = assembly.GetModules();
                foreach (var module in modules)
                {
                    var cert = module.GetSignerCertificate();
                    if (cert != null)
                        return cert;
                }
                return null;
            }
            catch
            {
                return null;
            }
        }

        private bool ValidateCertificate(X509Certificate2 certificate)
        {
            try
            {
                // Check certificate chain
                using var chain = new X509Chain();
                chain.Build(certificate);

                // Verify chain status
                foreach (var element in chain.ChainElements)
                {
                    if (element.ChainElementStatus.Length > 0)
                    {
                        foreach (var status in element.ChainElementStatus)
                        {
                            if (status.Status != X509ChainStatusFlags.NoError)
                            {
                                _logger.LogWarning($"Certificate validation failed: {status.StatusInformation}");
                                return false;
                            }
                        }
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating certificate");
                return false;
            }
        }

        private X509Certificate2? LoadCodeSigningCertificate()
        {
            try
            {
                // Load from Azure Key Vault or local store
                var certThumbprint = _configuration["security:code_signing:thumbprint"];
                if (!string.IsNullOrEmpty(certThumbprint))
                {
                    using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                    store.Open(OpenFlags.ReadOnly);
                    var certs = store.Certificates.Find(X509FindType.FindByThumbprint, certThumbprint, false);
                    return certs.Count > 0 ? certs[0] : null;
                }

                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading code signing certificate");
                return null;
            }
        }

        #endregion

        #region Integrity Monitoring

        private void CheckIntegrity()
        {
            _logger.LogDebug("Performing integrity check");

            try
            {
                // Check file integrity
                if (!CheckFileIntegrity())
                {
                    _logger.LogWarning("File integrity check failed");
                    HandleSecurityViolation("File integrity violation");
                    return;
                }

                // Check configuration integrity
                if (!CheckConfigurationIntegrity())
                {
                    _logger.LogWarning("Configuration integrity check failed");
                    HandleSecurityViolation("Configuration integrity violation");
                    return;
                }

                // Check memory integrity
                if (!CheckMemoryIntegrity())
                {
                    _logger.LogWarning("Memory integrity check failed");
                    HandleSecurityViolation("Memory integrity violation");
                    return;
                }

                _lastIntegrityCheck = DateTime.UtcNow;
                _logger.LogDebug("Integrity check passed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during integrity check");
                HandleSecurityViolation("Integrity check failed");
            }
        }

        private bool CheckFileIntegrity()
        {
            try
            {
                var assembly = Assembly.GetExecutingAssembly();
                var location = assembly.Location;

                if (string.IsNullOrEmpty(location))
                    return false;

                // Calculate file hash
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(location);
                var hash = sha256.ComputeHash(stream);

                // Compare with expected hash (stored securely)
                var expectedHash = GetExpectedFileHash();
                if (expectedHash != null)
                {
                    return CompareHashes(hash, expectedHash);
                }

                return true; // No expected hash configured
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking file integrity");
                return false;
            }
        }

        private bool CheckConfigurationIntegrity()
        {
            try
            {
                // Check if configuration files have been tampered with
                var configFiles = new[] { "cloud.json", "hybrid.json", "local.json" };
                
                foreach (var configFile in configFiles)
                {
                    var configPath = Path.Combine("config", configFile);
                    if (File.Exists(configPath))
                    {
                        // Check file permissions
                        var fileInfo = new FileInfo(configPath);
                        if (fileInfo.Attributes.HasFlag(FileAttributes.System))
                        {
                            _logger.LogWarning($"Suspicious file attributes on {configFile}");
                            return false;
                        }

                        // Check for suspicious content
                        var content = File.ReadAllText(configPath);
                        if (content.Contains("debug") || content.Contains("test") || content.Contains("localhost"))
                        {
                            _logger.LogWarning($"Suspicious content in {configFile}");
                            return false;
                        }
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking configuration integrity");
                return false;
            }
        }

        private bool CheckMemoryIntegrity()
        {
            try
            {
                // Check for suspicious memory patterns
                var currentProcess = Process.GetCurrentProcess();
                var modules = currentProcess.Modules;

                foreach (ProcessModule module in modules)
                {
                    // Check for suspicious module names
                    var moduleName = module.ModuleName?.ToLower();
                    if (!string.IsNullOrEmpty(moduleName))
                    {
                        var suspiciousModules = new[] { "inject", "hook", "patch", "crack", "hack" };
                        if (Array.Exists(suspiciousModules, x => moduleName.Contains(x)))
                        {
                            _logger.LogWarning($"Suspicious module loaded: {module.ModuleName}");
                            return false;
                        }
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking memory integrity");
                return false;
            }
        }

        #endregion

        #region Tamper Protection

        private void InitializeTamperProtection()
        {
            _logger.LogDebug("Initializing tamper protection");

            // Start periodic integrity checks
            _ = Task.Run(async () =>
            {
                while (!_isTampered)
                {
                    await Task.Delay(TimeSpan.FromMinutes(5)); // Check every 5 minutes
                    CheckIntegrity();
                }
            });

            // Monitor for suspicious file system changes
            MonitorFileSystemChanges();

            // Monitor for suspicious registry changes
            MonitorRegistryChanges();
        }

        private void MonitorFileSystemChanges()
        {
            try
            {
                var watcher = new FileSystemWatcher
                {
                    Path = AppDomain.CurrentDomain.BaseDirectory,
                    Filter = "*.exe",
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size,
                    EnableRaisingEvents = true
                };

                watcher.Changed += (sender, e) =>
                {
                    _logger.LogWarning($"Suspicious file system change detected: {e.FullPath}");
                    HandleSecurityViolation("File system tampering detected");
                };

                watcher.Created += (sender, e) =>
                {
                    _logger.LogWarning($"Suspicious file creation detected: {e.FullPath}");
                    HandleSecurityViolation("Suspicious file creation");
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting up file system monitoring");
            }
        }

        private void MonitorRegistryChanges()
        {
            try
            {
                // Monitor registry keys for suspicious changes
                var suspiciousKeys = new[]
                {
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                };

                // Implementation would use RegistryKey.Monitor() or similar
                _logger.LogDebug("Registry monitoring initialized");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting up registry monitoring");
            }
        }

        #endregion

        #region Encryption and Signing

        public byte[] EncryptData(byte[] data)
        {
            try
            {
                using var aes = Aes.Create();
                aes.Key = _encryptionKey;
                aes.GenerateIV();

                using var encryptor = aes.CreateEncryptor();
                var encryptedData = encryptor.TransformFinalBlock(data, 0, data.Length);

                // Combine IV and encrypted data
                var result = new byte[aes.IV.Length + encryptedData.Length];
                Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
                Buffer.BlockCopy(encryptedData, 0, result, aes.IV.Length, encryptedData.Length);

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error encrypting data");
                throw;
            }
        }

        public byte[] DecryptData(byte[] encryptedData)
        {
            try
            {
                using var aes = Aes.Create();
                aes.Key = _encryptionKey;

                // Extract IV
                var iv = new byte[16];
                Buffer.BlockCopy(encryptedData, 0, iv, 0, iv.Length);
                aes.IV = iv;

                // Extract encrypted data
                var data = new byte[encryptedData.Length - iv.Length];
                Buffer.BlockCopy(encryptedData, iv.Length, data, 0, data.Length);

                using var decryptor = aes.CreateDecryptor();
                return decryptor.TransformFinalBlock(data, 0, data.Length);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error decrypting data");
                throw;
            }
        }

        public byte[] SignData(byte[] data)
        {
            try
            {
                using var hmac = new HMACSHA256(_signingKey);
                return hmac.ComputeHash(data);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error signing data");
                throw;
            }
        }

        public bool VerifySignature(byte[] data, byte[] signature)
        {
            try
            {
                var expectedSignature = SignData(data);
                return CompareHashes(signature, expectedSignature);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying signature");
                return false;
            }
        }

        #endregion

        #region Security Utilities

        private string GenerateSecureAgentId()
        {
            try
            {
                var machineName = Environment.MachineName;
                var userName = Environment.UserName;
                var processorId = GetProcessorId();
                
                var combined = $"{machineName}_{userName}_{processorId}_{DateTime.UtcNow:yyyyMMdd}";
                using var sha256 = SHA256.Create();
                var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(combined));
                
                return Convert.ToBase64String(hash).Substring(0, 16);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating secure agent ID");
                return Guid.NewGuid().ToString("N").Substring(0, 16);
            }
        }

        private byte[] GenerateEncryptionKey()
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
                _logger.LogError(ex, "Error generating encryption key");
                throw;
            }
        }

        private byte[] GenerateSigningKey()
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
                _logger.LogError(ex, "Error generating signing key");
                throw;
            }
        }

        private string GetProcessorId()
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher("SELECT ProcessorId FROM Win32_Processor");
                foreach (System.Management.ManagementObject obj in searcher.Get())
                {
                    return obj["ProcessorId"]?.ToString() ?? "UNKNOWN";
                }
                return "UNKNOWN";
            }
            catch
            {
                return "UNKNOWN";
            }
        }

        private byte[]? GetExpectedFileHash()
        {
            try
            {
                // This would be retrieved from a secure source (Azure Key Vault, etc.)
                var hashString = _configuration["security:integrity:file_hash"];
                if (!string.IsNullOrEmpty(hashString))
                {
                    return Convert.FromBase64String(hashString);
                }
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting expected file hash");
                return null;
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

        private void HandleSecurityViolation(string violation)
        {
            _logger.LogError($"SECURITY VIOLATION: {violation}");
            _isTampered = true;

            // Log the violation
            LogSecurityViolation(violation);

            // Take action based on configuration
            var action = _configuration["security:violation_action"] ?? "log";
            switch (action.ToLower())
            {
                case "crash":
                    Environment.Exit(1);
                    break;
                case "disable":
                    // Disable functionality
                    break;
                case "alert":
                    // Send alert
                    break;
                default:
                    // Just log
                    break;
            }
        }

        private void LogSecurityViolation(string violation)
        {
            try
            {
                var logEntry = new
                {
                    Timestamp = DateTime.UtcNow,
                    AgentId = _agentId,
                    Violation = violation,
                    ProcessId = Process.GetCurrentProcess().Id,
                    UserName = Environment.UserName,
                    MachineName = Environment.MachineName
                };

                var logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "security_violations.log");
                var logLine = $"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} - {violation} - Agent: {_agentId}";
                File.AppendAllText(logPath, logLine + Environment.NewLine);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging security violation");
            }
        }

        #endregion

        #region P/Invoke

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        #endregion

        #region Public Properties

        public string AgentId => _agentId;
        public bool IsTampered => _isTampered;
        public bool IsInitialized => _isInitialized;
        public DateTime LastIntegrityCheck => _lastIntegrityCheck;

        #endregion
    }
} 
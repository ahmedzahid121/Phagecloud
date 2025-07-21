using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using PhageVirus.Agent.Core;

namespace PhageVirus.Agent
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            try
            {
                Console.WriteLine("🦠 PhageVirus Cloud Agent v2.0.0");
                Console.WriteLine("Starting AWS-focused hybrid cloud security agent...");
                Console.WriteLine("Region: ap-southeast-2 (Sydney)");
                Console.WriteLine("Secrets: Azure Key Vault");
                Console.WriteLine("Security: Enhanced encryption, anti-reverse engineering, tamper protection");
                Console.WriteLine();

                // Build configuration
                var configuration = BuildConfiguration();

                // Create host
                var host = CreateHostBuilder(args, configuration).Build();

                // Get services
                var logger = host.Services.GetRequiredService<ILogger<Program>>();
                var cloudAgent = host.Services.GetRequiredService<CloudAgent>();

                logger.LogInformation("PhageVirus Cloud Agent starting with enhanced security...");

                // Start the agent
                await cloudAgent.StartAsync();

                logger.LogInformation("PhageVirus Cloud Agent started successfully");
                Console.WriteLine("✅ Agent is running with enhanced security. Press Ctrl+C to stop.");

                // Wait for shutdown signal
                await host.RunAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Fatal error: {ex.Message}");
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
            }
        }

        private static IConfiguration BuildConfiguration()
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("config/cloud.json", optional: true, reloadOnChange: true)
                .AddJsonFile("config/hybrid.json", optional: true, reloadOnChange: true)
                .AddJsonFile("config/local.json", optional: true, reloadOnChange: true)
                .AddEnvironmentVariables()
                .AddCommandLine(Environment.GetCommandLineArgs());

            return builder.Build();
        }

        private static IHostBuilder CreateHostBuilder(string[] args, IConfiguration configuration)
        {
            return Host.CreateDefaultBuilder(args)
                .ConfigureServices((hostContext, services) =>
                {
                    // Add configuration
                    services.AddSingleton<IConfiguration>(configuration);

                    // Add logging
                    services.AddLogging(builder =>
                    {
                        builder.AddConsole();
                        builder.AddDebug();
                        
                        // Set log level from configuration
                        var logLevel = configuration.GetValue<string>("Performance:DefaultLogLevel", "Information");
                        if (Enum.TryParse<LogLevel>(logLevel, true, out var level))
                        {
                            builder.SetMinimumLevel(level);
                        }
                    });

                    // Add health checks
                    services.AddHealthChecks();

                    // Add security manager (core security)
                    services.AddSingleton<Security.SecurityManager>();

                    // Add telemetry security (encrypted communications)
                    services.AddSingleton<Security.TelemetrySecurity>();

                    // Add threat detection engine (behavioral AI, KQL)
                    services.AddSingleton<Security.ThreatDetectionEngine>();

                    // Add network security (TLS, IP whitelisting, WAF)
                    services.AddSingleton<Security.NetworkSecurity>();

                    // Add cloud agent
                    services.AddSingleton<CloudAgent>();

                    // Add AWS communicator (primary cloud service)
                    services.AddSingleton<Cloud.AWSCommunicator>();

                    // Add Azure Key Vault service (for secrets only)
                    services.AddSingleton<Cloud.AzureKeyVaultService>();

                    // Add local security engine
                    services.AddSingleton<Local.LocalSecurityEngine>();

                    // Add telemetry collector (AWS-focused)
                    services.AddSingleton<Cloud.TelemetryCollector>();

                    // Add HTTP client for cloud communication
                    services.AddHttpClient();
                })
                .ConfigureLogging(logging =>
                {
                    logging.ClearProviders();
                    logging.AddConsole();
                    logging.AddDebug();
                })
                .UseWindowsService(options =>
                {
                    options.ServiceName = "PhageVirus Cloud Agent";
                });
        }
    }
} 
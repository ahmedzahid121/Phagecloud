using System;
using System.Threading.Tasks;
using System.Linq; // Added for .Sum() and .Where()

namespace PhageVirus.Testing
{
    /// <summary>
    /// Main test runner for PhageVirus EDR system
    /// Executes all test suites and generates comprehensive reports
    /// </summary>
    public class RunTests
    {
        public static async Task Main(string[] args)
        {
            Console.WriteLine("🦠 PhageVirus EDR System - Industry Standard Testing Framework");
            Console.WriteLine("=".PadRight(80, '='));
            Console.WriteLine($"Started: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine();

            try
            {
                // Parse command line arguments
                var config = ParseArguments(args);

                // Create test runner
                var testRunner = new TestRunner(config);

                Console.WriteLine("📋 Test Configuration:");
                Console.WriteLine($"   Unit Tests: {(config.RunUnitTests ? "✅ Enabled" : "❌ Disabled")}");
                Console.WriteLine($"   Integration Tests: {(config.RunIntegrationTests ? "✅ Enabled" : "❌ Disabled")}");
                Console.WriteLine($"   Functional Tests: {(config.RunFunctionalTests ? "✅ Enabled" : "❌ Disabled")}");
                Console.WriteLine($"   Performance Tests: {(config.RunPerformanceTests ? "✅ Enabled" : "❌ Disabled")}");
                Console.WriteLine($"   Security Tests: {(config.RunSecurityTests ? "✅ Enabled" : "❌ Disabled")}");
                Console.WriteLine($"   Regression Tests: {(config.RunRegressionTests ? "✅ Enabled" : "❌ Disabled")}");
                Console.WriteLine($"   Manual QA Tests: {(config.RunManualQATests ? "✅ Enabled" : "❌ Disabled")}");
                Console.WriteLine();

                // Run all tests
                Console.WriteLine("🚀 Starting comprehensive test execution...");
                Console.WriteLine();

                var report = await testRunner.RunAllTestsAsync();

                // Display summary
                DisplayTestSummary(report);

                // Display detailed results
                DisplayDetailedResults(report);

                // Display recommendations
                DisplayRecommendations(report);

                Console.WriteLine();
                Console.WriteLine("=".PadRight(80, '='));
                Console.WriteLine("✅ Test execution completed successfully!");
                Console.WriteLine($"📄 Detailed report saved to: {GetReportFilePath()}");
                Console.WriteLine("=".PadRight(80, '='));

                // Exit with appropriate code
                Environment.Exit(report.TestSuites.Values.Sum(ts => ts.FailedTests) > 0 ? 1 : 0);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Test execution failed: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                Environment.Exit(1);
            }
        }

        /// <summary>
        /// Parse command line arguments to configure test execution
        /// </summary>
        private static TestConfiguration ParseArguments(string[] args)
        {
            var config = new TestConfiguration();

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLower())
                {
                    case "--unit":
                    case "-u":
                        config.RunUnitTests = true;
                        break;
                    case "--integration":
                    case "-i":
                        config.RunIntegrationTests = true;
                        break;
                    case "--functional":
                    case "-f":
                        config.RunFunctionalTests = true;
                        break;
                    case "--performance":
                    case "-p":
                        config.RunPerformanceTests = true;
                        break;
                    case "--security":
                    case "-s":
                        config.RunSecurityTests = true;
                        break;
                    case "--regression":
                    case "-r":
                        config.RunRegressionTests = true;
                        break;
                    case "--manual":
                    case "-m":
                        config.RunManualQATests = true;
                        break;
                    case "--all":
                    case "-a":
                        config.RunUnitTests = true;
                        config.RunIntegrationTests = true;
                        config.RunFunctionalTests = true;
                        config.RunPerformanceTests = true;
                        config.RunSecurityTests = true;
                        config.RunRegressionTests = true;
                        config.RunManualQATests = false; // Manual tests are optional
                        break;
                    case "--duration":
                        if (i + 1 < args.Length && int.TryParse(args[i + 1], out int duration))
                        {
                            config.PerformanceTestDuration = duration;
                            i++;
                        }
                        break;
                    case "--iterations":
                        if (i + 1 < args.Length && int.TryParse(args[i + 1], out int iterations))
                        {
                            config.StressTestIterations = iterations;
                            i++;
                        }
                        break;
                    case "--memory":
                        if (i + 1 < args.Length && double.TryParse(args[i + 1], out double memory))
                        {
                            config.MaxMemoryUsageMB = memory;
                            i++;
                        }
                        break;
                    case "--cpu":
                        if (i + 1 < args.Length && double.TryParse(args[i + 1], out double cpu))
                        {
                            config.MaxCpuUsagePercent = cpu;
                            i++;
                        }
                        break;
                    case "--help":
                    case "-h":
                        DisplayHelp();
                        Environment.Exit(0);
                        break;
                }
            }

            return config;
        }

        /// <summary>
        /// Display help information
        /// </summary>
        private static void DisplayHelp()
        {
            Console.WriteLine("PhageVirus EDR System - Testing Framework");
            Console.WriteLine();
            Console.WriteLine("Usage: dotnet run [options]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  --unit, -u              Run unit tests");
            Console.WriteLine("  --integration, -i       Run integration tests");
            Console.WriteLine("  --functional, -f        Run functional tests");
            Console.WriteLine("  --performance, -p       Run performance tests");
            Console.WriteLine("  --security, -s          Run security tests");
            Console.WriteLine("  --regression, -r        Run regression tests");
            Console.WriteLine("  --manual, -m            Run manual QA tests");
            Console.WriteLine("  --all, -a               Run all automated tests");
            Console.WriteLine("  --duration <seconds>    Performance test duration (default: 30)");
            Console.WriteLine("  --iterations <count>    Stress test iterations (default: 1000)");
            Console.WriteLine("  --memory <mb>           Max memory usage threshold (default: 500)");
            Console.WriteLine("  --cpu <percent>         Max CPU usage threshold (default: 80)");
            Console.WriteLine("  --help, -h              Show this help message");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  dotnet run --all                    # Run all automated tests");
            Console.WriteLine("  dotnet run --unit --integration     # Run unit and integration tests");
            Console.WriteLine("  dotnet run --performance --duration 60  # Run performance tests for 60 seconds");
        }

        /// <summary>
        /// Display test summary
        /// </summary>
        private static void DisplayTestSummary(TestReport report)
        {
            var totalTests = report.TestSuites.Values.Sum(ts => ts.TotalTests);
            var passedTests = report.TestSuites.Values.Sum(ts => ts.PassedTests);
            var failedTests = report.TestSuites.Values.Sum(ts => ts.FailedTests);
            var successRate = totalTests > 0 ? (double)passedTests / totalTests * 100 : 0;

            Console.WriteLine("📊 TEST SUMMARY");
            Console.WriteLine("-".PadRight(40, '-'));
            Console.WriteLine($"Total Tests: {totalTests}");
            Console.WriteLine($"Passed: {passedTests}");
            Console.WriteLine($"Failed: {failedTests}");
            Console.WriteLine($"Success Rate: {successRate:F2}%");
            Console.WriteLine($"Duration: {report.TotalDuration}");
            Console.WriteLine($"Overall Status: {(successRate >= 95 ? "✅ PASS" : "❌ FAIL")}");
            Console.WriteLine();

            // Test suite summary
            Console.WriteLine("📋 Test Suite Results:");
            foreach (var (suiteName, suiteResults) in report.TestSuites)
            {
                var suiteSuccessRate = suiteResults.TotalTests > 0 ? (double)suiteResults.PassedTests / suiteResults.TotalTests * 100 : 0;
                var status = suiteResults.PassedTests == suiteResults.TotalTests ? "✅" : "❌";
                Console.WriteLine($"  {status} {suiteName}: {suiteResults.PassedTests}/{suiteResults.TotalTests} passed ({suiteSuccessRate:F1}%)");
            }
            Console.WriteLine();
        }

        /// <summary>
        /// Display detailed test results
        /// </summary>
        private static void DisplayDetailedResults(TestReport report)
        {
            Console.WriteLine("🔍 DETAILED RESULTS");
            Console.WriteLine("-".PadRight(40, '-'));

            foreach (var (suiteName, suiteResults) in report.TestSuites)
            {
                if (suiteResults.FailedTests > 0)
                {
                    Console.WriteLine($"❌ {suiteName} - Failed Tests:");
                    foreach (var testResult in suiteResults.TestResults.Where(r => !r.Passed))
                    {
                        Console.WriteLine($"   • {testResult.TestName}");
                        if (!string.IsNullOrEmpty(testResult.ErrorMessage))
                        {
                            Console.WriteLine($"     Error: {testResult.ErrorMessage}");
                        }
                    }
                    Console.WriteLine();
                }
            }

            // Performance metrics
            if (report.PerformanceMetrics.Any())
            {
                Console.WriteLine("📈 Performance Metrics:");
                foreach (var metric in report.PerformanceMetrics)
                {
                    Console.WriteLine($"   • {metric.Name}: {metric.Value} {metric.Unit}");
                }
                Console.WriteLine();
            }

            // Security findings
            if (report.SecurityFindings.Any())
            {
                Console.WriteLine("🔒 Security Findings:");
                foreach (var finding in report.SecurityFindings)
                {
                    var severity = finding.Severity switch
                    {
                        SecuritySeverity.Critical => "🔴 CRITICAL",
                        SecuritySeverity.High => "🟠 HIGH",
                        SecuritySeverity.Medium => "🟡 MEDIUM",
                        SecuritySeverity.Low => "🟢 LOW",
                        _ => "⚪ INFO"
                    };
                    Console.WriteLine($"   {severity} {finding.Title}");
                    Console.WriteLine($"     {finding.Description}");
                }
                Console.WriteLine();
            }
        }

        /// <summary>
        /// Display recommendations based on test results
        /// </summary>
        private static void DisplayRecommendations(TestReport report)
        {
            Console.WriteLine("💡 RECOMMENDATIONS");
            Console.WriteLine("-".PadRight(40, '-'));

            var totalTests = report.TestSuites.Values.Sum(ts => ts.TotalTests);
            var passedTests = report.TestSuites.Values.Sum(ts => ts.PassedTests);
            var successRate = totalTests > 0 ? (double)passedTests / totalTests * 100 : 0;

            if (successRate >= 95)
            {
                Console.WriteLine("✅ All tests passed successfully. System is ready for production deployment.");
            }
            else if (successRate >= 80)
            {
                Console.WriteLine("⚠️  Most tests passed. Review failed tests before production deployment.");
                Console.WriteLine("   • Investigate failed test cases");
                Console.WriteLine("   • Fix critical issues");
                Console.WriteLine("   • Re-run tests after fixes");
            }
            else
            {
                Console.WriteLine("❌ Multiple test failures detected. System requires fixes before deployment.");
                Console.WriteLine("   • Address all failed tests");
                Console.WriteLine("   • Fix security vulnerabilities");
                Console.WriteLine("   • Optimize performance issues");
                Console.WriteLine("   • Complete full test suite after fixes");
            }

            if (report.SecurityFindings.Any(f => f.Severity >= SecuritySeverity.High))
            {
                Console.WriteLine("🔴 Critical security findings detected. Address before deployment.");
            }

            if (report.PerformanceMetrics.Any(m => m.Name.Contains("Memory") && m.Value > 500))
            {
                Console.WriteLine("⚠️  High memory usage detected. Consider optimization.");
            }

            if (report.PerformanceMetrics.Any(m => m.Name.Contains("CPU") && m.Value > 80))
            {
                Console.WriteLine("⚠️  High CPU usage detected. Consider optimization.");
            }

            Console.WriteLine();
            Console.WriteLine("📚 Next Steps:");
            Console.WriteLine("   • Review detailed test report");
            Console.WriteLine("   • Address any failed tests");
            Console.WriteLine("   • Fix security vulnerabilities");
            Console.WriteLine("   • Optimize performance bottlenecks");
            Console.WriteLine("   • Re-run tests after fixes");
            Console.WriteLine("   • Deploy to production when all tests pass");
        }

        /// <summary>
        /// Get the report file path
        /// </summary>
        private static string GetReportFilePath()
        {
            return System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                $"phagevirus_test_results_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
            );
        }
    }
} 
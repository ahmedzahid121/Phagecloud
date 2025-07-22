using System;
using System.Threading.Tasks;

namespace PhageVirus.Testing
{
    public class SimpleMain
    {
        public static async Task Main(string[] args)
        {
            try
            {
                var testRunner = new SimpleTestRunner();
                await testRunner.RunAllTestsAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Test execution failed: {ex.Message}");
                Environment.Exit(1);
            }
        }
    }
} 
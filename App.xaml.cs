using System.Windows;

namespace PhageVirus
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            
            // Set up global exception handling
            Current.DispatcherUnhandledException += (sender, args) =>
            {
                MessageBox.Show($"An error occurred: {args.Exception.Message}", 
                    "PhageVirus Error", MessageBoxButton.OK, MessageBoxImage.Error);
                args.Handled = true;
            };
        }
    }
} 
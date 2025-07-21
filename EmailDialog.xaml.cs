using System;
using System.Windows;

namespace PhageVirus
{
    public partial class EmailDialog : Window
    {
        public bool SendToEmail { get; private set; }
        public string EmailAddress { get; private set; } = "";

        public EmailDialog()
        {
            InitializeComponent();
            
            // Set default email if available
            EmailTextBox.Text = Environment.UserName + "@example.com";
        }

        private void SendToEmailCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            EmailTextBox.IsEnabled = true;
            EmailTextBox.Background = System.Windows.Media.Brushes.White;
            EmailTextBox.Foreground = System.Windows.Media.Brushes.Black;
        }

        private void SendToEmailCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            EmailTextBox.IsEnabled = false;
            EmailTextBox.Background = System.Windows.Media.Brushes.Gray;
            EmailTextBox.Foreground = System.Windows.Media.Brushes.DarkGray;
        }

        private void RunButton_Click(object sender, RoutedEventArgs e)
        {
            SendToEmail = SendToEmailCheckBox.IsChecked ?? false;
            EmailAddress = EmailTextBox.Text.Trim();
            
            if (SendToEmail && string.IsNullOrEmpty(EmailAddress))
            {
                MessageBox.Show("Please enter a valid email address.", "Email Required", 
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            
            if (SendToEmail && !IsValidEmail(EmailAddress))
            {
                MessageBox.Show("Please enter a valid email address format.", "Invalid Email", 
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            
            DialogResult = true;
            Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private bool IsValidEmail(string email)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email;
            }
            catch
            {
                return false;
            }
        }
    }
} 
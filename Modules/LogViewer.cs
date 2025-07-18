using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Threading;

namespace PhageVirus.Modules
{
    public class LogViewer : Window
    {
        private readonly ObservableCollection<LogEntry> logEntries = new ObservableCollection<LogEntry>();
        private readonly DispatcherTimer refreshTimer;
        private TextBox searchBox;
        private ComboBox logTypeFilter;
        private ComboBox severityFilter;
        private ListView logListView;
        private TextBox detailsBox;
        private Button exportButton;
        private Button clearButton;
        private Button refreshButton;
        private Label statusLabel;
        
        private string currentFilter = "";
        private string currentLogType = "All";
        private string currentSeverity = "All";
        private bool isAutoRefresh = true;

        public LogViewer()
        {
            Title = "PhageVirus - Advanced Log Viewer";
            Width = 1200;
            Height = 800;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            
            // Create UI layout
            CreateUI();
            
            // Set up data binding
            logListView.ItemsSource = logEntries;
            
            // Set up refresh timer
            refreshTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(2)
            };
            refreshTimer.Tick += RefreshTimer_Tick;
            refreshTimer.Start();
            
            // Load initial data
            LoadLogs();
            
            // Set up filtering
            SetupFiltering();
        }

        private void CreateUI()
        {
            var mainGrid = new Grid();
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Toolbar
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Filters
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // Log list
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Details
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Status

            // Toolbar
            var toolbar = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Margin = new Thickness(5)
            };

            refreshButton = new Button
            {
                Content = "🔄 Refresh",
                Margin = new Thickness(0, 0, 5, 0),
                Padding = new Thickness(10, 5, 10, 5)
            };
            refreshButton.Click += RefreshButton_Click;

            exportButton = new Button
            {
                Content = "📁 Export",
                Margin = new Thickness(0, 0, 5, 0),
                Padding = new Thickness(10, 5, 10, 5)
            };
            exportButton.Click += ExportButton_Click;

            clearButton = new Button
            {
                Content = "🗑️ Clear",
                Margin = new Thickness(0, 0, 5, 0),
                Padding = new Thickness(10, 5, 10, 5)
            };
            clearButton.Click += ClearButton_Click;

            var autoRefreshCheckBox = new CheckBox
            {
                Content = "Auto Refresh",
                IsChecked = true,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(10, 0, 0, 0)
            };
            autoRefreshCheckBox.Checked += (s, e) => isAutoRefresh = true;
            autoRefreshCheckBox.Unchecked += (s, e) => isAutoRefresh = false;

            toolbar.Children.Add(refreshButton);
            toolbar.Children.Add(exportButton);
            toolbar.Children.Add(clearButton);
            toolbar.Children.Add(autoRefreshCheckBox);

            Grid.SetRow(toolbar, 0);
            mainGrid.Children.Add(toolbar);

            // Filters
            var filterPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Margin = new Thickness(5)
            };

            filterPanel.Children.Add(new Label { Content = "Search:", VerticalAlignment = VerticalAlignment.Center });
            
            searchBox = new TextBox
            {
                Width = 200,
                Margin = new Thickness(5, 0, 10, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            searchBox.TextChanged += SearchBox_TextChanged;
            filterPanel.Children.Add(searchBox);

            filterPanel.Children.Add(new Label { Content = "Log Type:", VerticalAlignment = VerticalAlignment.Center });
            
            logTypeFilter = new ComboBox
            {
                Width = 120,
                Margin = new Thickness(5, 0, 10, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            logTypeFilter.Items.Add("All");
            logTypeFilter.Items.Add("INFO");
            logTypeFilter.Items.Add("WARNING");
            logTypeFilter.Items.Add("ERROR");
            logTypeFilter.Items.Add("SUCCESS");
            logTypeFilter.Items.Add("THREAT");
            logTypeFilter.Items.Add("NEUTRALIZATION");
            logTypeFilter.Items.Add("SCAN");
            logTypeFilter.Items.Add("PROCESS_CREATED");
            logTypeFilter.Items.Add("PROCESS_TERMINATED");
            logTypeFilter.Items.Add("MEMORY_INJECTION");
            logTypeFilter.Items.Add("FILE_OPERATION");
            logTypeFilter.Items.Add("REGISTRY_OPERATION");
            logTypeFilter.Items.Add("NETWORK_ACTIVITY");
            logTypeFilter.Items.Add("SELF_REPLICATION");
            logTypeFilter.Items.Add("PERSISTENCE");
            logTypeFilter.SelectedIndex = 0;
            logTypeFilter.SelectionChanged += LogTypeFilter_SelectionChanged;
            filterPanel.Children.Add(logTypeFilter);

            filterPanel.Children.Add(new Label { Content = "Severity:", VerticalAlignment = VerticalAlignment.Center });
            
            severityFilter = new ComboBox
            {
                Width = 100,
                Margin = new Thickness(5, 0, 10, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            severityFilter.Items.Add("All");
            severityFilter.Items.Add("Low");
            severityFilter.Items.Add("Medium");
            severityFilter.Items.Add("High");
            severityFilter.Items.Add("Critical");
            severityFilter.SelectedIndex = 0;
            severityFilter.SelectionChanged += SeverityFilter_SelectionChanged;
            filterPanel.Children.Add(severityFilter);

            Grid.SetRow(filterPanel, 1);
            mainGrid.Children.Add(filterPanel);

            // Log list
            logListView = new ListView
            {
                Margin = new Thickness(5)
            };
            logListView.SelectionChanged += LogListView_SelectionChanged;

            var gridView = new GridView();
            
            var timestampColumn = new GridViewColumn
            {
                Header = "Timestamp",
                Width = 150,
                DisplayMemberBinding = new Binding("Timestamp")
            };
            gridView.Columns.Add(timestampColumn);

            var typeColumn = new GridViewColumn
            {
                Header = "Type",
                Width = 120,
                DisplayMemberBinding = new Binding("LogType")
            };
            gridView.Columns.Add(typeColumn);

            var severityColumn = new GridViewColumn
            {
                Header = "Severity",
                Width = 80,
                DisplayMemberBinding = new Binding("Severity")
            };
            gridView.Columns.Add(severityColumn);

            var messageColumn = new GridViewColumn
            {
                Header = "Message",
                Width = 400,
                DisplayMemberBinding = new Binding("Message")
            };
            gridView.Columns.Add(messageColumn);

            var processColumn = new GridViewColumn
            {
                Header = "Process",
                Width = 100,
                DisplayMemberBinding = new Binding("ProcessName")
            };
            gridView.Columns.Add(processColumn);

            logListView.View = gridView;

            Grid.SetRow(logListView, 2);
            mainGrid.Children.Add(logListView);

            // Details panel
            var detailsPanel = new StackPanel
            {
                Margin = new Thickness(5)
            };
            detailsPanel.Children.Add(new Label { Content = "Details:", FontWeight = FontWeights.Bold });

            detailsBox = new TextBox
            {
                Height = 100,
                IsReadOnly = true,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 10
            };
            detailsPanel.Children.Add(detailsBox);

            Grid.SetRow(detailsPanel, 3);
            mainGrid.Children.Add(detailsPanel);

            // Status bar
            statusLabel = new Label
            {
                Content = "Ready",
                Margin = new Thickness(5),
                FontStyle = FontStyles.Italic
            };

            Grid.SetRow(statusLabel, 4);
            mainGrid.Children.Add(statusLabel);

            Content = mainGrid;
        }

        private void SetupFiltering()
        {
            var view = CollectionViewSource.GetDefaultView(logEntries);
            view.Filter = LogEntryFilter;
        }

        private bool LogEntryFilter(object item)
        {
            if (item is not LogEntry entry)
                return false;

            // Apply search filter
            if (!string.IsNullOrEmpty(currentFilter))
            {
                if (!entry.Message.ToLower().Contains(currentFilter.ToLower()) &&
                    !entry.LogType.ToLower().Contains(currentFilter.ToLower()) &&
                    !entry.ProcessName.ToLower().Contains(currentFilter.ToLower()))
                {
                    return false;
                }
            }

            // Apply log type filter
            if (currentLogType != "All" && entry.LogType != currentLogType)
            {
                return false;
            }

            // Apply severity filter
            if (currentSeverity != "All" && entry.Severity != currentSeverity)
            {
                return false;
            }

            return true;
        }

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            currentFilter = searchBox.Text;
            CollectionViewSource.GetDefaultView(logEntries).Refresh();
            UpdateStatus();
        }

        private void LogTypeFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            currentLogType = logTypeFilter.SelectedItem?.ToString() ?? "All";
            CollectionViewSource.GetDefaultView(logEntries).Refresh();
            UpdateStatus();
        }

        private void SeverityFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            currentSeverity = severityFilter.SelectedItem?.ToString() ?? "All";
            CollectionViewSource.GetDefaultView(logEntries).Refresh();
            UpdateStatus();
        }

        private void LogListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (logListView.SelectedItem is LogEntry selectedEntry)
            {
                ShowEntryDetails(selectedEntry);
            }
        }

        private void ShowEntryDetails(LogEntry entry)
        {
            var details = new StringBuilder();
            details.AppendLine($"Timestamp: {entry.Timestamp}");
            details.AppendLine($"Log Type: {entry.LogType}");
            details.AppendLine($"Severity: {entry.Severity}");
            details.AppendLine($"Process: {entry.ProcessName}");
            details.AppendLine($"Thread ID: {entry.ThreadId}");
            details.AppendLine();
            details.AppendLine("Full Message:");
            details.AppendLine(entry.Message);
            details.AppendLine();
            details.AppendLine("Additional Context:");
            details.AppendLine(entry.Context);

            detailsBox.Text = details.ToString();
        }

        private void RefreshTimer_Tick(object? sender, EventArgs e)
        {
            if (isAutoRefresh)
            {
                LoadLogs();
            }
        }

        private void RefreshButton_Click(object? sender, RoutedEventArgs e)
        {
            LoadLogs();
        }

        private void ExportButton_Click(object? sender, RoutedEventArgs e)
        {
            try
            {
                var saveDialog = new Microsoft.Win32.SaveFileDialog
                {
                    Title = "Export Logs",
                    Filter = "Text files (*.txt)|*.txt|CSV files (*.csv)|*.csv|All files (*.*)|*.*",
                    DefaultExt = "txt",
                    FileName = $"PhageVirus_Logs_{DateTime.Now:yyyyMMdd_HHmmss}"
                };

                if (saveDialog.ShowDialog() == true)
                {
                    ExportLogs(saveDialog.FileName, saveDialog.FilterIndex);
                    MessageBox.Show($"Logs exported successfully to {saveDialog.FileName}", "Export Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Export failed: {ex.Message}", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ExportLogs(string filePath, int filterIndex)
        {
            var content = new StringBuilder();
            
            if (filterIndex == 2) // CSV
            {
                content.AppendLine("Timestamp,LogType,Severity,Message,ProcessName,ThreadId");
                foreach (var entry in logEntries)
                {
                    content.AppendLine($"\"{entry.Timestamp}\",\"{entry.LogType}\",\"{entry.Severity}\",\"{entry.Message.Replace("\"", "\"\"")}\",\"{entry.ProcessName}\",\"{entry.ThreadId}\"");
                }
            }
            else // Text
            {
                content.AppendLine("=== PHAGEVIRUS LOG EXPORT ===");
                content.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                content.AppendLine($"Total Entries: {logEntries.Count}");
                content.AppendLine();
                
                foreach (var entry in logEntries)
                {
                    content.AppendLine($"[{entry.Timestamp}] [{entry.LogType}] [{entry.Severity}] {entry.Message}");
                    if (!string.IsNullOrEmpty(entry.Context))
                    {
                        content.AppendLine($"  Context: {entry.Context}");
                    }
                    content.AppendLine();
                }
            }

            File.WriteAllText(filePath, content.ToString(), Encoding.UTF8);
        }

        private void ClearButton_Click(object? sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show("Are you sure you want to clear all logs?", "Clear Logs", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (result == MessageBoxResult.Yes)
            {
                logEntries.Clear();
                detailsBox.Text = "";
                UpdateStatus();
            }
        }

        private void LoadLogs()
        {
            try
            {
                var logContent = EnhancedLogger.GetLogContent(1000);
                var lines = logContent.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
                
                // Clear existing entries
                logEntries.Clear();
                
                foreach (var line in lines)
                {
                    var entry = ParseLogLine(line);
                    if (entry != null)
                    {
                        logEntries.Add(entry);
                    }
                }
                
                UpdateStatus();
            }
            catch (Exception ex)
            {
                statusLabel.Content = $"Error loading logs: {ex.Message}";
            }
        }

        private LogEntry? ParseLogLine(string line)
        {
            try
            {
                // Expected format: [timestamp] [TYPE] message
                if (!line.StartsWith("[") || !line.Contains("]"))
                    return null;

                var firstBracketEnd = line.IndexOf(']');
                if (firstBracketEnd == -1)
                    return null;

                var timestamp = line.Substring(1, firstBracketEnd - 1);
                
                var remaining = line.Substring(firstBracketEnd + 1).Trim();
                if (!remaining.StartsWith("[") || !remaining.Contains("]"))
                    return null;

                var secondBracketEnd = remaining.IndexOf(']');
                if (secondBracketEnd == -1)
                    return null;

                var logType = remaining.Substring(1, secondBracketEnd - 1);
                var message = remaining.Substring(secondBracketEnd + 1).Trim();

                return new LogEntry
                {
                    Timestamp = timestamp,
                    LogType = logType,
                    Severity = DetermineSeverity(logType),
                    Message = message,
                    ProcessName = GetCurrentProcessName(),
                    ThreadId = Thread.CurrentThread.ManagedThreadId,
                    Context = GetContextForLogType(logType, message)
                };
            }
            catch
            {
                return null;
            }
        }

        private string DetermineSeverity(string logType)
        {
            return logType switch
            {
                "ERROR" => "High",
                "THREAT" => "Critical",
                "WARNING" => "Medium",
                "SUCCESS" => "Low",
                "INFO" => "Low",
                _ => "Low"
            };
        }

        private string GetCurrentProcessName()
        {
            try
            {
                return System.Diagnostics.Process.GetCurrentProcess().ProcessName;
            }
            catch
            {
                return "Unknown";
            }
        }

        private string GetContextForLogType(string logType, string message)
        {
            return logType switch
            {
                "PROCESS_CREATED" => "Process creation detected and logged",
                "PROCESS_TERMINATED" => "Process termination detected and logged",
                "MEMORY_INJECTION" => "Memory injection operation performed",
                "FILE_OPERATION" => "File system operation detected",
                "REGISTRY_OPERATION" => "Registry operation detected",
                "NETWORK_ACTIVITY" => "Network activity detected",
                "SELF_REPLICATION" => "Self-replication operation performed",
                "PERSISTENCE" => "Persistence mechanism operation",
                "THREAT" => "Threat detection and analysis",
                "NEUTRALIZATION" => "Threat neutralization operation",
                _ => "Standard log entry"
            };
        }

        private void UpdateStatus()
        {
            var totalEntries = logEntries.Count;
            var filteredEntries = CollectionViewSource.GetDefaultView(logEntries).Cast<object>().Count();
            
            statusLabel.Content = $"Total: {totalEntries} | Filtered: {filteredEntries} | Auto-refresh: {(isAutoRefresh ? "ON" : "OFF")}";
        }

        protected override void OnClosed(EventArgs e)
        {
            refreshTimer?.Stop();
            base.OnClosed(e);
        }
    }

    public class LogEntry : INotifyPropertyChanged
    {
        private string timestamp = "";
        private string logType = "";
        private string severity = "";
        private string message = "";
        private string processName = "";
        private int threadId;
        private string context = "";

        public string Timestamp
        {
            get => timestamp;
            set
            {
                timestamp = value;
                OnPropertyChanged(nameof(Timestamp));
            }
        }

        public string LogType
        {
            get => logType;
            set
            {
                logType = value;
                OnPropertyChanged(nameof(LogType));
            }
        }

        public string Severity
        {
            get => severity;
            set
            {
                severity = value;
                OnPropertyChanged(nameof(Severity));
            }
        }

        public string Message
        {
            get => message;
            set
            {
                message = value;
                OnPropertyChanged(nameof(Message));
            }
        }

        public string ProcessName
        {
            get => processName;
            set
            {
                processName = value;
                OnPropertyChanged(nameof(ProcessName));
            }
        }

        public int ThreadId
        {
            get => threadId;
            set
            {
                threadId = value;
                OnPropertyChanged(nameof(ThreadId));
            }
        }

        public string Context
        {
            get => context;
            set
            {
                context = value;
                OnPropertyChanged(nameof(Context));
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
} 

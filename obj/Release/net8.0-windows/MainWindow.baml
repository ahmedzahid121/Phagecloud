   M S B A M L   `   `   `  ����   
PhageVirus    PhageVirus.MainWindow   W SPresentationCore, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35e aSystem.Windows.Controls.Ribbon, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089R NWindowsBase, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35F 9http://schemas.microsoft.com/winfx/2006/xaml/presentation     R NSystem.Xaml, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml       � Title$&   PhageVirus - Advanced EDR System��$	��900��$
��1400�� � WindowStartupLocation$ CenterScreen=� � 
ResizeMode$ 	CanResize=�   PrimaryBackground#��[  .���  � RowDefinitions �� $
��Auto ��� $
��Auto ��� $
��Auto ��� $��* ��� $
��Auto �.+��� $��0��  CardGradient#��[   BorderPrimary#��[ $��0,0,0,1q� �� Padding$ 30,20q�._��  � ColumnDefinitions �� $��* ��� $
��Auto �.+��� $��0��$��Center=�.+��� $��
PHAGEVIRUS��$��32(�$	��800"�  AccentPrimary#��[ $��Segoe UI)��� $3��-Advanced Endpoint Detection & Response System��$��14(�  TextSecondary#��[ $��0,5,0,0q�$	��400"��� $��1�� �� Orientation$ 
Horizontal=�$��Center=�.+��� $��SYSTEM STATUS��#��[ $��Center=�$��0,0,15,0q�$��12(�$	��600"�A� -    A�Name$ VirusHunterStatus��  PulseIndicator#��[ A� -   $ PayloadReplacerStatus��#��[ A� -   $ ProcessWatcherStatus��#��[ A� -   $ AutorunBlockerStatus��#��[ A� -   $ MemoryTrapStatus��#��[ A� -   $ CredentialTrapStatus��#��[ A� -   $ ExploitShieldStatus��#��[ A� -   $ WatchdogStatus��#��[ A� -	   $ RedTeamAgentStatus��#��[ �� $��1��
������ $ 30,20q�._��  �� $��* ��� $��* ��� $��* ��� $��* ��� $��* ��� $��* �.+��� $��0��  
MetricCard#��[ ._��� .+��� -
    ��Name$ ActiveThreatsValue��$��0��  MetricValue#��[ �� $��Active Threats��  MetricLabel#��[ �� $��1��#��[ ._��� .+��� -   $ PreventedAttacksValue��$��0��#��[ �� $��Prevented Attacks��#��[ �� $��2��#��[ ._��� .+��� -   $ CpuUsageValue��$��0%��#��[ �� $��	CPU Usage��#��[ �� $��3��#��[ ._��� .+��� -   $ MemoryUsageValue��$
��0 MB��#��[ �� $��Memory Usage��#��[ �� $��4��#��[ ._��� .+��� -   $ LastThreatValue��$��0s��#��[ �� $��Last Threat��#��[ �� $��5��#��[ ._��� .+��� -   $ SystemHealthValue��$
��100%��#��[ �� $��System Health��#��[ �� $��2��#��[ #��[ $��0,1,0,1q�$ 30,15q�._��� .+��� $��QUICK ACTIONS��#��[ $	��600"�$��16(�$��0,0,0,15q�$��Center=�� $��Center=�.+��� -   	 ��Name$	 QuickStartHuntingButton��$��🚀 START HUNTING�� 	 SuccessButton#��[	 $��25,12q�$��5q�$��14(�$	��600"��� -   $	 QuickStopHuntingButton��$��⏹️ STOP HUNTING�� 
 WarningButton#��[
 $��25,12q�$��5q�$��14(�$	��600"��� -   $	 QuickBehaviorTestButton��$��🧪 BEHAVIOR TEST��  PrimaryButton#��[ $��25,12q�$��5q�$��14(�$	��600"��� -   $	 QuickDiagnosticButton��$��🔍 DIAGNOSTIC TEST��  ModernButton#��[ $��25,12q�$��5q�$��14(�$	��600"��� -   $	 QuickLogViewerButton��$��📋 LOG VIEWER��#��[ $��25,12q�$��5q�$��14(�$	��600"��� -   $	 QuickExportLogButton��$��📤 EXPORT LOGS��#��[ $��25,12q�$��5q�$��14(�$	��600"��� -   $	 QuickRefreshButton��$��🔄 REFRESH��#��[ $��25,12q�$��5q�$��14(�$	��600"��� -   $	 QuickSelfDestructButton��$��💥 SELF-DESTRUCT��  DangerButton#��[ $��25,12q�$��5q�$��14(�$	��600"��� $��3��
������ $��0q�$��	30,0,30,0q�.@��� $��THREAT INTELLIGENCE��.��� $��0,20,0,0q� �� $
��Auto ��� $��* ��� $	��200 �.+�� $��0��$��0,0,0,20q� �� $��* ��� $��* ��� $��* ��� $��* �.+��� $��0��#��[ ._��� .+��� -   $ CredentialAttacksValue��$��0��#��[ �� $��Credential Attacks��#��[ �� $��1��#��[ ._��� .+��� -   $ ExploitsNeutralizedValue��$��0��#��[ �� $��Exploits Neutralized��#��[ �� $��2��#��[ ._��� .+��� -   $ PersistenceEntriesValue��$��0��#��[ �� $��Persistence Entries��#��[ �� $��3��#��[ ._��� .+��� -   $ TotalThreatsValue��$��0��#��[ �� $��Total Threats��#��[ �� $��1��$��THREAT TIMELINE��$��0,0,0,20q�.��&   System.Windows.Controls.DataGrid  -   
  Name$
 ThreatTimelineGrid��  ModernDataGrid#��[ $	��200��   Columns 0  *System.Windows.Controls.DataGridTextColumn  ,  &System.Windows.Controls.DataGridColumn   Header$ 	Timestamp��   Width5  /System.Windows.Controls.DataGridLengthConverter$	 150    
FontFamily$ Consolas)�1  +System.Windows.Controls.DataGridBoundColumn   Binding �� *	Timestamp+  $ Threat Type��$	 120    
FontWeight$
 Bold"� �� *
ThreatType+  $ Target��$	 200 $ Consolas)� �� *Target+  $ Action��$	 120  �� *Action+  $ Status��$	 100  �� *Status+�� $��2��$��SYSTEM HEATMAP��.���� -    ��Name$ SystemHeatmap��
������ $��10q��� $��LIVE ACTIVITY��.��� $��0,20,0,0q� �� $��* ��� $
��Auto �.+��� -    ��Name$ LogBox��$��0�� �� 
IsReadOnly$
 True��" �� VerticalScrollBarVisibility$
 Auto=�$ �� HorizontalScrollBarVisibility$
 Auto=�
������   AccentSuccess#��[ $��Consolas)�$��12(�$��0q�$��0,0,0,20q��� $��1��$ 
Horizontal=�$��Right=�.+��� -   $	 LiveClearLogButton��$��🗑️ Clear Log��#��[ $��0,0,10,0q��� -    $	 LiveExportLogButton��$��📤 Export Log��#��[ $��0,0,10,0q��� -!   $	 LiveOpenLogViewerButton��$��📋 Log Viewer��#��[ $��0,0,10,0q��� -"   $!	 LiveStartBehaviorTestButton��$��🧪 Start Behavior Test��#��[	 $��0,0,10,0q��� -#   $ 	 LiveStopBehaviorTestButton��$��⏹️ Stop Behavior Test��#��[
 $��0,0,10,0q��� -$   $	 LiveDiagnosticTestButton��$��🔍 Diagnostic Test��#��[ �� $��SYSTEM MONITOR��.��� $��0,20,0,0q� �� $
��Auto ��� $��* �.+��� $��0��$��MONITORED PROCESSES��$��0,0,0,20q�.��  -%   $
 ProcessGrid��#��[ $	��200��   $	 PID��$ 80 $ Consolas)� �� *	ProcessId+  $ Process Name��$	 150  �� *ProcessName+  $ Status��$	 100  �� *Status+  $ Memory (MB)��$	 100  �� *MemoryUsage+  $ CPU %��$ 80  �� *
CpuUsage+  $ Threat Level��$	 100  �� *ThreatLevel+�� $��1��$��SYSTEM RESOURCES��.���  �� $��* ��� $��* �.+��� $��0��#��[ $��5q�._��� .+��� $��CPU Usage Over Time��#��[ $��0,0,0,10q��� -&   $ CpuChart��$	��100��
������ �� $��1��#��[ $��5q�._��� .+��� $��Memory Usage Over Time��#��[ $��0,0,0,10q��� -'   $ MemoryChart��$	��100��
������ �� $��🔴 RED TEAM SIMULATION��.��� $��0,20,0,0q� �� $
��Auto ��� $
��Auto ��� $��* ��� $
��Auto �.+��� $��0�����#2d1b1b���#ff4444$��2q� �� CornerRadius$ 8��$��0,0,0,20q�$ 20,15q�._��� .+��� $(��"⚠️ RED TEAM SIMULATION WARNING�����#ff6666$
��Bold"�$��16(�$��Center=�$��0,0,0,10q��� $����This module performs safe attack simulations to test your security controls. All actions are sandboxed and harmless. Only use in test environments.�����#ffaaaa$
��Wrap=�$��Center=�$��12(��� $��1��$ ��ATTACK SIMULATION CONTROLS��$��0,0,0,20q�.��� $��10q� �� $
��Auto ��� $
��Auto �.+�� $��0��$��Center=�$��0,0,0,15q�.+��� -(   $	 CredentialDumpButton��$��🔐 Credential Dump��#��[ $��20,10q�$��5q�$��12(�$	��600"��� -)   $	 ProcessHollowingButton��$��🧬 Process Hollowing��#��[ $��20,10q�$��5q�$��12(�$	��600"��� -*   $	 LateralMovementButton��$��🔄 Lateral Movement��#��[ $��20,10q�$��5q�$��12(�$	��600"��� -+   $	 PersistenceButton��$��📌 Persistence��#��[ $��20,10q�$��5q�$��12(�$	��600"��� -,   $	 RansomwareButton��$��💣 Ransomware��#��[ $��20,10q�$��5q�$��12(�$	��600"��� --   $	 PhishingButton��$��🎣 Phishing��#��[ $��20,10q�$��5q�$��12(�$	��600"��� -.   $	 FullAttackChainButton��$��⚡ Full Attack Chain��#��[ $��20,10q�$��5q�$��12(�$	��600"��� $��1��$ 
Horizontal=�$��Center=�.+��� -/   $	 StartRedTeamButton��$��🚀 Start Red Team Agent��#��[	 $��20,10q�$��5q�$��12(�$	��600"��� -0   $	 StopRedTeamButton��$ ��⏹️ Stop Red Team Agent��#��[
 $��20,10q�$��5q�$��12(�$	��600"��� -1   $	 ClearSimulationButton��$��🗑️ Clear Results��#��[ $��20,10q�$��5q�$��12(�$	��600"��� -2   $	 ExportSimulationButton��$��📤 Export Results��#��[ $��20,10q�$��5q�$��12(�$	��600"�� $��2��$��0,0,0,20q� �� $��* ��� $��* �.+��� $��0��$��ATTACK SIMULATION RESULTS��$��0,0,10,0q�.��  -3   $
 AttackResultsGrid��#��[ $	��200��   $ 	Timestamp��$	 120 $ Consolas)� �� *	Timestamp+  $ Attack Type��$	 120 $
 Bold"� �� *
AttackType+  $
 Step��$	 150  �� *Step+  $ Result��$	 100  �� *Result+  $ Blocked��$ 80  �� *
WasBlocked+  $ Detected��$ 80  �� *WasDetected+�� $��1��$��SECURITY SCORE��$��10,0,0,0q�.���� $��10q�.+��� #��[ $��0,0,0,15q�._��� .+��� -4   $ OverallSecurityScore��$
��100%��#��[ $��36(��� $��Overall Security Score��#��[ �� .+��� $��Attack Categories:��#��[ $
��Bold"�$��0,0,0,10q�� $��0,0,0,5q� �� $��* ��� $
��Auto �.+��� $��Credential Access��#��[ �� -5   $ CredentialScore��$��1��$
��100%��#��[ $
��Bold"�� $��0,0,0,5q� �� $��* ��� $
��Auto �.+��� $��Process Exploitation��#��[ �� -6   $ ExploitationScore��$��1��$
��100%��#��[ $
��Bold"�� $��0,0,0,5q� �� $��* ��� $
��Auto �.+��� $��Lateral Movement��#��[ �� -7   $ LateralScore��$��1��$
��100%��#��[ $
��Bold"�� $��0,0,0,5q� �� $��* ��� $
��Auto �.+��� $��Persistence��#��[ �� -8   $ PersistenceScore��$��1��$
��100%��#��[ $
��Bold"�� $��0,0,0,5q� �� $��* ��� $
��Auto �.+��� $��Malware Protection��#��[ �� -9   $ MalwareScore��$��1��$
��100%��#��[ $
��Bold"��� $��3��$@��:PROTECTION MODULE LOGS (How Your Security Stopped Attacks)��.���  �� $��* ��� $
��Auto �.+��� -:   $ ProtectionLogBox��$��0��$
 True��$
 Auto=�$
 Auto=�
������ #��[ $��Consolas)�$��11(�$��0q�$��0,0,0,10q��� $��1��$ 
Horizontal=�$��Right=�.+��� -;   $ ProtectionLogStatus��$��Ready for simulation...��#��[ $��Center=�$��0,0,15,0q��� -<   $	 ClearProtectionLogButton��$��🗑️ Clear Log��#��[ $��0,0,10,0q��� -=   $	 ExportProtectionLogButton��$��📤 Export Log��#��[ �� $��CONFIGURATION��.��� $��0,20,0,0q� �� $
��Auto ��� $
��Auto ��� $
��Auto ��� $��* �.+��� $��0��$ 
Horizontal=�$��Center=�$��0,0,0,30q�.+��� ->   $	 StartHuntingButton��$��🚀 Start Hunting��#��[	 $��30,15q�$��0,0,15,0q��� -?   $	 StopHuntingButton��$��⏹️ Stop Hunting��#��[
 $��30,15q�$��0,0,15,0q��� -@   $	 SelfDestructButton��$��💥 Self-Destruct��#��[ $��30,15q�$��0,0,15,0q��� -A   $	 QuickTestEmailButton��$��📧 Test Email��#��[ $��30,15q�$��0,0,15,0q��� -B   $	 ClearLogButton��$��🗑️ Clear Log��#��[ $��30,15q�$��0,0,15,0q��� -C   $	 ExportLogButton��$��📤 Export Log��#��[ $��30,15q��� $��1��$��MODULE CONTROLS��$��0,0,0,20q�.��� $��10q�.+��� -D    ��Name$ EnableVirusHunter��$��Virus Hunter�� d� 	IsChecked$
 TrueY��� -E   $ EnablePayloadReplacer��$��Payload Replacer��$
 TrueY��� -F   $ EnableProcessWatcher��$��Process Watcher��$
 TrueY��� -G   $ EnableAutorunBlocker��$��Autorun Blocker��$
 TrueY��� -H   $ EnableMemoryTrap��$��Memory Trap��$
 TrueY��� -I   $ EnableCredentialTrap��$��Credential Trap��$
 TrueY��� -J   $ EnableExploitShield��$��Exploit Shield��$
 TrueY��� -K   $ EnableWatchdog��$��Watchdog Core��$
 TrueY��� -L   $ EnablePhageSync��$��
Phage Sync��$
 TrueY��� -M   $ EnableHoneyProcess��$��HoneyProcess��$
 TrueY��� -N   $ EnableZeroTrustRuntime��$��ZeroTrustRuntime��$
 TrueY��� -O   $ EnableDnsSinkhole��$��DNS Sinkhole��$
 TrueY��� -P   $ EnablePhishingGuard��$��PhishingGuard��$
 TrueY��� -Q   $ EnableRollbackEngine��$��Rollback Engine��$
 TrueY��� -R   $ EnableAIThreatExplain��$��AI Threat Explain��$
 TrueY��� $��2��$��EMAIL REPORTING��$��0,0,0,20q�.��� $��10q� �� $
��Auto ��� $��* ��� $
��Auto ��� $��* � �� $
��Auto ��� $
��Auto �.+��� $��0��$��0��$��SMTP Server:��#��[ $��Center=�$��0,0,10,0q��� -S   $ SmtpServerBox��$��0��$��1��$��smtp.gmail.com��$��0,0,20,0q��� $��0��$��2��$��Port:��#��[ $��Center=�$��0,0,10,0q��� -T   $ SmtpPortBox��$��0��$��3��$	��587���� $��1��$��0��$��Email:��#��[ $��Center=�$��0,0,10,0q��� -U   $ EmailBox��$��1��$��1��$��0,0,20,0q��� -V   $	 TestEmailButton��$��1��$��2��$��2��$��
Test Email��#��[ $��Right=��� $��3��$��SYSTEM STATUS��.���� $��10q�.+��� -W   $ 
StatusText��$��System ready...��#��[ $��12(��� -X   $ EmailStatus��$�� ��  AccentWarning#��[ $��12(�$��0,5,0,0q�$y�	Collapsed=��� -Y   $ LastUpdateTime��$�� ��  	TextMuted#��[ $��10(�$��0,10,0,0q��� $��COMMAND CENTER��.��� $��0,20,0,0q� �� $
��Auto ��� $��* ��� $
��Auto �.+��� $��0��$ ��ENDPOINTS (PHAGESYNC MESH)��$��0,0,0,20q�.��  -Z   $
 EndpointGrid��#��[ $	��120��   $ Endpoint��$	 200  �� *NodeId+  $ 	Last Scan��$	 150  �� *
LastScan+  $ Threat Count��$	 100  �� *ThreatCount+  $ Status��$	 120  �� *Status+�� $��1��$ 
Horizontal=�$��Center=�$��	0,20,0,20q�.+��� $��Last Scan: ��#��[ $
��Bold"��� -[   $ CommandCenterLastScan��$��-��#��[ $��5,0,20,0q��� $��	Threats: ��#��[ $
��Bold"��� -\   $ CommandCenterThreatCount��$��0��  AccentDanger#��[ $��5,0,20,0q��� $��Status: ��#��[ $
��Bold"��� -]   $ CommandCenterStatus��$��Unknown��#��[ �� $��2��$��SECURE ADMIN SHELL��.���� .+��� -^   $ AdminShellInput��$��30��$��Consolas)�$��14(�$��0,0,0,10q��� -_   $	 AdminShellExecute��$��Execute��#��[ $	��100���� -`   $ AdminShellOutput��$	��100��$��Consolas)�$��12(�#��[ $��0,10,0,0q�$
 True�� �� TextWrapping$
 Wrap=��� $��4��#��[ #��[ $��0,1,0,0q�$ 30,15q�._��  �� $��* ��� $
��Auto �.+��� $��0��$ 
Horizontal=�$��Center=�.+��� -a   $ OverallStatus��$��🟢 System Protected��#��[ $
��Bold"�$��0,0,20,0q��� -b   $ 
UptimeText��$��Uptime: 00:00:00��#��[ $��12(��� $��1��$ 
Horizontal=�.+��� -c   $	 RefreshButton��$
��🔄��#��[ $��35��$��35��$��0,0,10,0q��� -d   $	 MinimizeButton��$
��🗕��#��[ $��35��$��35��
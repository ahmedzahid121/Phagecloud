   M S B A M L   `   `   `  ����   
PhageVirus    PhageVirus.EmailDialog   W SPresentationCore, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35e aSystem.Windows.Controls.Ribbon, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089R NWindowsBase, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35F 9http://schemas.microsoft.com/winfx/2006/xaml/presentation     R NSystem.Xaml, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml       � Title$%  Diagnostic Test - Email Options��$	��400��$	��300�� � WindowStartupLocation$ CenterOwner=� � 
ResizeMode$ NoResize=����#1a1a1a.��� $��20q� � RowDefinitions �� $
��Auto ��� $
��Auto ��� $
��Auto ��� $
��Auto ��� $
��Auto ��� $��* ��� $
��Auto �.+��� $��0��$(��"🔍 Diagnostic Test Email Options��$��16(�$
��Bold"����#00ffff$��0,0,0,20q�$��Center=��� $��1��$~��xThe diagnostic test will generate a comprehensive report of your system health, PhageVirus status, and any issues found.�����#cccccc$
��Wrap=�$��0,0,0,20q��� -    ��Name$ SendToEmailCheckBox��$��2��$%��Send diagnostic report to email�����#cccccc$��0,0,0,10q��� $��3�� �� Orientation$ 
Horizontal=�$��0,0,0,10q�.+��� $��Email Address:�����#cccccc$��Center=�$��0,0,10,0q��� -    ��Name$ EmailTextBox��$	��250�����#333333���#cccccc���#555555${�False���� $��4��$W��QNote: The report will always be saved to your desktop regardless of email option.�����#888888$��11(�$
��Wrap=�$��0,0,0,20q�� $��5���� $��6��$ 
Horizontal=�$��Right=�.+��� -    ��Name$ CancelButton��$��Cancel�����#666666���#ffffff$
��20,8q�$��0,0,10,0q��� -   $ 	RunButton��$��Run Diagnostic Test�����#00cc66���#ffffff$
��20,8q�
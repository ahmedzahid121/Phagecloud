   M S B A M L   `   `   `  ����  
PhageVirus    PhageVirus.EmailDialog   5   	   W SPresentationCore, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35e aSystem.Windows.Controls.Ribbon, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089R NWindowsBase, Version=8.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35F 9http://schemas.microsoft.com/winfx/2006/xaml/presentation     5   	   R NSystem.Xaml, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	     � Title$%  Diagnostic Test - Email Options��5   	   $	��400��5   	   $	��300��5   	    � WindowStartupLocation$ CenterOwner=�5   	    � 
ResizeMode$ NoResize=�5   	   ���#1a1a1a.��5      � $��20q�6    � RowDefinitions 5   
   �� 5      $
��Auto �6   �� 5      $
��Auto �6   �� 5      $
��Auto �6   �� 5      $
��Auto �6   �� 5      $
��Auto �6   �� 5      $��* �6   �� 5      $
��Auto �6   .+�5   
   �� $��0��6   $(��"🔍 Diagnostic Test Email Options��5      $��16(�5      $
��Bold"�5      ���#00ffff$��0,0,0,20q�5      $��Center=�5      �� 5    
   $��1��6   $~��xThe diagnostic test will generate a comprehensive report of your system health, PhageVirus status, and any issues found.��5!      ���#cccccc$
��Wrap=�5#      $��0,0,0,20q�5$      �� 5'   
   -   5         ��Name$ SendToEmailCheckBox��5(      $��2��5'      $%��Send diagnostic report to email��5)      ���#cccccc$��0,0,0,10q�5+      5-      �� 50   
   $��3��6    �� Orientation$ 
Horizontal=�51      $��0,0,0,10q�52      .+�53      �� $��Email Address:��6   ���#cccccc$��Center=�55      $��0,0,10,0q�56      �� 57      -   5         ��Name$ EmailTextBox��57      $	��250��58      ���#333333���#cccccc���#555555${�False��5<      5=      �� 5@   
   $��4��6   $W��QNote: The report will always be saved to your desktop regardless of email option.��5A      ���#888888$��11(�5C      $
��Wrap=�5D      $��0,0,0,20q�5E      � 5H   
   $��5��6   �� 5K   
   $��6��6   $ 
Horizontal=�5L      $��Right=�5M      .+�5N      �� -   5         ��Name$ CancelButton��5N      $��Cancel��5O      ���#666666���#ffffff$
��20,8q�5R      $��0,0,10,0q�5S      5T      �� 5U      -   5        $ 	RunButton��5U      $��Run Diagnostic Test��5V      ���#00cc66���#ffffff$
��20,8q�5Y      5Z      5[      5\      5]      
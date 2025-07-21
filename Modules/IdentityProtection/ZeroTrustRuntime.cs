using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Text;
using System.Security.Cryptography;
using Microsoft.Win32;
using System.Management; // Added for VM detection

namespace PhageVirus.Modules
{
    public class ZeroTrustRuntime
    {
        private static bool isRunning = false;
        private static readonly Dictionary<int, ProcessSignature> ProcessSignatures = new();
        private static readonly Dictionary<string, string> KnownSignatures = new();
        private static readonly object signatureLock = new object();
        
        // Windows API imports for hooks
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);
        
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        
        [DllImport("user32.dll")]
        private static extern IntPtr SetWindowsHookEx(int idHook, IntPtr lpfn, IntPtr hMod, uint dwThreadId);
        
        [DllImport("user32.dll")]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);
        
        [DllImport("kernel32.dll")]
        private static extern IntPtr LoadLibrary(string lpFileName);
        
        [DllImport("kernel32.dll")]
        private static extern bool FreeLibrary(IntPtr hModule);
        
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        
        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);
        
        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);
        
        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        
        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        
        // Hook types
        private const int WH_CALLWNDPROC = 4;
        private const int WH_GETMESSAGE = 3;
        private const int PROCESS_ALL_ACCESS = 0x1F0FFF;
        private const int MEM_COMMIT = 0x1000;
        private const int MEM_RESERVE = 0x2000;
        private const int PAGE_EXECUTE_READWRITE = 0x40;
        
        private static IntPtr callWndProcHook = IntPtr.Zero;
        private static IntPtr getMessageHook = IntPtr.Zero;

        public static bool StartZeroTrustProtection()
        {
            try
            {
                EnhancedLogger.LogInfo("Starting Zero Trust Runtime protection...", Console.WriteLine);
                
                isRunning = true;
                
                // Initialize known signatures
                InitializeKnownSignatures();
                
                // Set up Windows hooks
                SetupWindowsHooks();
                
                // Start process monitoring
                Task.Run(MonitorProcesses);
                
                // Start DLL injection detection
                Task.Run(MonitorDllInjection);
                
                // Start AppInit_DLLs monitoring
                MonitorAppInitDlls();
                
                EnhancedLogger.LogInfo("Zero Trust Runtime protection started", Console.WriteLine);
                
                // Send telemetry to cloud for zero trust status
                Task.Run(async () =>
                {
                    try
                    {
                        var zeroTrustData = new
                        {
                            process_signatures_count = ProcessSignatures.Count,
                            known_signatures_count = KnownSignatures.Count,
                            call_wnd_proc_hook_active = callWndProcHook != IntPtr.Zero,
                            get_message_hook_active = getMessageHook != IntPtr.Zero,
                            threat_type = "zero_trust_status",
                            timestamp = DateTime.UtcNow
                        };

                        await CloudIntegration.SendTelemetryAsync("ZeroTrustRuntime", "zero_trust_status", zeroTrustData, ThreatLevel.Normal);
                        
                        // Get cloud zero trust analysis
                        var analysis = await CloudIntegration.GetCloudAnalysisAsync("ZeroTrustRuntime", zeroTrustData);
                        if (analysis.Success)
                        {
                            EnhancedLogger.LogInfo($"Cloud zero trust analysis: {analysis.Analysis}");
                        }
                    }
                    catch (Exception ex)
                    {
                        EnhancedLogger.LogWarning($"Cloud zero trust analysis failed: {ex.Message}");
                    }
                });
                
                return true;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to start Zero Trust protection: {ex.Message}", Console.WriteLine);
                return false;
            }
        }

        public static void StopZeroTrustProtection()
        {
            try
            {
                isRunning = false;
                
                // Remove hooks
                if (callWndProcHook != IntPtr.Zero)
                {
                    UnhookWindowsHookEx(callWndProcHook);
                    callWndProcHook = IntPtr.Zero;
                }
                
                if (getMessageHook != IntPtr.Zero)
                {
                    UnhookWindowsHookEx(getMessageHook);
                    getMessageHook = IntPtr.Zero;
                }
                
                EnhancedLogger.LogInfo("Zero Trust Runtime protection stopped", Console.WriteLine);
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to stop Zero Trust protection: {ex.Message}", Console.WriteLine);
            }
        }

        private static void InitializeKnownSignatures()
        {
            try
            {
                // Add known legitimate process signatures
                KnownSignatures["explorer.exe"] = "Microsoft Windows Explorer";
                KnownSignatures["svchost.exe"] = "Microsoft Windows Service Host";
                KnownSignatures["lsass.exe"] = "Microsoft Windows Local Security Authority";
                KnownSignatures["winlogon.exe"] = "Microsoft Windows Logon";
                KnownSignatures["csrss.exe"] = "Microsoft Windows Client Server Runtime";
                KnownSignatures["wininit.exe"] = "Microsoft Windows Initialization";
                KnownSignatures["services.exe"] = "Microsoft Windows Services";
                KnownSignatures["spoolsv.exe"] = "Microsoft Windows Print Spooler";
                KnownSignatures["taskmgr.exe"] = "Microsoft Windows Task Manager";
                KnownSignatures["notepad.exe"] = "Microsoft Windows Notepad";
                KnownSignatures["calc.exe"] = "Microsoft Windows Calculator";
                KnownSignatures["cmd.exe"] = "Microsoft Windows Command Prompt";
                KnownSignatures["powershell.exe"] = "Microsoft Windows PowerShell";
                KnownSignatures["chrome.exe"] = "Google Chrome Browser";
                KnownSignatures["firefox.exe"] = "Mozilla Firefox Browser";
                KnownSignatures["outlook.exe"] = "Microsoft Outlook";
                KnownSignatures["winword.exe"] = "Microsoft Word";
                KnownSignatures["excel.exe"] = "Microsoft Excel";
                KnownSignatures["powerpnt.exe"] = "Microsoft PowerPoint";
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to initialize known signatures: {ex.Message}", Console.WriteLine);
            }
        }

        private static void SetupWindowsHooks()
        {
            try
            {
                // Set up call window procedure hook
                var callWndProcDelegate = new CallWndProcDelegate(CallWndProcHook);
                callWndProcHook = SetWindowsHookEx(WH_CALLWNDPROC, Marshal.GetFunctionPointerForDelegate(callWndProcDelegate), IntPtr.Zero, 0);
                
                // Set up get message hook
                var getMessageDelegate = new GetMessageDelegate(GetMessageHook);
                getMessageHook = SetWindowsHookEx(WH_GETMESSAGE, Marshal.GetFunctionPointerForDelegate(getMessageDelegate), IntPtr.Zero, 0);
                
                EnhancedLogger.LogInfo("Windows hooks installed", Console.WriteLine);
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to setup Windows hooks: {ex.Message}", Console.WriteLine);
            }
        }

        private static IntPtr CallWndProcHook(int nCode, IntPtr wParam, IntPtr lParam)
        {
            try
            {
                if (nCode >= 0)
                {
                    // Check for suspicious window messages
                    var msg = Marshal.ReadInt32(lParam);
                    if (IsSuspiciousMessage(msg))
                    {
                        EnhancedLogger.LogWarning($"Suspicious window message detected: 0x{msg:X}", Console.WriteLine);
                        HandleSuspiciousActivity("Suspicious Window Message", msg.ToString());
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error in CallWndProc hook: {ex.Message}", Console.WriteLine);
            }
            
            // Call next hook
            return CallNextHookEx(callWndProcHook, nCode, wParam, lParam);
        }

        private static IntPtr GetMessageHook(int nCode, IntPtr wParam, IntPtr lParam)
        {
            try
            {
                if (nCode >= 0)
                {
                    // Check for suspicious message patterns
                    var msg = Marshal.ReadInt32(lParam);
                    if (IsSuspiciousMessage(msg))
                    {
                        EnhancedLogger.LogWarning($"Suspicious get message detected: 0x{msg:X}", Console.WriteLine);
                        HandleSuspiciousActivity("Suspicious Get Message", msg.ToString());
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error in GetMessage hook: {ex.Message}", Console.WriteLine);
            }
            
            // Call next hook
            return CallNextHookEx(getMessageHook, nCode, wParam, lParam);
        }

        [DllImport("user32.dll")]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        private static bool IsSuspiciousMessage(int message)
        {
            // Check for suspicious window messages
            var suspiciousMessages = new[]
            {
                0x0001, // WM_CREATE
                0x0002, // WM_DESTROY
                0x0003, // WM_MOVE
                0x0005, // WM_SIZE
                0x0006, // WM_ACTIVATE
                0x0007, // WM_SETFOCUS
                0x0008, // WM_KILLFOCUS
                0x0010, // WM_CLOSE
                0x0012, // WM_QUIT
                0x0016, // WM_ENABLE
                0x0017, // WM_SETREDRAW
                0x0018, // WM_SETTEXT
                0x0019, // WM_GETTEXT
                0x001A, // WM_GETTEXTLENGTH
                0x001B, // WM_PAINT
                0x001C, // WM_CLOSE
                0x001D, // WM_QUERYENDSESSION
                0x001E, // WM_QUIT
                0x001F, // WM_QUERYOPEN
                0x0020, // WM_ERASEBKGND
                0x0021, // WM_SYSCOLORCHANGE
                0x0022, // WM_ENDSESSION
                0x0023, // WM_SYSTEMERROR
                0x0024, // WM_SHOWWINDOW
                0x0025, // WM_CTLCOLOR
                0x0026, // WM_WININICHANGE
                0x0027, // WM_SETTINGCHANGE
                0x0028, // WM_DEVMODECHANGE
                0x0029, // WM_ACTIVATEAPP
                0x002A, // WM_FONTCHANGE
                0x002B, // WM_TIMECHANGE
                0x002C, // WM_CANCELMODE
                0x002D, // WM_SETCURSOR
                0x002E, // WM_MOUSEACTIVATE
                0x002F, // WM_CHILDACTIVATE
                0x0030, // WM_QUEUESYNC
                0x0031, // WM_GETMINMAXINFO
                0x0032, // WM_PAINTICON
                0x0033, // WM_ICONERASEBKGND
                0x0034, // WM_NEXTDLGCTL
                0x0035, // WM_SPOOLERSTATUS
                0x0036, // WM_DRAWITEM
                0x0037, // WM_MEASUREITEM
                0x0038, // WM_DELETEITEM
                0x0039, // WM_VKEYTOITEM
                0x003A, // WM_CHARTOITEM
                0x003B, // WM_SETFONT
                0x003C, // WM_GETFONT
                0x003D, // WM_SETHOTKEY
                0x003E, // WM_GETHOTKEY
                0x003F, // WM_QUERYDRAGICON
                0x0040, // WM_COMPAREITEM
                0x0041, // WM_GETOBJECT
                0x0042, // WM_COMPACTING
                0x0043, // WM_COMMNOTIFY
                0x0044, // WM_WINDOWPOSCHANGING
                0x0045, // WM_WINDOWPOSCHANGED
                0x0046, // WM_POWER
                0x0047, // WM_COPYDATA
                0x0048, // WM_CANCELJOURNAL
                0x0049, // WM_NOTIFY
                0x004A, // WM_INPUTLANGCHANGEREQUEST
                0x004B, // WM_INPUTLANGCHANGE
                0x004C, // WM_TCARD
                0x004D, // WM_HELP
                0x004E, // WM_USERCHANGED
                0x004F, // WM_NOTIFYFORMAT
                0x0050, // WM_CONTEXTMENU
                0x0051, // WM_STYLECHANGING
                0x0052, // WM_STYLECHANGED
                0x0053, // WM_DISPLAYCHANGE
                0x0054, // WM_GETICON
                0x0055, // WM_SETICON
                0x0056, // WM_NCCREATE
                0x0057, // WM_NCDESTROY
                0x0058, // WM_NCCALCSIZE
                0x0059, // WM_NCHITTEST
                0x005A, // WM_NCPAINT
                0x005B, // WM_NCACTIVATE
                0x005C, // WM_GETDLGCODE
                0x005D, // WM_SYNCPAINT
                0x005E, // WM_NCMOUSEMOVE
                0x005F, // WM_NCLBUTTONDOWN
                0x0060, // WM_NCLBUTTONUP
                0x0061, // WM_NCLBUTTONDBLCLK
                0x0062, // WM_NCRBUTTONDOWN
                0x0063, // WM_NCRBUTTONUP
                0x0064, // WM_NCRBUTTONDBLCLK
                0x0065, // WM_NCMBUTTONDOWN
                0x0066, // WM_NCMBUTTONUP
                0x0067, // WM_NCMBUTTONDBLCLK
                0x0068, // WM_NCXBUTTONDOWN
                0x0069, // WM_NCXBUTTONUP
                0x006A, // WM_NCXBUTTONDBLCLK
                0x006B, // WM_INPUT_DEVICE_CHANGE
                0x006C, // WM_INPUT
                0x006D, // WM_KEYFIRST
                0x006E, // WM_KEYDOWN
                0x006F, // WM_KEYUP
                0x0070, // WM_CHAR
                0x0071, // WM_DEADCHAR
                0x0072, // WM_SYSKEYDOWN
                0x0073, // WM_SYSKEYUP
                0x0074, // WM_SYSCHAR
                0x0075, // WM_SYSDEADCHAR
                0x0076, // WM_UNICHAR
                0x0077, // WM_KEYLAST
                0x0078, // WM_IME_STARTCOMPOSITION
                0x0079, // WM_IME_ENDCOMPOSITION
                0x007A, // WM_IME_COMPOSITION
                0x007B, // WM_IME_KEYLAST
                0x007C, // WM_INITDIALOG
                0x007D, // WM_COMMAND
                0x007E, // WM_SYSCOMMAND
                0x007F, // WM_TIMER
                0x0080, // WM_HSCROLL
                0x0081, // WM_VSCROLL
                0x0082, // WM_INITMENU
                0x0083, // WM_INITMENUPOPUP
                0x0084, // WM_GESTURE
                0x0085, // WM_GESTURENOTIFY
                0x0086, // WM_MENUSELECT
                0x0087, // WM_MENUCHAR
                0x0088, // WM_ENTERIDLE
                0x0089, // WM_MENURBUTTONUP
                0x008A, // WM_MENUDRAG
                0x008B, // WM_MENUGETOBJECT
                0x008C, // WM_UNINITMENUPOPUP
                0x008D, // WM_MENUCOMMAND
                0x008E, // WM_CHANGEUISTATE
                0x008F, // WM_UPDATEUISTATE
                0x0090, // WM_QUERYUISTATE
                0x0091, // WM_CTLCOLORMSGBOX
                0x0092, // WM_CTLCOLOREDIT
                0x0093, // WM_CTLCOLORLISTBOX
                0x0094, // WM_CTLCOLORBTN
                0x0095, // WM_CTLCOLORDLG
                0x0096, // WM_CTLCOLORSCROLLBAR
                0x0097, // WM_CTLCOLORSTATIC
                0x0098, // WM_MOUSEFIRST
                0x0099, // WM_MOUSEMOVE
                0x009A, // WM_LBUTTONDOWN
                0x009B, // WM_LBUTTONUP
                0x009C, // WM_LBUTTONDBLCLK
                0x009D, // WM_RBUTTONDOWN
                0x009E, // WM_RBUTTONUP
                0x009F, // WM_RBUTTONDBLCLK
                0x00A0, // WM_MBUTTONDOWN
                0x00A1, // WM_MBUTTONUP
                0x00A2, // WM_MBUTTONDBLCLK
                0x00A3, // WM_MOUSEWHEEL
                0x00A4, // WM_XBUTTONDOWN
                0x00A5, // WM_XBUTTONUP
                0x00A6, // WM_XBUTTONDBLCLK
                0x00A7, // WM_MOUSEHWHEEL
                0x00A8, // WM_MOUSELAST
                0x00A9, // WM_PARENTNOTIFY
                0x00AA, // WM_ENTERMENULOOP
                0x00AB, // WM_EXITMENULOOP
                0x00AC, // WM_NEXTMENU
                0x00AD, // WM_SIZING
                0x00AE, // WM_CAPTURECHANGED
                0x00AF, // WM_MOVING
                0x00B0, // WM_POWERBROADCAST
                0x00B1, // WM_DEVICECHANGE
                0x00B2, // WM_MDICREATE
                0x00B3, // WM_MDIDESTROY
                0x00B4, // WM_MDIACTIVATE
                0x00B5, // WM_MDIRESTORE
                0x00B6, // WM_MDINEXT
                0x00B7, // WM_MDIMAXIMIZE
                0x00B8, // WM_MDITILE
                0x00B9, // WM_MDICASCADE
                0x00BA, // WM_MDIICONARRANGE
                0x00BB, // WM_MDIGETACTIVE
                0x00BC, // WM_MDISETMENU
                0x00BD, // WM_ENTERSIZEMOVE
                0x00BE, // WM_EXITSIZEMOVE
                0x00BF, // WM_DROPFILES
                0x00C0, // WM_MDIREFRESHMENU
                0x00C1, // WM_IME_SETCONTEXT
                0x00C2, // WM_IME_NOTIFY
                0x00C3, // WM_IME_CONTROL
                0x00C4, // WM_IME_COMPOSITIONFULL
                0x00C5, // WM_IME_SELECT
                0x00C6, // WM_IME_CHAR
                0x00C7, // WM_IME_REQUEST
                0x00C8, // WM_IME_KEYDOWN
                0x00C9, // WM_IME_KEYUP
                0x00CA, // WM_MOUSEHOVER
                0x00CB, // WM_MOUSELEAVE
                0x00CC, // WM_NCMOUSEHOVER
                0x00CD, // WM_NCMOUSELEAVE
                0x00CE, // WM_WTSSESSION_CHANGE
                0x00CF, // WM_TABLET_FIRST
                0x00D0, // WM_TABLET_LAST
                0x00D1, // WM_CUT
                0x00D2, // WM_COPY
                0x00D3, // WM_PASTE
                0x00D4, // WM_CLEAR
                0x00D5, // WM_UNDO
                0x00D6, // WM_RENDERFORMAT
                0x00D7, // WM_RENDERALLFORMATS
                0x00D8, // WM_DESTROYCLIPBOARD
                0x00D9, // WM_DRAWCLIPBOARD
                0x00DA, // WM_PAINTCLIPBOARD
                0x00DB, // WM_VSCROLLCLIPBOARD
                0x00DC, // WM_SIZECLIPBOARD
                0x00DD, // WM_ASKCBFORMATNAME
                0x00DE, // WM_CHANGECBCHAIN
                0x00DF, // WM_HSCROLLCLIPBOARD
                0x00E0, // WM_QUERYNEWPALETTE
                0x00E1, // WM_PALETTEISCHANGING
                0x00E2, // WM_PALETTECHANGED
                0x00E3, // WM_HOTKEY
                0x00E4, // WM_PRINT
                0x00E5, // WM_PRINTCLIENT
                0x00E6, // WM_APPCOMMAND
                0x00E7, // WM_THEMECHANGED
                0x00E8, // WM_CLIPBOARDUPDATE
                0x00E9, // WM_DWMCOMPOSITIONCHANGED
                0x00EA, // WM_DWMNCRENDERINGCHANGED
                0x00EB, // WM_DWMCOLORIZATIONCOLORCHANGED
                0x00EC, // WM_DWMWINDOWMAXIMIZEDCHANGE
                0x00ED, // WM_DWMSENDICONTITLEBARGLYPH
                0x00EE, // WM_DWMSENDICONTITLETEXT
                0x00EF, // WM_DWMSENDICONTHUMBNAIL
                0x00F0, // WM_DWMSENDICONICLIVEPREVIEWBITMAP
                0x00F1, // WM_GETTITLEBARINFOEX
                0x00F2, // WM_HANDHELDFIRST
                0x00F3, // WM_HANDHELDLAST
                0x00F4, // WM_AFXFIRST
                0x00F5, // WM_AFXLAST
                0x00F6, // WM_PENWINFIRST
                0x00F7, // WM_PENWINLAST
                0x00F8, // WM_APP
                0x00F9, // WM_USER
            };
            
            return Array.IndexOf(suspiciousMessages, message) >= 0;
        }

        private static async Task MonitorProcesses()
        {
            // DISABLED FOR VM STABILITY - This was causing infinite loops
            try
            {
                EnhancedLogger.LogInfo("ZeroTrust process monitoring DISABLED for VM stability");
                
                // Do a single scan instead of infinite loop
                var processes = Process.GetProcesses();
                var verifiedCount = 0;
                
                foreach (var process in processes.Take(5)) // Limit to 5 processes
                {
                    try
                    {
                        if (!ProcessSignatures.ContainsKey(process.Id))
                        {
                            // Verify process signature
                            var signature = VerifyProcessSignature(process);
                            lock (signatureLock)
                            {
                                ProcessSignatures[process.Id] = signature;
                            }
                            
                            if (signature.IsValid)
                            {
                                verifiedCount++;
                            }
                            else
                            {
                                // Don't handle invalid signatures in VM - too aggressive
                                if (!IsVirtualMachine())
                                {
                                    HandleInvalidSignature(process, signature);
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        EnhancedLogger.LogError($"Error verifying process {process.Id}: {ex.Message}", Console.WriteLine);
                    }
                }
                
                EnhancedLogger.LogInfo($"ZeroTrust process scan completed - verified {verifiedCount} processes");
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Error in process monitoring: {ex.Message}", Console.WriteLine);
            }
        }

        private static ProcessSignature VerifyProcessSignature(Process process)
        {
            try
            {
                var signature = new ProcessSignature
                {
                    ProcessId = process.Id,
                    ProcessName = process.ProcessName,
                    IsValid = false,
                    VerificationTime = DateTime.Now
                };
                
                // Check if process name is known
                if (KnownSignatures.ContainsKey(process.ProcessName.ToLower()))
                {
                    signature.KnownProcess = true;
                    signature.Description = KnownSignatures[process.ProcessName.ToLower()];
                }
                
                // Calculate process memory hash
                signature.MemoryHash = CalculateProcessMemoryHash(process);
                
                // Check for suspicious characteristics
                signature.HasSuspiciousModules = CheckSuspiciousModules(process);
                signature.HasHighEntropyRegions = CheckHighEntropyRegions(process);
                signature.HasInjectedCode = CheckInjectedCode(process);
                
                // Determine if process is valid
                signature.IsValid = !signature.HasSuspiciousModules && 
                                   !signature.HasHighEntropyRegions && 
                                   !signature.HasInjectedCode;
                
                return signature;
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to verify process signature for {process.Id}: {ex.Message}", Console.WriteLine);
                return new ProcessSignature
                {
                    ProcessId = process.Id,
                    ProcessName = process.ProcessName,
                    IsValid = false,
                    VerificationTime = DateTime.Now
                };
            }
        }

        private static string CalculateProcessMemoryHash(Process process)
        {
            try
            {
                var processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, process.Id);
                if (processHandle != IntPtr.Zero)
                {
                    // Read first 4KB of process memory for hash calculation
                    var buffer = new byte[4096];
                    if (ReadProcessMemory(processHandle, IntPtr.Zero, buffer, buffer.Length, out var bytesRead))
                    {
                        using var sha256 = SHA256.Create();
                        var hash = sha256.ComputeHash(buffer);
                        return Convert.ToBase64String(hash);
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to calculate memory hash for process {process.Id}: {ex.Message}", Console.WriteLine);
            }
            
            return string.Empty;
        }

        private static bool CheckSuspiciousModules(Process process)
        {
            try
            {
                foreach (ProcessModule module in process.Modules)
                {
                    var moduleName = module.ModuleName.ToLower();
                    if (moduleName.Contains("inject") || 
                        moduleName.Contains("hook") || 
                        moduleName.Contains("suspicious") ||
                        moduleName.Contains("malware") ||
                        moduleName.Contains("trojan"))
                    {
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to check suspicious modules for process {process.Id}: {ex.Message}", Console.WriteLine);
            }
            
            return false;
        }

        private static bool CheckHighEntropyRegions(Process process)
        {
            try
            {
                var processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, process.Id);
                if (processHandle != IntPtr.Zero)
                {
                    // Check multiple memory regions for high entropy
                    var testAddresses = new[] { 0x10000000, 0x20000000, 0x30000000, 0x40000000 };
                    
                    foreach (var address in testAddresses)
                    {
                        var buffer = new byte[1024];
                        if (ReadProcessMemory(processHandle, (IntPtr)address, buffer, buffer.Length, out var bytesRead))
                        {
                            if (CalculateEntropy(buffer) > 7.5) // High entropy threshold
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to check high entropy regions for process {process.Id}: {ex.Message}", Console.WriteLine);
            }
            
            return false;
        }

        private static bool CheckInjectedCode(Process process)
        {
            try
            {
                // Check for suspicious thread creation patterns
                var threadCount = process.Threads.Count;
                
                // Check for remote thread creation
                foreach (ProcessThread thread in process.Threads)
                {
                    if (thread.StartAddress != IntPtr.Zero)
                    {
                        // Check if thread start address is in a suspicious range
                        var address = (long)thread.StartAddress;
                        if (address > 0x70000000) // Suspicious high address
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to check injected code for process {process.Id}: {ex.Message}", Console.WriteLine);
            }
            
            return false;
        }

        private static double CalculateEntropy(byte[] data)
        {
            try
            {
                var frequency = new int[256];
                foreach (var b in data)
                {
                    frequency[b]++;
                }
                
                var entropy = 0.0;
                var length = data.Length;
                
                for (int i = 0; i < 256; i++)
                {
                    if (frequency[i] > 0)
                    {
                        var probability = (double)frequency[i] / length;
                        entropy -= probability * Math.Log(probability, 2);
                    }
                }
                
                return entropy;
            }
            catch
            {
                return 0.0;
            }
        }

        private static void HandleInvalidSignature(Process process, ProcessSignature signature)
        {
            try
            {
                EnhancedLogger.LogWarning($"Invalid process signature detected: {process.ProcessName} (PID: {process.Id})", Console.WriteLine);
                
                var logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] Invalid process signature: {process.ProcessName} (PID: {process.Id})\n";
                logEntry += $"  Suspicious Modules: {signature.HasSuspiciousModules}\n";
                logEntry += $"  High Entropy: {signature.HasHighEntropyRegions}\n";
                logEntry += $"  Injected Code: {signature.HasInjectedCode}\n";
                
                var logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus", "Logs", "zero_trust_violations.log");
                File.AppendAllText(logPath, logEntry);
                
                // Trigger threat response
                HandleSuspiciousActivity("Invalid Process Signature", process.ProcessName);
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to handle invalid signature: {ex.Message}", Console.WriteLine);
            }
        }

        private static async void MonitorDllInjection()
        {
            while (isRunning)
            {
                try
                {
                    // Monitor for DLL injection attempts
                    var processes = Process.GetProcesses();
                    
                    foreach (var process in processes)
                    {
                        try
                        {
                            // Check for suspicious DLL loading patterns
                            if (DetectDllInjection(process))
                            {
                                HandleDllInjection(process);
                            }
                        }
                        catch (Exception ex)
                        {
                            EnhancedLogger.LogError($"Error monitoring DLL injection for process {process.Id}: {ex.Message}", Console.WriteLine);
                        }
                    }
                    
                    await Task.Delay(15000); // Check every 15 seconds
                }
                catch (Exception ex)
                {
                    EnhancedLogger.LogError($"Error in DLL injection monitoring: {ex.Message}", Console.WriteLine);
                    await Task.Delay(30000); // Wait longer on error
                }
            }
        }

        private static bool DetectDllInjection(Process process)
        {
            try
            {
                // Check for suspicious DLL loading patterns
                var suspiciousDlls = new[] { "kernel32.dll", "user32.dll", "ntdll.dll" };
                var loadedDlls = new List<string>();
                
                foreach (ProcessModule module in process.Modules)
                {
                    loadedDlls.Add(module.ModuleName.ToLower());
                }
                
                // Check if suspicious DLLs were loaded recently
                foreach (var suspiciousDll in suspiciousDlls)
                {
                    if (loadedDlls.Contains(suspiciousDll))
                    {
                        // Check if this is a new load
                        if (!ProcessSignatures.ContainsKey(process.Id) || 
                            !ProcessSignatures[process.Id].LoadedDlls.Contains(suspiciousDll))
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to detect DLL injection for process {process.Id}: {ex.Message}", Console.WriteLine);
            }
            
            return false;
        }

        private static void HandleDllInjection(Process process)
        {
            try
            {
                EnhancedLogger.LogWarning($"DLL injection detected in process {process.ProcessName} (PID: {process.Id})", Console.WriteLine);
                
                var logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] DLL injection detected in process {process.ProcessName} (PID: {process.Id})\n";
                var logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhageVirus", "Logs", "dll_injections.log");
                File.AppendAllText(logPath, logEntry);
                
                HandleSuspiciousActivity("DLL Injection", process.ProcessName);
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to handle DLL injection: {ex.Message}", Console.WriteLine);
            }
        }

        private static void MonitorAppInitDlls()
        {
            try
            {
                // Monitor AppInit_DLLs registry key for suspicious entries
                var appInitKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows");
                if (appInitKey != null)
                {
                    var appInitDlls = appInitKey.GetValue("AppInit_DLLs") as string;
                    if (!string.IsNullOrEmpty(appInitDlls))
                    {
                        EnhancedLogger.LogWarning($"AppInit_DLLs detected: {appInitDlls}", Console.WriteLine);
                        HandleSuspiciousActivity("AppInit_DLLs", appInitDlls);
                    }
                }
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to monitor AppInit_DLLs: {ex.Message}", Console.WriteLine);
            }
        }

        private static void HandleSuspiciousActivity(string activityType, string details)
        {
            try
            {
                // Create threat data for mesh sharing
                var threatData = new ThreatData
                {
                    ThreatHash = $"zerotrust_{DateTime.Now.Ticks}",
                    ThreatType = $"Zero Trust Violation: {activityType}",
                    TargetPath = details,
                    ThreatLevel = "Critical",
                    Description = $"Zero Trust runtime violation detected: {activityType} - {details}"
                };
                
                // Share with mesh network
                PhageSync.ShareThreat(threatData);
                
                // Trigger immediate system scan
                VirusHunter.ScanSystem();
                
                EnhancedLogger.LogWarning($"Zero Trust violation detected: {activityType} - {details}", Console.WriteLine);
            }
            catch (Exception ex)
            {
                EnhancedLogger.LogError($"Failed to handle suspicious activity: {ex.Message}", Console.WriteLine);
            }
        }

        public static List<ProcessSignature> GetProcessSignatures()
        {
            lock (signatureLock)
            {
                return ProcessSignatures.Values.ToList();
            }
        }

        public static bool IsZeroTrustActive()
        {
            return isRunning;
        }

        private static bool IsVirtualMachine()
        {
            try
            {
                // Simple VM detection
                var computerSystem = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                foreach (ManagementObject obj in computerSystem.Get())
                {
                    var manufacturer = obj["Manufacturer"]?.ToString()?.ToLower() ?? "";
                    var model = obj["Model"]?.ToString()?.ToLower() ?? "";
                    
                    if (manufacturer.Contains("vmware") || manufacturer.Contains("virtual") ||
                        model.Contains("vmware") || model.Contains("virtual") ||
                        manufacturer.Contains("microsoft") && model.Contains("virtual"))
                    {
                        return true;
                    }
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
    }

    public class ProcessSignature
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public bool IsValid { get; set; }
        public bool KnownProcess { get; set; }
        public string Description { get; set; } = "";
        public string MemoryHash { get; set; } = "";
        public bool HasSuspiciousModules { get; set; }
        public bool HasHighEntropyRegions { get; set; }
        public bool HasInjectedCode { get; set; }
        public DateTime VerificationTime { get; set; }
        public List<string> LoadedDlls { get; set; } = new();
    }

    // Delegate definitions for Windows hooks
    public delegate IntPtr CallWndProcDelegate(int nCode, IntPtr wParam, IntPtr lParam);
    public delegate IntPtr GetMessageDelegate(int nCode, IntPtr wParam, IntPtr lParam);
} 

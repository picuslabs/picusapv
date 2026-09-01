// ---------------------------------------------------- //
//    ______                 __ __                  __  //
//   / __/ /  ___ ________  / // /_   __ _____  ___/ /  //
//  _\ \/ _ \/ _ `/ __/ _ \/ _  / _ \/ // / _ \/ _  /   //
// /___/_//_/\_,_/_/ / .__/_//_/\___/\_,_/_//_/\_,_/    //
//                  /_/                                 //
//  app type    : console                               //
//  dotnet ver. : 462                                   //
//  client ver  : 3?                                    //
//  license     : open....?                             //
//------------------------------------------------------//
// creational_pattern : Inherit from System.CommandLine //
// structural_pattern  : Chain Of Responsibility         //
// behavioral_pattern : inherit from SharpHound3        //
// ---------------------------------------------------- //

using CommandLine;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using Sharphound.Client;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Sharphound
{

    #region Reference Implementations

    #endregion

    #region Console Entrypoint

    public class Program {
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_TERMINATE = 0x0001;
        private const int SystemProcessInformation = 5;

        private const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
        private const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
        private const uint SERVICE_DEMAND_START = 0x00000003;
        const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
        const int LOGON32_PROVIDER_DEFAULT = 0;

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public unsafe byte* lpSecurityDescriptor;
            public int bInheritHandle;
        }
        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }
        public const UInt32 TOKEN_DUPLICATE = 0x0002;
        public const UInt32 TOKEN_IMPERSONATE = 0x0004;
        public const UInt32 TOKEN_QUERY = 0x0008;
        public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
        public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpTokenAttributes,
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            TOKEN_TYPE TokenType,
            ref IntPtr phNewToken);


        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool LogonUser(
            string lpszUserName,
            string lpszDomain,
            string lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            ref IntPtr phToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool RevertToSelf();

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

        //=================
        private static Dictionary<uint, long> FindCmdProcesses(BasicLogger logger)
        {
            Dictionary<uint, long> result = new Dictionary<uint, long>();
            uint returnLen1 = 0;
            NtQuerySystemInformation(SystemProcessInformation, IntPtr.Zero, 0, out returnLen1);
            if (returnLen1 == 0)
            {
                logger.LogInformation("FindCmdProcesses - NtQuerySystemInformation returned 0 length");
                return result;
            }

            IntPtr pBuffer = Marshal.AllocHGlobal((int)returnLen1);
            try
            {
                uint returnLen2 = 0;
                int status = NtQuerySystemInformation(SystemProcessInformation, pBuffer, returnLen1, out returnLen2);
                if (status != 0)
                {
                    logger.LogInformation($"FindCmdProcesses - NtQuerySystemInformation failed. Status: 0x{status:X}");
                    return result;
                }

                IntPtr current = pBuffer;
                while (true)
                {
                    ushort imageNameLength = (ushort)Marshal.ReadInt16(current, 56);
                    if (imageNameLength > 0)
                    {
                        int bufferOffset = IntPtr.Size == 8 ? 64 : 60;
                        IntPtr imageNameBuffer = Marshal.ReadIntPtr(current, bufferOffset);
                        if (imageNameBuffer != IntPtr.Zero)
                        {
                            string imageName = Marshal.PtrToStringUni(imageNameBuffer, imageNameLength / 2);
                            if (imageName.Equals("cmd.exe", StringComparison.OrdinalIgnoreCase))
                            {
                                int pidOffset = IntPtr.Size == 8 ? 80 : 68;
                                uint pid = (uint)Marshal.ReadIntPtr(current, pidOffset).ToInt64();
                                long createTime = Marshal.ReadInt64(current, 32);
                                result[pid] = createTime;
                            }
                        }
                    }

                    uint nextOffset = (uint)Marshal.ReadInt32(current, 0);
                    if (nextOffset == 0)
                        break;
                    current = IntPtr.Add(current, (int)nextOffset);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pBuffer);
            }
            return result;
        }

        private static string GetProcessCommandLine(BasicLogger logger, uint processId)
        {
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, processId);
            if (hProcess == IntPtr.Zero)
            {
                logger.LogInformation($"GetProcessCommandLine - OpenProcess failed for PID {processId}. Error: {Marshal.GetLastWin32Error()}");
                return null;
            }
            try
            {
                PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
                int returnLength;
                int status = NtQueryInformationProcess(hProcess, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);
                if (status != 0)
                {
                    logger.LogInformation($"GetProcessCommandLine - NtQueryInformationProcess failed for PID {processId}. Status: 0x{status:X}");
                    return null;
                }

                byte[] pebBuffer = new byte[IntPtr.Size == 8 ? 0x100 : 0x80];
                int bytesRead;
                if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, pebBuffer, pebBuffer.Length, out bytesRead))
                {
                    logger.LogInformation($"GetProcessCommandLine - ReadProcessMemory (PEB) failed for PID {processId}. Error: {Marshal.GetLastWin32Error()}");
                    return null;
                }

                int processParamsOffset = IntPtr.Size == 8 ? 0x20 : 0x10;
                IntPtr processParamsPtr = IntPtr.Size == 8
                    ? (IntPtr)BitConverter.ToInt64(pebBuffer, processParamsOffset)
                    : (IntPtr)BitConverter.ToInt32(pebBuffer, processParamsOffset);

                byte[] paramsBuffer = new byte[IntPtr.Size == 8 ? 0x100 : 0x80];
                if (!ReadProcessMemory(hProcess, processParamsPtr, paramsBuffer, paramsBuffer.Length, out bytesRead))
                {
                    logger.LogInformation($"GetProcessCommandLine - ReadProcessMemory (ProcessParameters) failed for PID {processId}. Error: {Marshal.GetLastWin32Error()}");
                    return null;
                }

                int cmdLineOffset = IntPtr.Size == 8 ? 0x70 : 0x40;
                ushort cmdLineLength = BitConverter.ToUInt16(paramsBuffer, cmdLineOffset);
                int bufferPtrOffset = cmdLineOffset + (IntPtr.Size == 8 ? 8 : 4);
                IntPtr cmdLineBufferPtr = IntPtr.Size == 8
                    ? (IntPtr)BitConverter.ToInt64(paramsBuffer, bufferPtrOffset)
                    : (IntPtr)BitConverter.ToInt32(paramsBuffer, bufferPtrOffset);

                if (cmdLineLength == 0 || cmdLineBufferPtr == IntPtr.Zero)
                    return null;

                byte[] cmdLineBytes = new byte[cmdLineLength];
                if (!ReadProcessMemory(hProcess, cmdLineBufferPtr, cmdLineBytes, cmdLineLength, out bytesRead))
                {
                    logger.LogInformation($"GetProcessCommandLine - ReadProcessMemory (CommandLine) failed for PID {processId}. Error: {Marshal.GetLastWin32Error()}");
                    return null;
                }

                return Encoding.Unicode.GetString(cmdLineBytes);
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }

        //=================
        // dummyProc receives the process the token was taken from, so the caller can decide when to kill it
        // allMatchingPids returns all cmd processes that match the expected command line
        static WindowsImpersonationContext ImpersonateProcess(BasicLogger logger, out Process dummyProc, out List<uint> allMatchingPids)
        {
            dummyProc = null;
            allMatchingPids = new List<uint>();
            IntPtr correctProcessHandle = IntPtr.Zero;

            try
            {
                Dictionary<uint, long> cmdPids = FindCmdProcesses(logger);
                Dictionary<uint, long> matchingPids = new Dictionary<uint, long>();

                foreach (var entry in cmdPids)
                {
                    string cmdLine = GetProcessCommandLine(logger, entry.Key);
                    if (cmdLine != null && cmdLine.Equals("C:\\Windows\\System32\\cmd.exe /k echo picusadvdummyproc"))
                    {
                        matchingPids[entry.Key] = entry.Value;
                    }
                }

                if (matchingPids.Count == 0)
                {
                    logger.LogInformation("ImpersonateProcess: CMD process not found");
                    return null;
                }

                uint targetPid = 0;
                long maxCreateTime = long.MinValue;
                foreach (var entry in matchingPids)
                {
                    if (entry.Value > maxCreateTime)
                    {
                        maxCreateTime = entry.Value;
                        targetPid = entry.Key;
                    }
                }
                allMatchingPids = new List<uint>(matchingPids.Keys);

                correctProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION, false, targetPid);
                if (correctProcessHandle == IntPtr.Zero)
                {
                    logger.LogError($"ImpersonateProcess: OpenProcess failed ({Marshal.GetLastWin32Error()})");
                    return null;
                }

                IntPtr hToken = IntPtr.Zero;
                IntPtr hNewToken = IntPtr.Zero;

                try
                {
                    if (!OpenProcessToken(correctProcessHandle, TOKEN_READ | TOKEN_DUPLICATE, out hToken))
                    {
                        logger.LogError($"ImpersonateProcess: OpenProcessToken failed ({Marshal.GetLastWin32Error()})");
                        return null;
                    }

                    SECURITY_ATTRIBUTES at = new SECURITY_ATTRIBUTES();
                    if (!DuplicateTokenEx(hToken, TOKEN_QUERY | TOKEN_IMPERSONATE, ref at,
                        SECURITY_IMPERSONATION_LEVEL.SecurityDelegation, TOKEN_TYPE.TokenImpersonation, ref hNewToken))
                    {
                        logger.LogError($"ImpersonateProcess: DuplicateTokenEx failed ({Marshal.GetLastWin32Error()})");
                        return null;
                    }

                    var identity = new WindowsIdentity(hNewToken);
                    var ctx = identity.Impersonate();
                    try
                    {
                        dummyProc = Process.GetProcessById((int)targetPid);
                    }
                    catch
                    {
                        logger.LogInformation($"ImpersonateProcess: Could not get Process object for PID {targetPid}");
                    }
                    return ctx;
                }
                finally
                {
                    if (hToken != IntPtr.Zero) CloseHandle(hToken);
                    if (hNewToken != IntPtr.Zero) CloseHandle(hNewToken);
                }
            }
            catch (Exception ex)
            {
                logger.LogInformation($"ImpersonateProcess exception: {ex.Message}");
                return null;
            }
            finally
            {
                if (correctProcessHandle != IntPtr.Zero)
                    CloseHandle(correctProcessHandle);
            }
        }
        //=================


        public static async Task Main(string[] args) {
            var logger = new BasicLogger((int)LogLevel.Information);

            logger.LogInformation("This version of SharpHound is compatible with the 5.0.0 Release of BloodHound");

            try {
                // Checks the release version available on the machine.
                var releaseVersion = (int) Registry.GetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full", "Release", 0);
                if (releaseVersion == 0) releaseVersion = (int) Registry.GetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full", "Release", 0);
                // The value 461808 corresponds to .Net 4.7.2
                if (releaseVersion < 461808)
                {
                    logger.LogError("The .Net Runtime is not compatible with SharpHound. Please update to .Net 4.7.2.");
                    return;
                }

                var parser = new Parser(with => {
                    with.CaseInsensitiveEnumValues = true;
                    with.CaseSensitive = false;
                    with.HelpWriter = Console.Error;
                });
                var options = parser.ParseArguments<Options>(args);

                await options.WithParsedAsync(async options =>
                {
                    if (!options.ResolveCollectionMethods(logger, out var resolved, out var dconly)) return;

                    logger = new BasicLogger(options.Verbosity);

                    var flags = new Flags
                    {
                        Loop = options.Loop,
                        DumpComputerStatus = options.TrackComputerCalls,
                        NoRegistryLoggedOn = options.SkipRegistryLoggedOn,
                        ExcludeDomainControllers = options.ExcludeDCs,
                        SkipPortScan = options.SkipPortCheck,
                        SkipPasswordAgeCheck = options.SkipPasswordCheck,
                        DisableKerberosSigning = options.DisableSigning,
                        SecureLDAP = options.ForceSecureLDAP,
                        InvalidateCache = options.RebuildCache,
                        NoZip = options.NoZip,
                        NoOutput = false,
                        Stealth = options.Stealth,
                        RandomizeFilenames = options.RandomFileNames,
                        MemCache = options.MemCache,
                        CollectAllProperties = options.CollectAllProperties,
                        DCOnly = dconly,
                        PrettyPrint = options.PrettyPrint,
                        SearchForest = options.SearchForest,
                        RecurseDomains = options.RecurseDomains,
                        DoLocalAdminSessionEnum = options.DoLocalAdminSessionEnum,
                        ParititonLdapQueries = options.PartitionLdapQueries
                    };

                    var ldapOptions = new LdapConfig
                    {
                        Port = options.LDAPPort,
                        SSLPort = options.LDAPSSLPort,
                        DisableSigning = options.DisableSigning,
                        ForceSSL = options.ForceSecureLDAP,
                        AuthType = AuthType.Negotiate,
                        DisableCertVerification = options.DisableCertVerification
                    };

                    if (options.DomainController != null) ldapOptions.Server = options.DomainController;

                    if (options.LDAPUsername != null)
                    {
                        if (options.LDAPPassword == null)
                        {
                            logger.LogError("You must specify LDAPPassword if using the LDAPUsername options");
                            return;
                        }

                        ldapOptions.Username = options.LDAPUsername;
                        ldapOptions.Password = options.LDAPPassword;
                    }

                    // Check to make sure both Local Admin Session Enum options are set if either is set

                    if (options.LocalAdminPassword != null && options.LocalAdminUsername == null ||
                        options.LocalAdminUsername != null && options.LocalAdminPassword == null)
                    {
                        logger.LogError(
                            "You must specify both LocalAdminUsername and LocalAdminPassword if using these options!");
                        return;
                    }

                    // Check to make sure doLocalAdminSessionEnum is set when specifying localadmin and password

                    if (options.LocalAdminPassword != null || options.LocalAdminUsername != null)
                    {
                        if (options.DoLocalAdminSessionEnum == false)
                        {
                            logger.LogError(
                                "You must use the --doLocalAdminSessionEnum switch in combination with --LocalAdminUsername and --LocalAdminPassword!");
                            return;
                        }
                    }

                    // Check to make sure LocalAdminUsername and LocalAdminPassword are set when using doLocalAdminSessionEnum

                    if (options.DoLocalAdminSessionEnum == true)
                    {
                        if (options.LocalAdminPassword == null || options.LocalAdminUsername == null)
                        {
                            logger.LogError(
                                "You must specify both LocalAdminUsername and LocalAdminPassword if using the --doLocalAdminSessionEnum option!");
                            return;
                        }
                    }

                    await StartCollection(options, logger, resolved, flags, ldapOptions);
                });
            } catch (Exception ex) {
                logger.LogError($"Error running SharpHound: {ex.Message}\n{ex.StackTrace}");
            }
        }

        private static async Task StartCollection(Options options, BasicLogger logger, CollectionMethod resolved, Flags flags, LdapConfig ldapOptions)
        {
            IContext context = new BaseContext(logger, ldapOptions, flags)
            {
                DomainName = options.Domain,
                CacheFileName = options.CacheName,
                ZipFilename = options.ZipFilename,
                SearchBase = options.DistinguishedName,
                StatusInterval = options.StatusInterval,
                RealDNSName = options.RealDNSName,
                ComputerFile = options.ComputerFile,
                OutputPrefix = options.OutputPrefix,
                OutputDirectory = options.OutputDirectory,
                Jitter = options.Jitter,
                Throttle = options.Throttle,
                LdapFilter = options.LdapFilter,
                PortScanTimeout = options.PortCheckTimeout,
                ResolvedCollectionMethods = resolved,
                Threads = options.Threads,
                LoopDuration = options.LoopDuration,
                LoopInterval = options.LoopInterval,
                ZipPassword = options.ZipPassword,
                IsFaulted = false,
                LocalAdminUsername = options.LocalAdminUsername,
                LocalAdminPassword = options.LocalAdminPassword
            };

            var cancellationTokenSource = new CancellationTokenSource();
            context.CancellationTokenSource = cancellationTokenSource;

            // Console.CancelKeyPress += delegate(object sender, ConsoleCancelEventArgs eventArgs)
            // {
            //     eventArgs.Cancel = true;
            //     cancellationTokenSource.Cancel();
            // };

            // Create new chain links
            Links<IContext> links = new SharpLinks();

            WindowsImpersonationContext impCtx = null;
            Process dummyProc = null;
            List<uint> allMatchingCmdPids = null;
            if (WindowsIdentity.GetCurrent().IsSystem)
            {
                // Best effort: use the dummy CMD token when it is there, otherwise keep running as SYSTEM
                impCtx = ImpersonateProcess(logger, out dummyProc, out allMatchingCmdPids);
                if (impCtx == null)
                    logger.LogInformation("Impersonation not applied, continuing as SYSTEM.");
            }

            try
            {
            // Run our chain
            context = links.Initialize(context, ldapOptions);
            if (context.Flags.IsFaulted)
                return;
            context = await links.TestConnection(context);
            if (context.Flags.IsFaulted)
                return;
            context = links.SetSessionUserName(options.OverrideUserName, context);
            context = links.InitCommonLib(context);
            context = await links.GetDomainsForEnumeration(context);
            if (context.Flags.IsFaulted)
                return;
            context = links.StartBaseCollectionTask(context);
            context = await links.AwaitBaseRunCompletion(context);
            context = links.StartLoopTimer(context);
            context = links.StartLoop(context);
            context = await links.AwaitLoopCompletion(context);
            context = links.SaveCacheFile(context);
            links.Finish(context);
            }
            finally
            {
                impCtx?.Undo();

                // The dummy process is kept alive between runs so each one can steal its token.
                // ComputerOnly is the last step of the chain, so clean it up there.
                if (IsComputerOnlyRun(options))
                {
                    if (allMatchingCmdPids != null && allMatchingCmdPids.Count > 0)
                    {
                        foreach (uint pid in allMatchingCmdPids)
                        {
                            IntPtr hTerminate = OpenProcess(PROCESS_TERMINATE, false, pid);
                            if (hTerminate != IntPtr.Zero)
                            {
                                try
                                {
                                    if (!TerminateProcess(hTerminate, 0))
                                        logger.LogInformation($"Could not kill CMD process (PID {pid}): {Marshal.GetLastWin32Error()}");
                                    else
                                        logger.LogInformation($"Killed CMD process PID {pid} after ComputerOnly run.");
                                }
                                finally
                                {
                                    CloseHandle(hTerminate);
                                }
                            }
                            else
                            {
                                logger.LogInformation($"Failed to open CMD process for termination (PID {pid}): {Marshal.GetLastWin32Error()}");
                            }
                        }
                    }
                    else if (dummyProc != null)
                    {
                        try
                        {
                            dummyProc.Kill();
                            logger.LogInformation($"Killed dummy process PID {dummyProc.Id} after ComputerOnly run.");
                        }
                        catch (Exception ex)
                        {
                            logger.LogInformation($"Could not kill dummy process ({ex.Message})");
                        }
                    }
                }
            }
        }

        // True when ComputerOnly was requested, including as part of a comma separated list
        private static bool IsComputerOnlyRun(Options options)
        {
            if (options.CollectionMethods == null)
                return false;

            foreach (var method in options.CollectionMethods)
            {
                if (method == null) continue;
                foreach (var part in method.Split(','))
                {
                    if (part.Trim().Equals("ComputerOnly", StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }

            return false;
        }

        // Accessor function for the PS1 to work, do not change or remove
        public static void InvokeSharpHound(string[] args) {      
            Main(args).Wait();
        }
    }

    #endregion
}
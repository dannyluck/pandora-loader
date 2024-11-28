using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace pandora_loader
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.Title = "pandora-loader";
            Console.WriteLine("pandora-loader by louvresmile");
            Console.WriteLine("");

            Console.WriteLine("[+] Killing steam");
            Process.Start("taskkill", "/F /IM steam.exe");
            Thread.Sleep(1000);

            Console.WriteLine("[+] Starting steam");
            Process.Start("steam://");

            Console.WriteLine("[+] Downloading DLLs");

            using (var client = new WebClient())
            {
                client.DownloadFile("https://github.com/dannyluck/pandora-loader/raw/refs/heads/main/dll/pandora2022.dll", Path.Combine(Path.GetTempPath(), "pandora2022.dll"));
                client.DownloadFile("https://github.com/dannyluck/pandora-loader/raw/refs/heads/main/dll/steam-module.dll", Path.Combine(Path.GetTempPath(), "steam-module.dll"));
            }
            Console.WriteLine("[+] DLLs downloaded");

            Console.WriteLine("[+] Injecting steam module");

            WaitForProcessAndInject("steam", Path.Combine(Path.GetTempPath(), "steam-module.dll"), 30000, 2000); // 30 seconds timeout

            Console.WriteLine("[+] Waiting for CS:GO (launch manually)");
            WaitForProcessAndInject("csgo", Path.Combine(Path.GetTempPath(), "pandora2022.dll"), 60000, 5000); // 60 seconds timeout


            Thread.Sleep(5000);
        }

        static bool IsProcessRunning(string processName)
        {
            Process[] processes = Process.GetProcessesByName(processName);
            return processes.Length > 0;
        }

        static void WaitForProcessAndInject(string processName, string dllPath, int timeoutMs, int delayAfterStartMs)
        {
            int waited = 0;
            int interval = 3000;

            while (waited < timeoutMs)
            {
                if (IsProcessRunning(processName))
                {
                    Thread.Sleep(delayAfterStartMs);

                    BasicInject.Injector(dllPath, processName);
                    return;
                }

                Thread.Sleep(interval);
                waited += interval;
            }

            Console.WriteLine($"[-] Timed out waiting for {processName} to start.");
        }

    }

    public class BasicInject
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
            uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess,
            IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        const int PROCESS_CREATE_THREAD = 0x0002;
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_OPERATION = 0x0008;
        const int PROCESS_VM_WRITE = 0x0020;
        const int PROCESS_VM_READ = 0x0010;

        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_READWRITE = 4;

        public static int Injector(string dllPath, string processName)
        {
            // Find the target process
            Process targetProcess = Process.GetProcessesByName(processName).FirstOrDefault();
            if (targetProcess == null)
            {
                Console.WriteLine($"[-] Process '{processName}' not found.");
                return -1;
            }

            // Get the handle of the process with required privileges
            IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, targetProcess.Id);

            // Get the address of LoadLibraryA
            IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            // Allocate memory in the target process for the DLL path
            IntPtr allocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            // Write the DLL path to the allocated memory
            UIntPtr bytesWritten;
            WriteProcessMemory(procHandle, allocMemAddress, Encoding.Default.GetBytes(dllPath), (uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);

            // Create a remote thread that calls LoadLibraryA with the DLL path
            CreateRemoteThread(procHandle, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);

            return 0;
        }
    }
}

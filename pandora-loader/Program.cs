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
            Console.WriteLine("[+] Killing steam");
            Process.Start("taskkill", "/F /IM steam.exe");
            Thread.Sleep(2000);

            Console.WriteLine("[+] Starting steam");
            Process.Start("steam://");

            Console.WriteLine("[+] Downloading DLLs");

            using (var client = new WebClient())
            {
                client.DownloadFile("https://github.com/dannyluck/pandora-loader/raw/refs/heads/main/dll/pandora2022.dll", Path.Combine(Path.GetTempPath(), "pandora2022.dll"));
                client.DownloadFile("https://github.com/dannyluck/pandora-loader/raw/refs/heads/main/dll/steam-module.dll", Path.Combine(Path.GetTempPath(), "steam-module.dll"));
            }
            Console.WriteLine("[+] DLLs downloaded");

            Thread.Sleep(9000);
            Console.WriteLine("[+] Injecting steam module");
            BasicInject.Injector(Path.Combine(Path.GetTempPath(), "steam-module.dll"), "steam");
            Console.WriteLine("[+] Steam module injected");

            Console.WriteLine("[+] Waiting for CS:GO (launch manually)");
            Thread.Sleep(20000);

            Console.WriteLine("[+] Injecting pandora");
            BasicInject.Injector(Path.Combine(Path.GetTempPath(), "pandora2022.dll"), "csgo");
            Console.WriteLine("[+] Pandora injected");
            Thread.Sleep(5000);

            if (File.Exists(Path.Combine(Path.GetTempPath(), "steam-module.dll")) && (File.Exists(Path.Combine(Path.GetTempPath(), "pandora2022.dll"))))
            {
                File.Delete(Path.Combine(Path.GetTempPath(), "steam-module.dll"));
                File.Delete(Path.Combine(Path.GetTempPath(), "pandora2022.dll"));
            }
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

            Console.WriteLine("[+] Injection complete.");
            return 0;
        }
    }

    public class SteamGameLocator
    {
        private static readonly string steamRegPath = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Valve\\Steam"; // not compatible with 32-bit

        private bool? steamInstalled = null;
        private string steamInstallPath = null;
        private List<string> steamLibraryList = new List<string>();
        private List<GameStruct> steamGameList = new List<GameStruct>();

        /// <summary>
        /// A struct holding properties on games
        /// </summary>
        public struct GameStruct
        {
            public string steamGameID;
            public string steamGameName;
            public string steamGameLocation;
        }

        /// <summary>
        /// Returns a bool of whether Steam is installed or not.
        /// </summary>
        /// <returns>
        /// True = Steam is installed. False = Steam is not installed.
        /// </returns>
        /// <exception cref="SecurityException">Thrown if unsufficient permissions to check Steam install.</exception>
        public bool getIsSteamInstalled() // function to return a boolean of whether steam is installed or not
        {
            if (steamInstalled != null) { return (bool)steamInstalled; } // if this information is already stored, let's use that instead
            try // try statement, this could fail due to registry errors, or if the user does not have admin perms
            {
                string steamInstallPath = RegistryHandler.safeGetRegistryKey("InstallPath", steamRegPath); // uses a safe way of getting the registry key
                if (steamInstallPath == null) { steamInstalled = false; return (bool)steamInstalled; } // if the safe registry returner is null, then steam is not installed
                if (Directory.Exists(steamInstallPath) == false) { steamInstalled = false; return (bool)steamInstalled; } // if the folder location in the registry key is not on the system, then steam is not installed
            }
            catch (ArgumentNullException) { steamInstalled = false; return (bool)steamInstalled; } // unlikely to occur, but could be raised by safe registry returner, will return false as it would mean failed to find reg key
            catch (SecurityException sx) { throw sx; } // security exception, means user needs more perms. will throw this exception back to the program to resolve
            catch (Exception ex) { throw ex; } // any other general exception - this should never occur but good practice to throw other exceptions back to program
            steamInstalled = true;
            return (bool)steamInstalled; // if other 'guard if statements' are passed, then steam is accepted to be installed
        }

        /// <summary>
        /// Returns a string of the location of where steam is installed.
        /// </summary>
        /// <returns>
        /// string - the full file path of where Steam is installed.
        /// </returns>
        /// <exception cref="DirectoryNotFoundException">Thrown if Steam is not installed.</exception>
        /// <exception cref="SecurityException">Thrown if unsufficient permissions to check Steam install path.</exception>
        public string getSteamInstallLocation()
        {
            if (steamInstallPath != null && Directory.Exists(steamInstallPath)) { return steamInstallPath; } // if this information is already stored, let's use that instead
            try // try statement, this could fail due to registry errors, or if the user does not have admin perms
            {
                steamInstallPath = RegistryHandler.safeGetRegistryKey("InstallPath", steamRegPath); // uses a safe way of getting the registry key
                if (steamInstallPath == null) { throw new DirectoryNotFoundException(); } // if the safe registry returner is null, then steam is not installed. throw directory not found exception
                if (Directory.Exists(steamInstallPath) == false) { throw new DirectoryNotFoundException(); } // if the folder location in the registry key is not on the system, then steam is not installed. throw directory not found exception
            }
            catch (ArgumentNullException) { throw new DirectoryNotFoundException(); } // unlikely to occur, but could be raised by safe registry returner, will return false as it would mean failed to find reg key
            catch (SecurityException sx) { throw sx; } // security exception, means user needs more perms. will throw this exception back to the program to resolve
            catch (Exception ex) { throw ex; } // any other general exception - this should never occur but good practice to throw other exceptions back to program
            return steamInstallPath; // if other 'guard if statements' are passed, then steam is accepted to be installed
        }

        /// <summary>
        /// Returns a list of strings with the locations of Steam library folders.
        /// </summary>
        /// <returns>
        /// List of strings with the full file location of the library folder.
        /// </returns>
        public List<String> getSteamLibraryLocations()
        {
            if (steamLibraryList.Count != 0) { return steamLibraryList; } // if this information is already stored, let's use that instead

            if (steamInstallPath == null) { getSteamInstallLocation(); } // if the steam install path has not already been fetched, fetch it

            StreamReader libraryVDFReader = File.OpenText(steamInstallPath + "\\steamapps\\libraryfolders.vdf");
            string lineReader = libraryVDFReader.ReadLine();
            bool continueRead = true;
            while (continueRead)
            {
                while (lineReader.Contains("path") == false)
                {
                    try
                    {
                        lineReader = libraryVDFReader.ReadLine(); // waiting to read in a line that looks like: "path"      "C:\location\to\library\folder"
                        if (lineReader == null) { break; }
                    }
                    catch (Exception) // End of file exception
                    {
                        continueRead = false; // stop reading
                        break; // break this loop
                    }
                }
                if (lineReader == null) { break; }
                string cleanLine = lineReader.Replace("\"path\"", ""); // we then clean this up by removing the path part, leaving us with:         "C:\location\to\library\folder"
                cleanLine = cleanLine.Split('"')[1]; // we then remove the leading spaces and quotes to get: C:\location\to\library\folder"
                cleanLine = cleanLine.Replace("\"", ""); // we then remove the last quote to get: C:\location\to\library\folder

                lineReader = libraryVDFReader.ReadLine(); // prevents it from getting stuck on the same library folder

                if (Directory.Exists(cleanLine)) { steamLibraryList.Add(cleanLine); } // if the directory exists on the disk, then add it to the library list
            }
            return steamLibraryList;
        }

        /// <summary>
        /// Returns the install path of a game, by it's Steam install folder.
        /// </summary>
        /// <param name="gameName">The name of the folder Steam installs the game to.</param>
        /// <returns>
        /// GameStruct - useful properties being steamGameName and steamGameLocation.
        /// </returns>
        /// <exception cref="DirectoryNotFoundException">Thrown if the game is not installed.</exception>
        public GameStruct getGameInfoByAppID(string appID)
        {
            if (steamGameList.Count != 0)
            {
                foreach (GameStruct steamGame in steamGameList)
                {
                    if (steamGame.steamGameID == appID) { return steamGame; } // If the game is already stored, return it.
                }
            }

            GameStruct gameInfo = new GameStruct();
            gameInfo.steamGameID = appID;

            if (steamLibraryList.Count == 0) { getSteamLibraryLocations(); } // Fetch library locations if not already done.

            foreach (string libraryFolder in steamLibraryList)
            {
                string acfFilePath = Path.Combine(libraryFolder, "steamapps", $"appmanifest_{appID}.acf");

                if (File.Exists(acfFilePath))
                {
                    string gameInstallDir = GetGameInstallDirFromACF(acfFilePath);

                    if (!string.IsNullOrEmpty(gameInstallDir))
                    {
                        // Use Path.Combine to ensure correct path formatting.
                        gameInfo.steamGameLocation = Path.Combine(libraryFolder, "steamapps", "common", gameInstallDir);
                        gameInfo.steamGameName = gameInstallDir;

                        // Replace double backslashes, if any.
                        gameInfo.steamGameLocation = gameInfo.steamGameLocation.Replace(@"\\", @"\");

                        steamGameList.Add(gameInfo);
                        return gameInfo;
                    }
                }
            }

            throw new DirectoryNotFoundException($"Game with App ID {appID} not found.");
        }

        private string GetGameInstallDirFromACF(string acfFilePath)
        {
            using (StreamReader reader = new StreamReader(acfFilePath))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (line.Contains("\"installdir\""))
                    {
                        // Extract and clean up the installdir value.
                        string rawPath = line.Split('"')[3].Trim();
                        return rawPath.Replace(@"\\", @"\"); // Ensure no double backslashes.
                    }
                }
            }
            return null;
        }
    }

    internal static class RegistryHandler
    {
        public static string safeGetRegistryKey(string keyName, string regPath)
        {
            object regKeyObj = Registry.GetValue(regPath, keyName, null);
            if (regKeyObj != null)
            {
                return regKeyObj.ToString();
            }
            else
            {
                return null;
            }
        }
    }


}

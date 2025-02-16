using PKMBlack2TextHook;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;

class Program
{
    // Access rights
    const int PROCESS_QUERY_INFORMATION = 0x0400;
    const int PROCESS_VM_READ = 0x0010;
    // Memory constants
    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_GUARD = 0x100;
    const uint PAGE_NOACCESS = 0x01;

    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        UIntPtr dwSize,
        out UIntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        UIntPtr dwSize,
        out UIntPtr lpNumberOfBytesWritte
        );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern UIntPtr VirtualQueryEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer,
        UIntPtr dwLength);

    [DllImport("user32.dll")]
    private static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll")]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll")]
    private static extern bool EmptyClipboard();

    [DllImport("user32.dll")]
    private static extern IntPtr SetClipboardData(uint uFormat, IntPtr hMem);

    static void CopyToClipboard(string text)
    {
        OpenClipboard(IntPtr.Zero);
        EmptyClipboard();
        IntPtr hGlobal = Marshal.StringToHGlobalUni(text);
        SetClipboardData(13, hGlobal);
        CloseClipboard();
    }

    [StructLayout(LayoutKind.Sequential)]
    struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    static Process HookProcess()
    {
        Process[] processes = Process.GetProcessesByName("melonDS");
        if (processes.Length == 0)
        {
            Console.WriteLine("Process not found.");
            Thread.Sleep(5000);
            return HookProcess();
        }

        IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, processes[0].Id);
        if (hProcess == IntPtr.Zero)
        {
            Console.WriteLine("Failed to open process.");
            return HookProcess();
        }
        Console.WriteLine("Process hooked.");
        return processes[0];
    }

    static UInt64 AoBScan(Process proc, byte[] pattern, string mask)
    {

        UInt64 startAddress = 0x10000000000;
        UInt64 endAddress = 0x3FFFFFFFFFF;
        UInt64 currentAddress = startAddress;
        UInt64 foundAddress = 0;

        while (currentAddress < endAddress)
        {
            MEMORY_BASIC_INFORMATION mbi;
            UIntPtr mbiSize = (UIntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            UIntPtr result = VirtualQueryEx(proc.Handle, new IntPtr((long)currentAddress), out mbi, mbiSize);
            if (result == UIntPtr.Zero)
                break;

            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) == 0 && (mbi.Protect & PAGE_NOACCESS) == 0)
            {
                UInt64 regionStart = (UInt64)mbi.BaseAddress.ToInt64();

                int regionSize = (int)mbi.RegionSize;
                byte[] buffer = new byte[regionSize];

                if (ReadProcessMemory(proc.Handle, mbi.BaseAddress, buffer, (UIntPtr)regionSize, out UIntPtr bytesRead))
                {
                    int index = FindPattern(buffer, pattern, mask);
                    if (index != -1)
                    {
                        foundAddress = regionStart + (UInt64)index;
                        Console.WriteLine($"Pattern found at: 0x{foundAddress:X}");
                        break;
                    }
                }
            }

            currentAddress = (UInt64)mbi.BaseAddress.ToInt64() + (UInt64)mbi.RegionSize;
        }


        return foundAddress;

    }

    static byte[] baseAddressPattern = new byte[] { 0xFB, 0x80, 0x04, 0xFF, 0x00, 0xEC, 0xD2, 0xF8, 0xB6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x30 };
    static string baseAddressMask = "xxx?xxxxx???????x";

    static byte[] combatAddressPattern = new byte[] { 0x80, 0x01, 0x0C, 0x00, 0xEC, 0xD2, 0xF8, 0xB6}; //To test
    static string combatAddressMask = "xxxxxxxx";


    static UInt64 GetCurrentAddress(Process proc)
    {
        UInt64 currentAddress = 0;

        while(currentAddress == 0)
        {
            currentAddress = AoBScan(proc, baseAddressPattern, baseAddressMask);

            if(currentAddress != 0)
            {
                Console.WriteLine("Text address found");
                break;
            }
            else
            {
                Console.WriteLine("Text address not found, talk to a NPC first");
            }

            currentAddress = AoBScan(proc, combatAddressPattern, combatAddressMask);
            if (currentAddress != 0)
            {
                byte[] buffer = new byte[32];
                if (ReadProcessMemory(proc.Handle, (nint)(currentAddress + 9), buffer, 32, out UIntPtr bytesRead))
                {
                    if (buffer[0] == 0)
                    {
                        Console.WriteLine("Combat address found, but currently not in combat");
                        currentAddress = 0;
                    }
                    else
                    {
                        break;
                    }

                }
            }
            else
            {
                Console.WriteLine("Combat address not found, restart the game and hope it fixes by itself");
            }



            Thread.Sleep(5000);
        }

        return currentAddress + 9;

    }

    static void Main(string[] args)
    {

        ChangeFont.SetConsoleFont("NSimSun");
        Process proc = HookProcess();

        UInt64 baseAddress = GetCurrentAddress(proc);

        Console.OutputEncoding = Encoding.UTF8;
        string lastString = " ";
        while (true)
        {
            byte[] buffer = new byte[500];
            if (ReadProcessMemory(proc.Handle, (nint)baseAddress, buffer, 500, out UIntPtr bytesRead))
            {
                byte[] emptyBuffer = new byte[500];
                WriteProcessMemory(proc.Handle, (nint)baseAddress, emptyBuffer, 500, out UIntPtr bytesWritten);

                string text = Encoding.Unicode.GetString(buffer, 0, (int)bytesRead);

                Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
                string regpattern = @"[^\u3040-\u309F\u30A0-\u30FF\u4E00-\u9FFF\uAC00-\uD7AF\uFF00-\uFFEF\s\p{P}]";
                text = Regex.Replace(text, regpattern, "");
                string kanjiPattern = @"[\p{IsCJKUnifiedIdeographs}\uAC00-\uD7AF]{5,}";
                text = Regex.Replace(text, kanjiPattern, "");
                text = text.Replace("븁", "\n");



                if (text != lastString && text != "")
                {
                    lastString = text;

                    Console.WriteLine("----------------------------------");
                    Console.WriteLine(text);
                    CopyToClipboard(text);


                }
                Thread.Sleep(1000);

            }
        }


    }


    static int FindPattern(byte[] data, byte[] pattern, string mask)
    {
        for (int i = 0; i <= data.Length - pattern.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (mask[j] == 'x' && data[i + j] != pattern[j])
                {
                    match = false;
                    break;
                }
            }
            if (match)
                return i;
        }
        return -1;
    }
}

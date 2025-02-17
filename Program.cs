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

    static List<UInt64> AoBScan(Process proc, byte[] pattern, string mask)
    {
        List<UInt64> foundAddresses = new List<UInt64>();
        UInt64 startAddress = 0x10000000000;
        UInt64 endAddress = 0x3FFFFFFFFFF;
        UInt64 currentAddress = startAddress;

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
                    int offset = 0;
                    while (true)
                    {
                        int index = FindPattern(buffer, pattern, mask, offset);
                        if (index == -1)
                            break;
                        foundAddresses.Add(regionStart + (UInt64)index);
                        offset = index + 1;
                    }
                }
            }

            currentAddress = (UInt64)mbi.BaseAddress.ToInt64() + (UInt64)mbi.RegionSize;
        }

        return foundAddresses;
    }

    static string baseAddressAob = "73 74 72 62 75 66 2E 63 00 ?? 00 ?? 00 ?? 00 ?? ?? 00 64 00 ?? ?? 00 ?? 80 04 ?? 00 EC D2 F8 B6";
    static string combatAddressAoB = "24 80 01 ?? 00 EC D2 F8 B6";

    static UInt64 baseAddress;
    static UInt64 combatAddress;


    static bool combat = false;

    static UInt64 GetCurrentAddress(Process proc)
    {
        UInt64 currentAddress = 0;

        var (basePattern, baseMask) = ParseAoB(baseAddressAob);
        var (combatPattern, combatMask) = ParseAoB(combatAddressAoB);

        while (currentAddress == 0)
        {
            if (combatAddress == 0)
            {
                var combatAddresses = AoBScan(proc, combatPattern, combatMask);
                if (combatAddresses.Count > 0)
                {
                    foreach (var addr in combatAddresses)
                    {
                        byte[] buffer = new byte[1];
                        if (ReadProcessMemory(proc.Handle, (IntPtr)(addr + 10), buffer, 1, out _) && buffer[0] != 0)
                        {
                            combat = true;
                            currentAddress = addr + 9;
                            combatAddress = currentAddress;
                            break;
                        }
                    }
                }
            }
            else
            {
                byte[] buffer = new byte[1];
                if (ReadProcessMemory(proc.Handle, (IntPtr)(combatAddress-6), buffer, 1, out _) && buffer[0] != 0)
                {
                    combat = true;
                    currentAddress = combatAddress;
                    break;
                }
                else
                {
                    combatAddress = 0;
                }
            }

            if (baseAddress == 0)
            {
                var baseAddresses = AoBScan(proc, basePattern, baseMask);
                if (baseAddresses.Count > 0)
                {
                    foreach (var addr in baseAddresses)
                    {
                        byte[] buffer = new byte[1];
                        if (ReadProcessMemory(proc.Handle, (IntPtr)(addr + 32), buffer, 1, out _) && buffer[0] != 0)
                        {
                            combat = false;
                            currentAddress = addr + 32;
                            baseAddress = currentAddress;
                            break;
                        }
                    }
                }
            }
            else
            {
                byte[] buffer = new byte[1];
                if (ReadProcessMemory(proc.Handle, (IntPtr)baseAddress, buffer, 1, out _) && buffer[0] != 0)
                {
                    combat = false;
                    currentAddress = baseAddress;
                    break;
                }
                else
                {
                    baseAddress = 0;
                }
            }




            Thread.Sleep(5000);
        }

        return currentAddress;
    }


    static void Main(string[] args)
    {

        ChangeFont.SetConsoleFont("NSimSun");
        Process proc = HookProcess();

        UInt64 baseAddress = GetCurrentAddress(proc);

        Console.OutputEncoding = Encoding.UTF8;
        string lastString = " ";
        long startTime = DateTime.Now.Ticks / TimeSpan.TicksPerMillisecond;
        int oldTextLenght = 0;
        while (true)
        {          
            byte[] buffer = new byte[500];
            if (ReadProcessMemory(proc.Handle, (nint)baseAddress, buffer, 500, out UIntPtr bytesRead))
            {
                byte[] emptyBuffer = new byte[500];

                string text = Encoding.GetEncoding("UTF-16LE").GetString(buffer, 0, (int)bytesRead);

                Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

                text = text.Replace("븁", "\n");

                text = text.Split("￿")[0];


                if (text != lastString)
                {
                    lastString = text;
                    Console.WriteLine("----------------------------------");
                    Console.WriteLine(text);
                    CopyToClipboard(text);
                }
                Thread.Sleep(500);

                baseAddress = GetCurrentAddress(proc);
            }
        }


    }

    static (byte[] pattern, string mask) ParseAoB(string aob)
    {
        List<byte> pattern = new List<byte>();
        StringBuilder mask = new StringBuilder();

        string[] tokens = aob.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (string token in tokens)
        {
            if (token == "??")
            {
                pattern.Add(0x00);
                mask.Append('?');
            }
            else
            {
                pattern.Add(Convert.ToByte(token, 16));
                mask.Append('x');
            }
        }

        return (pattern.ToArray(), mask.ToString());
    }

    static int FindPattern(byte[] data, byte[] pattern, string mask, int startIndex = 0)
    {
        for (int i = startIndex; i <= data.Length - pattern.Length; i++)
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

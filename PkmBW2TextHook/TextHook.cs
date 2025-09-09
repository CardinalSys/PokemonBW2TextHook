using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace PkmBW2TextHook
{
    public class TextHook
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

        public void CopyToClipboard(string text)
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

        public event Action<string>? OnTextExtracted;
        public event Action<string>? OnLog;

        private static bool _running = true;
        private static bool combatEnd = false;
        private static string lastString = " ";

        private Process? _proc;

        static string baseAddressAob = "28 ?? 00 00 ?? ?? ?? 02 ?? ?? ?? 02 ?? 00 4E 19 73 74 72 62 75 66 2E 63 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 00 ?? ?? ?? ?? 80 ?? ?? 00 EC D2 F8 B6";

        public void HookProcess()
        {
            Process[] processes = Process.GetProcessesByName("melonDS");
            if (processes.Length == 0)
            {
                OnLog?.Invoke("Process not found...");
                return;
            }

            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, processes[0].Id);
            if (hProcess == IntPtr.Zero)
            {
                OnLog?.Invoke("Can't open the process, retrying...");
                Thread.Sleep(5000);
                HookProcess();
                return;
            }

            _proc = processes[0];
            OnLog?.Invoke("Process hooked.");
        }

        public void StartExtracting()
        {
            if (_proc == null)
            {
                OnLog?.Invoke("No hay proceso enganchado.");
                return;
            }
            OnLog?.Invoke("Getting base address");
            UInt64 baseAddress = GetCurrentAddress(_proc);

            var scannerThread = new Thread(() =>
            {
                while (_running)
                {
                    UInt64 newAddress = GetCurrentAddress(_proc);
                    if (newAddress != 0 && newAddress != baseAddress && !combatEnd)
                    {
                        baseAddress = newAddress;
                        OnLog?.Invoke($"Base address: {baseAddress.ToString("X")}");
                    }
                    Thread.Sleep(500);
                }
            })
            { IsBackground = true };
            scannerThread.Start();
            OnLog?.Invoke("Starting text extraction");
            var readerThread = new Thread(() =>
            {
                while (_running)
                {

                    byte[] buffer = new byte[500];
                    if (ReadProcessMemory(_proc.Handle, (nint)baseAddress, buffer, 500, out UIntPtr bytesRead))
                    {
                        string text = Encoding.GetEncoding("UTF-16LE").GetString(buffer, 0, (int)bytesRead);
                        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
                        text = text.Replace("\0", "");
                        text = text.Replace("븁", "\n");

                        text = text.Split("￿")[0];
                        text = text.Replace("", "");

                        text = text.Replace("븀", "\n");
                        text = text.Replace("￾", " ");
                        if (text != lastString && text != "" && text != " " && text != "　" && !text.Contains("❣") && !text.Contains("�"))
                        {
                            combatEnd = false;
                            lastString = text;

                            OnTextExtracted?.Invoke(text);

                            CopyToClipboard(text);
                        }
                        Thread.Sleep(500);
                    }
                }
            })
            { IsBackground = true };
            readerThread.Start();
        }

        static UInt64 GetCurrentAddress(Process proc)
        {
            var (basePattern, baseMask) = ParseAoB(baseAddressAob);
            var baseAddresses = AoBScan(proc, basePattern, baseMask);
            if (baseAddresses.Count > 0)
                return baseAddresses[0] + 48;
            else
                return 0;
        }

        static List<UInt64> AoBScan(Process proc, byte[] pattern, string mask)
        {
            List<UInt64> foundAddresses = new List<UInt64>();
            UInt64 startAddress = 0x10000000000;
            UInt64 endAddress = 0x40000000000;
            UInt64 currentAddress = startAddress;
            const int CHUNK_SIZE = 4096;
            byte[] buffer = new byte[CHUNK_SIZE];

            while (currentAddress < endAddress)
            {
                MEMORY_BASIC_INFORMATION mbi;
                UIntPtr mbiSize = (UIntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
                UIntPtr result = VirtualQueryEx(proc.Handle, new IntPtr((long)currentAddress), out mbi, mbiSize);
                if (result == UIntPtr.Zero) break;

                if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) == 0 && (mbi.Protect & PAGE_NOACCESS) == 0)
                {
                    UInt64 regionStart = (UInt64)mbi.BaseAddress.ToInt64();
                    UInt64 regionSize = (UInt64)mbi.RegionSize;

                    for (UInt64 offset = 0; offset < regionSize; offset += CHUNK_SIZE)
                    {
                        IntPtr readAddress = new IntPtr((long)(regionStart + offset));
                        int bytesToRead = (int)Math.Min(CHUNK_SIZE, regionSize - offset);
                        if (ReadProcessMemory(proc.Handle, readAddress, buffer, (UIntPtr)bytesToRead, out UIntPtr bytesRead))
                        {
                            int baseOffset = 0;
                            while (baseOffset <= bytesToRead - pattern.Length)
                            {
                                int index = FindPattern(buffer, pattern, mask, baseOffset);
                                if (index == -1) break;
                                foundAddresses.Add(regionStart + offset + (UInt64)index);
                                baseOffset = index + 1;
                            }
                        }
                    }
                }
                currentAddress = (UInt64)mbi.BaseAddress.ToInt64() + (UInt64)mbi.RegionSize;
            }

            return foundAddresses;
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
                if (match) return i;
            }
            return -1;
        }
    }
}

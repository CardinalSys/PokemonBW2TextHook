using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PKMBlack2TextHook
{


    public class ChangeFont
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct COORD
        {
            public short X;
            public short Y;

            public COORD(short x, short y)
            {
                X = x;
                Y = y;
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CONSOLE_FONT_INFOEX
        {
            public uint cbSize;
            public uint nFont;
            public COORD dwFontSize;
            public int FontFamily;
            public int FontWeight;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string FaceName;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetCurrentConsoleFontEx(
            IntPtr hConsoleOutput,
            bool bMaximumWindow,
            ref CONSOLE_FONT_INFOEX lpConsoleCurrentFontEx);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetCurrentConsoleFontEx(
            IntPtr hConsoleOutput,
            bool bMaximumWindow,
            ref CONSOLE_FONT_INFOEX lpConsoleCurrentFontEx);

        public static void SetConsoleFont(string fontName = "Lucida Console", short fontSizeX = 8, short fontSizeY = 16)
        {
            CONSOLE_FONT_INFOEX info = new CONSOLE_FONT_INFOEX();
            info.cbSize = (uint)Marshal.SizeOf<CONSOLE_FONT_INFOEX>();
            IntPtr hConsole = GetStdHandle(-11);


            if (!GetCurrentConsoleFontEx(hConsole, false, ref info))
            {
                throw new System.ComponentModel.Win32Exception();
            }


            info.dwFontSize.X = fontSizeX;
            info.dwFontSize.Y = fontSizeY;
            info.FontFamily = 0x36;
            info.FontWeight = 400;
            info.FaceName = fontName;


            if (!SetCurrentConsoleFontEx(hConsole, false, ref info))
            {
                throw new System.ComponentModel.Win32Exception();
            }
        }

    }
}

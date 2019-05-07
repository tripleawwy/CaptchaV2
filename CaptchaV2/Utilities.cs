using System;
using System.Drawing;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static DLLImports.Kernel32DLL;
using static DLLImports.Kernel32DLL.ProcessAccessFlags;
using static DLLImports.User32DLL;
using static DLLImports.User32DLL.WM_Flags;


namespace CaptchaV2
{
    public static class Utilities
    {


        public static void WriteCaptchaNumbers(IntPtr targetHandle, IntPtr writePtr, byte[] byteArray)
        {
            WriteProcessMemory(targetHandle, writePtr, byteArray, byteArray.Length , out _);
        }

        public static byte[] ConvertToUTF16(byte[] byteArray)
        {
            byte[] convertedArray = new byte[byteArray.Length * 2];

            for (int i = 0; i < byteArray.Length; i++)
            {
                convertedArray[i * 2] = byteArray[i];
            }

            return convertedArray;
        }

        public static void LeftClick(IntPtr targetHandle, Point wantedPosition)
        {
            uint spot = CalcLParamCoordinates(wantedPosition);
            PostMessage(targetHandle, WM_LBUTTONDOWN, 0x00000001, spot);
            PostMessage(targetHandle, WM_LBUTTONUP, 0x00000000, spot);
        }

        //calculates coordinate parameters (Y Coordinate = LOWWORD ; X Coordinate = HIGHWORD)
        private static uint CalcLParamCoordinates(Point wantedPosition)
        {
            uint spot = (uint)(wantedPosition.Y << 16) | (uint)wantedPosition.X;
            return spot;
        }

    }
}

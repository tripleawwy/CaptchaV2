using System;
using System.Drawing;
using System.Windows.Forms;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static DLLImports.Kernel32DLL;
using static DLLImports.User32DLL;
using static DLLImports.Kernel32DLL.ProcessAccessFlags;

namespace CaptchaV2
{

    public struct ScanStructure
    {
        public ScanStructure(IntPtr ptr, byte[] value)
        {
            Address = ptr;
            Value = value;
        }
        public IntPtr Address { get; set; }
        public byte[] Value { get; set; }


    }

    public struct RegionStructure
    {
        public RegionStructure(IntPtr regionBeginning, int regionSize)
        {
            RegionBeginning = regionBeginning;
            RegionSize = regionSize;
        }
        public IntPtr RegionBeginning;
        public int RegionSize;
    }


    public class Scanner
    {

        public Scanner(Process process)
        {
            CurrentProcess = process;
            CaptchaNumbers = new byte[4];
            IndicatorValues = new byte[] { 0x08, 0x01 };
            CaptchaRead = new byte[] { 0x73, 0x72, 0x00, 0x30 };
            CaptchaWrite = new byte[] { 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00 };
            Initialize();
        }


        public Process CurrentProcess { get; set; }
        private List<ScanStructure> Results { get; set; }
        private List<RegionStructure>[] RegionLists { get; set; }
        private SystemInfo CurrentSystem { get; set; }
        private IntPtr TargetHandle { get; set; }

        private byte[] IndicatorValues { get; set; }
        private byte[] CaptchaRead { get; set; }
        private byte[] CaptchaWrite { get; set; }

        public byte[] CaptchaNumbers { get; private set; }
        public IntPtr ReadValuePtr { get; private set; }
        public IntPtr WriteValuePtr { get; private set; }
        public IntPtr WriteCounterPtr { get; private set; }





        public void ExecuteScan()
        {
            CreateEntryPoints();
            SetReadValuePtr();
            SetCaptchaNumber();
            SetWriteValuePtr();
            SetWriteCounterPtr();
            Console.WriteLine(WriteCounterPtr.ToString("X8") + " \n" + BitConverter.ToString(CaptchaNumbers,0));
            Clipboard.SetText(WriteCounterPtr.ToString("X8"));

            IntPtr childHandle;
            childHandle = FindWindowEx(IntPtr.Zero, IntPtr.Zero, null, "Anwesenheitskontrolle");
        }


        public void ExecuteHack()
        {
            if (WriteValuePtr != IntPtr.Zero)
            {
                Utilities.WriteCaptchaNumbers(TargetHandle, WriteValuePtr, Utilities.ConvertToUTF16(CaptchaNumbers));
            }
            if (WriteCounterPtr != IntPtr.Zero)
            {
                Utilities.WriteCaptchaNumbers(TargetHandle, WriteCounterPtr, new byte[] { 0x04 });
            }
            IntPtr test = new IntPtr(0x00250258);
            Point spot = new Point(310, 375);
            Utilities.LeftClick(test, spot);

        }


        private void SetReadValuePtr()
        {
            int offset = -0x04;
            bool found = false;
            byte[] buffer = new byte[CaptchaNumbers.Length];
            Results = new List<ScanStructure>();


            SearchForValuesInMultipleThreads(CaptchaRead);


            foreach (ScanStructure item in Results)
            {
                ReadProcessMemory(TargetHandle, item.Address + offset, buffer, (uint)buffer.Length, out IntPtr notNecessary);
                for (int i = 0; i < buffer.Length; i++)
                {
                    found = buffer[i] >= 0x30 && buffer[i] <= 0x39;
                    if (!found)
                    {
                        break;
                    }
                }

                if (found)
                {
                    ReadValuePtr = item.Address + offset;
                }

            }


            GC.Collect();
        }

        private void SetWriteValuePtr()
        {
            int offset = 0x04;
            int indicatorOffset = 0x9;
            bool found;

            Results = new List<ScanStructure>();
            SearchForValuesInMultipleThreads(CaptchaWrite);
            
            if (Results.Count() != 0)
            {
                foreach (ScanStructure item in Results)
                {
                    byte[] buffer = new byte[2];
                    ReadProcessMemory(TargetHandle, item.Address - indicatorOffset, buffer, (uint)buffer.Length, out _);

                    found = buffer[0] == IndicatorValues[0] && buffer[1] == IndicatorValues[1];

                    if (found)
                    {
                        WriteValuePtr = item.Address + offset;
                        break;
                    }
                }
            }

            GC.Collect();
        }

        private void SetWriteCounterPtr()
        {
            int offset = -0x014;
            if (WriteValuePtr != null && WriteValuePtr != IntPtr.Zero)
            {
                WriteCounterPtr = WriteValuePtr + offset;
            }
        }

        private void SetCaptchaNumber()
        {
            if (ReadValuePtr != null && ReadValuePtr != IntPtr.Zero)
            {
                ReadProcessMemory(TargetHandle, ReadValuePtr, CaptchaNumbers, (uint)CaptchaNumbers.Length, out _);
            }
        }


        private void Initialize()
        {
            //int threadCount = Environment.ProcessorCount / 2;
            int threadCount = 1;

            RegionLists = new List<RegionStructure>[threadCount];
            CurrentSystem = new SystemInfo();
            TargetHandle = OpenProcess(QueryInformation | VirtualMemoryRead | VirtualMemoryWrite | VirtualMemoryOperation, false, CurrentProcess.Id);
        }

        private void CreateEntryPoints()
        {
            long maximum32BitAddress = 0x7fff0000;
            IntPtr minimumAddress = CurrentSystem.MinimumApplicationAddress;
            IntPtr _targetHandle = TargetHandle;


            long helpMinimumAddress = (long)minimumAddress;
            RegionStructure region;
            MEMORY_BASIC_INFORMATION memoryInfo = new MEMORY_BASIC_INFORMATION();
            List<RegionStructure> originalRegionList = new List<RegionStructure>();


            while (helpMinimumAddress < maximum32BitAddress)
            {
                minimumAddress = new IntPtr(helpMinimumAddress);

                //receives basic memory information for a handle specified by OpenProcess (more info : MEMORY_BASIC_INFORMATION struct)
                VirtualQueryEx(_targetHandle, minimumAddress, out memoryInfo, (uint)Marshal.SizeOf(memoryInfo));
                if (memoryInfo.RegionSize < 0) //TODO: prüfen regionsize int oder uint  |  prüfen cast auf long oder int
                {
                    break;
                }

                //checks regions for necessary ProtectionStatus to ReadAndWrite and for the needed MemoryType 
                if (memoryInfo.RegionSize == 0x2AB0000 // only for 1 region (prolly the correct region)
                    && (memoryInfo.Protect == AllocationProtectEnum.PAGE_READWRITE
                    || memoryInfo.Protect == AllocationProtectEnum.PAGE_WRITECOMBINEPLUSREADWRITE
                    && (memoryInfo.Type == TypeEnum.MEM_IMAGE || memoryInfo.Type == TypeEnum.MEM_PRIVATE)
                    ))
                {
                    //adds regions to a List
                    region = new RegionStructure(memoryInfo.BaseAddress, (int)memoryInfo.RegionSize);
                    originalRegionList.Add(region);
                }
                helpMinimumAddress = (uint)memoryInfo.BaseAddress + memoryInfo.RegionSize;
            }
            SplitList(originalRegionList, RegionLists);

        }

        //splits a list into as many lists as the count of processors of the system
        private void SplitList(List<RegionStructure> sourceList, List<RegionStructure>[] destinationList)
        {
            int threadCount = destinationList.Length;

            for (int i = 0; i < RegionLists.Count(); i++)
            {
                destinationList[i] = new List<RegionStructure>();
            }

            for (int i = 0; i < sourceList.Count(); i++)
            {
                destinationList[i % threadCount].Add(sourceList.ElementAt(i));
            }
        }


        private void ByteArrayDigger(List<RegionStructure> list, byte[] arrayToLookFor)
        {
            bool found;
            bool done;
            int length = arrayToLookFor.Length;
            IntPtr targetHandle = TargetHandle;


            foreach (RegionStructure pair in list)
            {
                byte[] buffer = new byte[pair.RegionSize];
                if (ReadProcessMemory(targetHandle, pair.RegionBeginning, buffer, (uint)pair.RegionSize, out IntPtr notNecessary))
                {

                    int bufferSize = buffer.Length - (length - 1);

                    for (int i = 0; i < bufferSize; i++)
                    {
                        found = true;
                        for (int j = 0; j < length; j++)
                        {

                            //show off
                            found = buffer[i + j] == arrayToLookFor[j];

                            if (!found && j != 0)
                            {
                                i += j - 1;
                                break;
                            }
                            else if (!found && j == 0)
                            {
                                i += j;
                                break;
                            }

                        }
                        if (found)
                        {
                            done = false;
                            ScanStructure scan = new ScanStructure(pair.RegionBeginning + i, arrayToLookFor);

                            while (!done)
                            {
                                Monitor.TryEnter(Results, ref done); //waits until no other thread is accessing the list
                                if (done)
                                {
                                    Results.Add(scan);
                                    Monitor.Exit(Results);
                                }
                            }
                        }
                    }
                }
            }
        }


        private void SearchForValuesInMultipleThreads(byte[] arrayToLookFor)
        {
            List<Task> threadList = new List<Task>();


            foreach (List<RegionStructure> list in RegionLists)
            {
                Task arsch = Task.Run(() => ByteArrayDigger(list, arrayToLookFor));
                threadList.Add(arsch);
            }

            foreach (Task thread in threadList)
            {
                thread.Wait();
            }

        }




    }
}

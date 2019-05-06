using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static DLLImports.Kernel32DLL;
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
            Initialize();
            CaptchaRead = new byte[] { 0x73, 0x72, 0x00, 0x30 };
            CaptchaWrite = new byte[] { 0x08, 0x01, 0x00, 0x00, 0x00, 0x30, 0x01, 0xC0, 0x0C, 0x10, /*0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00*/ };

            // 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 05 00 00 00
            //05 00 00 00 D0 BB 85 0D 00 00 00 00 10 B4 90 09
        }


        public Process CurrentProcess { get; set; }
        private List<ScanStructure> Results { get; set; }
        private List<RegionStructure>[] RegionLists { get; set; }
        private SystemInfo CurrentSystem { get; set; }
        private IntPtr TargetHandle { get; set; }


        private byte[] CaptchaRead { get; set; }
        private byte[] CaptchaWrite { get; set; }


        public byte[] CaptchaNumbers { get; private set; }
        public IntPtr ReadValuePtr { get; private set; }
        public IntPtr WriteValuePtr { get; private set; }
        public IntPtr WriteCounterPtr { get; private set; }





        public void Execute()
        {
            SetReadValuePtr();
            SetWriteValuePtr();
            SetWriteCounterPtr();
            SetCaptchaNumber();
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
            int offset = 0x0D;

            Results = new List<ScanStructure>();
            SearchForValuesInMultipleThreads(CaptchaWrite);
            if (Results.Count() == 1)
            {
                WriteValuePtr = Results[0].Address + offset;
            }
            else if (Results.Count() == 0)
            {
                Console.WriteLine("no entries found");
            }
            else
            {
                Console.WriteLine("too many entries found");
            }

            GC.Collect();
        }

        private void SetWriteCounterPtr()
        {
            int offset = -0x07;

            if (WriteValuePtr != null && WriteValuePtr != IntPtr.Zero)
            {
                WriteCounterPtr = WriteValuePtr - offset;
            }

        }

        private void SetCaptchaNumber()
        {
            if (ReadValuePtr != null && ReadValuePtr != IntPtr.Zero)
            {
                ReadProcessMemory(TargetHandle, ReadValuePtr, CaptchaNumbers, (uint)CaptchaNumbers.Length, out IntPtr notNecessary);
                Console.WriteLine("MemoryScanner Result = " + BitConverter.ToString(CaptchaNumbers, 0));
            }
            else
            {
                Console.WriteLine("no value found");
            }
        }

        public void Test()
        {
            IntPtr arsch = IntPtr.Zero;
            SearchForValuesInMultipleThreads(CaptchaRead);
            foreach (ScanStructure item in Results)
            {
                Console.WriteLine(item.Address.ToString("X8"));
                CaptchaNumbers = new byte[4];
                ReadProcessMemory(TargetHandle, item.Address - 0x04, CaptchaNumbers, 4, out arsch);
                Console.WriteLine(BitConverter.ToString(CaptchaNumbers, 0));
            }

            ReadValuePtr = Results[0].Address - 0x04;

            GC.Collect();


            Initialize();
            SearchForValuesInMultipleThreads(CaptchaWrite);
            if (Results.Count() != 0)
            {
                foreach (ScanStructure item in Results)
                {
                    Console.WriteLine(Results[0].Address.ToString("X8"));
                    CaptchaNumbers = new byte[CaptchaWrite.Length];
                    ReadProcessMemory(TargetHandle, item.Address, CaptchaNumbers, (uint)CaptchaWrite.Length, out arsch);
                    Console.WriteLine(BitConverter.ToString(CaptchaNumbers, 0));
                }

                WriteValuePtr = Results[0].Address + 0x0D;
            }



            GC.Collect();

            byte[] value = new byte[4];
            byte[] writeValue = new byte[8];
            ReadProcessMemory(TargetHandle, ReadValuePtr, value, 4, out arsch);
            for (int i = 0; i < value.Length; i++)
            {
                writeValue[i * 2] = value[i];
            }

            WriteProcessMemory(TargetHandle, WriteValuePtr, writeValue, 8, out arsch);
            Thread.Sleep(500);
            WriteProcessMemory(TargetHandle, WriteValuePtr - 0x07, new byte[] { 4 }, 1, out arsch);

        }


        private void Initialize()
        {
            int threadCount = Environment.ProcessorCount / 2;

            RegionLists = new List<RegionStructure>[threadCount];
            CurrentSystem = new SystemInfo();
            TargetHandle = OpenProcess(QueryInformation | VirtualMemoryRead | VirtualMemoryWrite | VirtualMemoryOperation, false, CurrentProcess.Id);
            CreateEntryPoints();
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
                if (memoryInfo.Protect == AllocationProtectEnum.PAGE_READWRITE
                    || memoryInfo.Protect == AllocationProtectEnum.PAGE_WRITECOMBINEPLUSREADWRITE
                    && (memoryInfo.Type == TypeEnum.MEM_IMAGE || memoryInfo.Type == TypeEnum.MEM_PRIVATE))
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

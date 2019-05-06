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
            Initialize();
            CaptchaRead = new byte[] { 0x73, 0x72, 0x00, 0x30 };
            CaptchaWrite = new byte[] { 0x08, 0x01, 0x00, 0x00, 0x00, 0x30, 0x01, 0x60, 0x0C, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        }


        public Process CurrentProcess { get; private set; }
        public byte[] CaptchaNumbers { get; set; }

        public List<ScanStructure> Results { get; private set; }
        private List<RegionStructure>[] RegionLists { get; set; }
        private SystemInfo CurrentSystem { get; set; }
        private IntPtr TargetHandle { get; set; }




        private byte[] CaptchaRead { get; set; }
        private byte[] CaptchaWrite { get; set; }


        public void Test()
        {
            IntPtr arsch = IntPtr.Zero;
            SearchForValuesInMultipleThreads(CaptchaRead);
            Console.WriteLine(Results[0].Address.ToString("X8"));
            CaptchaNumbers = new byte[4];
            ReadProcessMemory(TargetHandle, Results[0].Address + 0x04, CaptchaNumbers, 4, out arsch);
            Console.WriteLine(BitConverter.ToString(CaptchaNumbers, 0));
            GC.Collect();
        }


        private void Initialize()
        {
            int threadCount = Environment.ProcessorCount;

            Results = new List<ScanStructure>();
            RegionLists = new List<RegionStructure>[threadCount/2];
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
                    for (int i = 0; i < buffer.Length - (length - 1); i++)
                    {
                        found = true;
                        for (int j = 0; j < length; j++)
                        {

                            if (buffer[i + j] != arrayToLookFor[j])
                            {
                                found = false;
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

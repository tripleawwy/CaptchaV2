﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace CaptchaV2
{
    class Program
    {
        [STAThreadAttribute]
        static void Main()
        {
            Scanner scanner = new Scanner(Process.GetProcessesByName("CCLauncher_Client")[0]);
            scanner.Run();

            Console.ReadLine();




        }
    }
}

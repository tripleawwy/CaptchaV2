using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace CaptchaV2
{
    class Program
    {
        static void Main()
        {
            Scanner scanner = new Scanner(Process.GetProcessById(260));
            scanner.Test();

            Console.ReadLine();
        }
    }
}

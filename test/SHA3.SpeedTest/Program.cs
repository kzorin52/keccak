using System;
using System.Diagnostics;

namespace Temnij.Security.Cryptography.SpeedTest;

internal class Program
{
    private static void Main()
    {
        var data = new byte[1024 * 1024 * 10];
        var rand = new Random();

        var max = 0d;

        for (var i = -1; i < 50; i++)
        {
            using var sha3 = new SHA3256Managed();
            sha3.UseKeccakPadding = true;

            sha3.ComputeHash("Hello"u8.ToArray());
            rand.NextBytes(data);

            var begin = Stopwatch.StartNew();

            sha3.ComputeHash(data);

            begin.Stop();
            var time = begin.Elapsed;

            if (i >= 0) // ignore first run
            {
                var mbs = data.Length / (1024d * 1024d) / time.TotalSeconds;
                if (mbs > max)
                    max = mbs;
                Console.WriteLine("{0}mb in {1} on {2}, {3}mb/sec", data.Length / (1024 * 1024), time.TotalSeconds,
                    IntPtr.Size == 4 ? "x86" : "amd64", mbs);
            }
        }

        Console.WriteLine($"Max: {max} mb/s");
    }
}
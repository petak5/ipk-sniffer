using System;
using SharpPcap;

namespace ipk_sniffer
{
    class Program
    {
        static int Main(string[] args)
        {
            var arguments = new ArgumentsParser(args);
            
            // List interfaces
            if (arguments.doListInterfaces)
            {
                foreach (var dev in CaptureDeviceList.Instance)
                    Console.WriteLine(dev.Name);

                return 0;
            }

            Console.WriteLine(arguments.interf);
            Console.WriteLine($"Do list interfaces: {arguments.doListInterfaces}");
            Console.WriteLine($"Port: {arguments.port}");
            
            Console.WriteLine($"Show all protocols: {arguments.showAllProtocols}");
            Console.WriteLine($"    TCP:  {arguments.useTCP}");
            Console.WriteLine($"    UDP:  {arguments.useUDP}");
            Console.WriteLine($"    ARP:  {arguments.useARP}");
            Console.WriteLine($"    ICMP: {arguments.useICMP}");
            
            Console.WriteLine($"Number of packets: {arguments.numberOfPackets}");

            return 0;
        }
    }
}

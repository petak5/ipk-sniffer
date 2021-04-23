using System;

namespace ipk_sniffer
{
    class Program
    {
        static void Main(string[] args)
        {
            var arguments = new ArgumentsParser(args);

            Console.WriteLine(arguments.interf);
            Console.WriteLine($"Do list interfaces: {arguments.doListInterfaces}");
            Console.WriteLine($"Port: {arguments.port}");
            
            Console.WriteLine($"Show all protocols: {arguments.showAllProtocols}");
            Console.WriteLine($"    TCP:  {arguments.useTCP}");
            Console.WriteLine($"    UDP:  {arguments.useUDP}");
            Console.WriteLine($"    ARP:  {arguments.useARP}");
            Console.WriteLine($"    ICMP: {arguments.useICMP}");
            
            Console.WriteLine($"Number of packets: {arguments.numberOfPackets}");
        }
    }
}

// ./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}
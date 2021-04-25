using System;
using System.Linq;
using System.Text;
using SharpPcap;

namespace ipk_sniffer
{
    class Program
    {
        private static ArgumentsParser arguments;
        private static int packetsCount = 0;
        static int Main(string[] args)
        {
            arguments = new ArgumentsParser(args);

            var devices = CaptureDeviceList.Instance;

            // List interfaces
            if (arguments.doListInterfaces)
            {
                foreach (var dev in devices)
                    Console.WriteLine(dev.Name);

                return 0;
            }

            // Requested interface is not available
            if (devices.All(d => d.Name != arguments.interf))
                Tools.ExitWithMessage($"Interface '{arguments.interf}' is not available.", 1);

            var device = devices.First(d => d.Name == arguments.interf);
            device.Open(DeviceMode.Normal, 1000);
            device.OnPacketArrival += Device_OnPacketArrival;
            //tcpdump filter to capture only TCP/IP packets
            string filter = "ip and tcp";
            device.Filter = filter;
            device.StartCapture();

            Console.WriteLine($"Interface: {arguments.interf}");
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
        
        private static void Device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            packetsCount++;
            if (packetsCount > arguments.numberOfPackets)
                Environment.Exit(0);

            var time = Tools.DateTimeToString(e.Packet.Timeval.Date.ToLocalTime());
            var len = e.Packet.Data.Length;

            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);

            var tcpPacket = packet.Extract<PacketDotNet.TcpPacket>();
            if (tcpPacket != null)
            {
                var ipPacket = (PacketDotNet.IPPacket)tcpPacket.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                int srcPort = tcpPacket.SourcePort;
                int dstPort = tcpPacket.DestinationPort;
                byte[] payload = e.Packet.Data;

                Console.WriteLine($"{time} {srcIp} : {srcPort} > {dstIp} : {dstPort}, length {len} bytes");
                
                PrettyPrint(payload);
            }
        }

        /// <summary>
        /// Pretty print contents of data
        /// </summary>
        private static void PrettyPrint(byte[] data)
        {
            var sbHexa = new StringBuilder();
            var sbAscii = new StringBuilder();

            for (var i = 0; i < data.Length; i++)
            {
                var c = Convert.ToChar(data[i]);
                
                sbHexa.Append($"{(int)c:X2} ");
                
                if (c >= 32 && c <= 126)
                {
                    sbAscii.Append(c);
                }
                else
                {
                    sbAscii.Append('.');
                }

                // Print out every 16 iterations (at the end of 16. iteration when all the necessary data is collected)
                if (i % 16 == 15)
                {
                    Console.WriteLine($"0x{i + 1:X4}:  {sbHexa.ToString()} {sbAscii.ToString()}");
                    sbHexa.Clear();
                    sbAscii.Clear();
                }

                // Last iteration, print what is left
                if (i + 1 == data.Length)
                {
                    Console.WriteLine($"0x{i + 16 - i % 16:X4}:  {sbHexa.ToString()} {sbAscii.ToString()}");
                }
            }
        }

    }
}

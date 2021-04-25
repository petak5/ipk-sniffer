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
            
            // Create filter string
            string filter = string.Empty;
            if (arguments.useTCP)
            {
                filter += "(ip and tcp)";
            }
            if (arguments.useUDP)
            {
                if (filter != string.Empty)
                    filter += " or ";
                filter += "(ip and udp)";
            }
            if (arguments.useARP)
            {
                if (filter != string.Empty)
                    filter += " or ";
                filter += "arp";
            }
            if (arguments.useICMP)
            {
                if (filter != string.Empty)
                    filter += " or ";
                filter += "icmp";
            }

            device.Filter = filter;
            device.StartCapture();

            return 0;
        }
        
        private static void Device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var time = Tools.DateTimeToString(e.Packet.Timeval.Date.ToLocalTime());
            var len = e.Packet.Data.Length;

            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);

            // TCP
            var tcpPacket = packet.Extract<PacketDotNet.TcpPacket>();
            if (tcpPacket != null)
            {
                var ipPacket = (PacketDotNet.IPPacket)tcpPacket.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                int srcPort = tcpPacket.SourcePort;
                int dstPort = tcpPacket.DestinationPort;
                byte[] payload = e.Packet.Data;

                // If port was specified
                if (arguments.port != -1)
                {
                    // If source and destination port doesn't match the specified port, ignore this packet
                    if (srcPort != arguments.port && dstPort != arguments.port)
                        return;
                }

                Console.WriteLine($"{time} {srcIp} : {srcPort} > {dstIp} : {dstPort}, length {len} bytes");

                PrettyPrint(payload);
            }

            // UDP
            var udpPacket = packet.Extract<PacketDotNet.UdpPacket>();
            if (udpPacket != null)
            {
                var ipPacket = (PacketDotNet.IPPacket)udpPacket.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                int srcPort = udpPacket.SourcePort;
                int dstPort = udpPacket.DestinationPort;
                byte[] payload = e.Packet.Data;

                // If port was specified
                if (arguments.port != -1)
                {
                    // If source and destination port doesn't match the specified port, ignore this packet
                    if (srcPort != arguments.port && dstPort != arguments.port)
                        return;
                }

                Console.WriteLine($"{time} {srcIp} : {srcPort} > {dstIp} : {dstPort}, length {len} bytes");

                PrettyPrint(payload);
            }
            
            // ARP
            var icmpPacket = packet.Extract<PacketDotNet.ArpPacket>();
            if (icmpPacket != null)
            {
                var ipPacket = (PacketDotNet.IPPacket)icmpPacket.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                byte[] payload = e.Packet.Data;

                Console.WriteLine($"{time} {srcIp} > {dstIp}, length {len} bytes");

                PrettyPrint(payload);
            }
            
            var icmpv4Packet = packet.Extract<PacketDotNet.IcmpV4Packet>();
            var icmpv6Packet = packet.Extract<PacketDotNet.IcmpV4Packet>();
            // ICMPv4
            if (icmpv4Packet != null)
            {
                var ipPacket = (PacketDotNet.IPPacket)icmpv4Packet.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                byte[] payload = e.Packet.Data;

                Console.WriteLine($"{time} {srcIp} > {dstIp}, length {len} bytes");

                PrettyPrint(payload);
            }
            // ICMPv6
            else if (icmpv6Packet != null)
            {
                var ipPacket = (PacketDotNet.IPPacket)icmpv6Packet.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                byte[] payload = e.Packet.Data;

                Console.WriteLine($"{time} {srcIp} > {dstIp}, length {len} bytes");

                PrettyPrint(payload);
            }

            packetsCount++;
            // If required amount of packets was captured, exit the program
            if (packetsCount >= arguments.numberOfPackets)
                Environment.Exit(0);
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
                
                sbHexa.Append($"{(int)c:x2} ");
                
                // ASCII characters with value from 32 to 126 are printable
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
                    Console.WriteLine($"0x{i - 16 + 1:x4}:  {sbHexa.ToString()} {sbAscii.ToString()}");
                    sbHexa.Clear();
                    sbAscii.Clear();
                }
                // Last iteration, print what is left
                else if (i + 1 == data.Length)
                {
                    Console.WriteLine($"0x{i - i % 16:x4}:  {sbHexa.ToString()} {sbAscii.ToString()}");
                }
            }
        }

    }
}

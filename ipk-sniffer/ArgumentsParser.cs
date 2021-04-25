using System;

// ./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}

namespace ipk_sniffer
{
    public class ArgumentsParser
    {
        // Show all protocols either when none was explicitly set to enabled or when all protocols were set to enabled
        public bool showAllProtocols => useTCP == useUDP == useARP == useICMP;
        
        public bool doListInterfaces = false;
        
        public string interf = null;
        public int port = -1;
        public bool useTCP = false;
        public bool useUDP = false;
        public bool useARP = false;
        public bool useICMP = false;
        public int numberOfPackets = -1;

        /// <summary>
        /// Create object and populate its attributes with parsed data
        /// </summary>
        /// <param name="args">Arguments to parse</param>
        public ArgumentsParser(string[] args)
        {
            Parse(args);
        }

        private void Parse(string[] args)
        {
            // No arguments => list interfaces
            if (args.Length == 0)
            {
                doListInterfaces = true;
                return;
            }

            if (args.Length == 1)
            {
                if (args[0] == "-i" || args[0] == "--interface")
                {
                    doListInterfaces = true;
                    return;
                }
                
                if (args[0] == "-h" || args[0] == "--help")
                    Tools.ExitWithMessage("Usage: ./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}", 0);

                Tools.ExitWithMessage("Invalid arguments.", 1);
            }

            for (var i = 0; i < args.Length; i++)
            {
                var arg = args[i];

                switch (arg)
                {
                    case "-i":
                    case "--interface":
                        if (interf != null || doListInterfaces)
                            Tools.ExitWithMessage("Invalid arguments: interface set more than once", 1);
                        // Last argument
                        if (i + 1 == args.Length)
                            Tools.ExitWithMessage("Invalid arguments: no interface provided.", 1);

                        i++;
                        interf = args[i];
                        break;
                    
                    case "-p":
                        if (port != -1)
                            Tools.ExitWithMessage("Invalid arguments: port set more than once", 1);
                        // Last argument
                        if (i + 1 == args.Length)
                            Tools.ExitWithMessage("Invalid arguments: no port provided.", 1);
                        
                        // Try parse
                        try
                        {
                            int result = Int32.Parse(args[i + 1]);
                            if (result < 0)
                                Tools.ExitWithMessage($"Invalid arguments: '{result}' is not a valid port number", 1);
                            
                            port = result;
                        }
                        catch (FormatException)
                        {
                            Tools.ExitWithMessage($"Invalid arguments: '{args[i + 1]}' can not be converted to integer", 1);
                        }

                        i++;
                        break;
                    
                    case "-t":
                    case "--tcp":
                        if (useTCP)
                            Tools.ExitWithMessage("Invalid arguments: use TCP already set", 1);
                        useTCP = true;
                        break;
                    
                    case "-u":
                    case "--udp":
                        if (useUDP)
                            Tools.ExitWithMessage("Invalid arguments: use UDP already set", 1);
                        useUDP = true;
                        break;
                    
                    case "--arp":
                        if (useARP)
                            Tools.ExitWithMessage("Invalid arguments: use ARP already set", 1);
                        useARP = true;
                        break;
                    
                    case "--icmp":
                        if (useICMP)
                            Tools.ExitWithMessage("Invalid arguments: use ICMP already set", 1);
                        useICMP = true;
                        break;
                    
                    case "-n":
                        if (numberOfPackets != -1)
                            Tools.ExitWithMessage("Invalid arguments: number of packets to capture set more than once", 1);
                        // Last argument
                        if (i + 1 == args.Length)
                            Tools.ExitWithMessage("Invalid arguments: number of packets to capture not provided.", 1);
                        
                        // Try parse
                        try
                        {
                            int result = Int32.Parse(args[i + 1]);
                            if (result < 1)
                                Tools.ExitWithMessage($"Invalid arguments: can not capture '{result}' packets, minimum number can be 1", 1);
                            
                            numberOfPackets = result;
                        }
                        catch (FormatException)
                        {
                            Tools.ExitWithMessage($"Invalid arguments: '{args[i + 1]}' can not be converted to integer", 1);
                        }

                        i++;
                        break;

                    default:
                        Tools.ExitWithMessage($"Invalid argument '{arg}'.", 1);
                        break;
                }
            }

            // Set to default value if not set
            if (numberOfPackets == -1)
                numberOfPackets = 1;
        }
    }
}

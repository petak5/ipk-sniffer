namespace ipk_sniffer
{
    public static class Tools
    {
        public static void ExitWithMessage(string message, int exitCode)
        {
            System.Console.WriteLine(message);
            System.Environment.Exit(exitCode);
        }
    }
}

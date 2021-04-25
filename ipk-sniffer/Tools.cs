namespace ipk_sniffer
{
    public static class Tools
    {
        public static void ExitWithMessage(string message, int exitCode)
        {
            System.Console.WriteLine(message);
            System.Environment.Exit(exitCode);
        }
        
        /// <summary>
        /// Convert DateTime to string representation of RFC3339 format
        /// </summary>
        /// <see cref="https://sebnilsson.com/blog/c-datetime-to-rfc3339-iso-8601/"/>
        public static string DateTimeToString(System.DateTime dt)
        {
            return dt.ToString("yyyy-MM-dd'T'HH:mm:ss.fffzzz", System.Globalization.DateTimeFormatInfo.InvariantInfo);
        }
    }
}

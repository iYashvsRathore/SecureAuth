namespace SecureAuthPOC.API.Middleware
{
    public class RateLimitingOptions
    {
        public int RequestsPerMinute { get; set; } = 5;
        public int BurstLimit { get; set; } = 10;
        public int BlockDurationMinutes { get; set; } = 15;
        public bool Enabled { get; set; } = true;
        public string[] ExcludePaths { get; set; } = Array.Empty<string>();
    }
}

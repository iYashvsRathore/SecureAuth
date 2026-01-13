namespace SecureAuthPOC.API.Models
{
    public class RateLimitRecord
    {
        public string Key { get; set; } // IP + endpoint
        public int Tokens { get; set; } = 5;
        public DateTime LastRefill { get; set; } = DateTime.UtcNow;
    }
}

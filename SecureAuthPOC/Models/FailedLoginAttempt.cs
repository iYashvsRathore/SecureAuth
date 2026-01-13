namespace SecureAuthPOC.API.Models
{
    public class FailedLoginAttempt
    {
        public string Key { get; set; } // Email + IP combination
        public int Attempts { get; set; }
        public DateTime FirstAttempt { get; set; }
        public DateTime LastAttempt { get; set; }
        public bool IsBlocked { get; set; }
        public DateTime BlockedUntil { get; set; }
    }
}

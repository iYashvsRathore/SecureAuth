using System.ComponentModel.DataAnnotations;

namespace SecureAuthPOC.API.Models
{
    public class User
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();

        [Required]
        [EmailAddress]
        [MaxLength(255)]
        public required string Email { get; set; }

        [Required]
        [MaxLength(255)]
        public required string Username { get; set; }

        [Required]
        public required string PasswordHash { get; set; }

        [Required]
        public required string Salt { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? LastLoginAt { get; set; }
        public int FailedLoginAttempts { get; set; } = 0;
        public bool IsLocked { get; set; } = false;
        public DateTime? LockedUntil { get; set; }
        public string LastLoginIp { get; set; }
        public string LastLoginUserAgent { get; set; }
        public bool TwoFactorEnabled { get; set; } = false;
        public string TwoFactorSecret { get; set; }

        // GDPR/CCPA Compliance Fields
        public bool ConsentGiven { get; set; } = false;
        public DateTime? ConsentDate { get; set; }
        public string ConsentVersion { get; set; }
        public bool MarketingOptIn { get; set; } = false;
    }
}

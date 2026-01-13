using System.ComponentModel.DataAnnotations;

namespace SecureAuthPOC.API.Models
{
    public class AuthRequest
    {
        [Required]
        [EmailAddress]
        public required string Email { get; set; }

        [Required]
        [StringLength(100, MinimumLength = 12,
            ErrorMessage = "Password must be at least 12 characters")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$",
            ErrorMessage = "Password must contain uppercase, lowercase, number, and special character")]
        public required string Password { get; set; }

        public string TwoFactorCode { get; set; }
        public string ClientIp { get; set; }
        public string UserAgent { get; set; }
    }
}

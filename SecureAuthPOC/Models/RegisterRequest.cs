using System.ComponentModel.DataAnnotations;

namespace SecureAuthPOC.API.Models
{
    public class RegisterRequest : AuthRequest
    {
        [Required]
        [StringLength(50, MinimumLength = 3)]
        public required string Username { get; set; }

        [Required]
        [Compare("Password", ErrorMessage = "Passwords do not match")]
        public required string ConfirmPassword { get; set; }

        [Required]
        [Range(typeof(bool), "true", "true",
            ErrorMessage = "You must accept the terms and conditions")]
        public bool AcceptTerms { get; set; }

        public bool MarketingOptIn { get; set; } = false;
    }
}

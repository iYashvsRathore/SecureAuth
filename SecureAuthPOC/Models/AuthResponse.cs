namespace SecureAuthPOC.API.Models
{
    public class AuthResponse
    {
        public bool Success { get; set; }
        public string Token { get; set; }
        public string RefreshToken { get; set; }
        public DateTime TokenExpiry { get; set; }
        public DateTime RefreshTokenExpiry { get; set; }
        public string UserId { get; set; }
        public string Email { get; set; }
        public bool RequiresTwoFactor { get; set; }
        public string Message { get; set; }
    }
}

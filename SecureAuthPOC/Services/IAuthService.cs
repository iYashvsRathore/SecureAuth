using SecureAuthPOC.API.Models;

namespace SecureAuthPOC.API.Services
{
    public interface IAuthService
    {
        Task<AuthResponse> RegisterAsync(RegisterRequest request);
        Task<AuthResponse> LoginAsync(AuthRequest request);
        AuthResponse RefreshTokenAsync(RefreshTokenRequest refreshTokenRequest);
        bool LogoutAsync(string userId, string refreshToken);
        bool ValidateTwoFactorAsync(string userId, string code);
        void RecordFailedAttempt(string key);
        void ResetFailedAttempts(string key);
        Task LogAuditEventAsync(AuditLog log);
    }
}

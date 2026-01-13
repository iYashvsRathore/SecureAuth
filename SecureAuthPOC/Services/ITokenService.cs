using SecureAuthPOC.API.Models;
using System.Security.Claims;

namespace SecureAuthPOC.API.Services
{
    public interface ITokenService
    {
        string GenerateAccessToken(User user);
        string GenerateRefreshToken();
        ClaimsPrincipal ValidateToken(string token);
        bool ValidateRefreshToken(string refreshToken, string userId);
        bool RevokeRefreshToken(string userId, string refreshToken);
    }
}

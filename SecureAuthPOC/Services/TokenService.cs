using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SecureAuthPOC.API.Data;
using SecureAuthPOC.API.Middleware;
using SecureAuthPOC.API.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SecureAuthPOC.API.Services
{
    public class TokenService : ITokenService
    {
        //private readonly string _secretKey;
        //private readonly string _issuer;
        //private readonly string _audience;
        //private readonly int _accessTokenExpiryMinutes;
        private readonly JWTOptions _options;
        private readonly InMemoryDbContext _dbContext;

        public TokenService(IOptions<JWTOptions> options, InMemoryDbContext dbContext)
        {
            //_secretKey = configuration["Jwt:SecretKey"]
            //    ?? throw new ArgumentNullException("Jwt:SecretKey");
            //_issuer = configuration["Jwt:Issuer"] ?? "SecureAuthPOC";
            //_audience = configuration["Jwt:Audience"] ?? "SecureAuthPOC-Client";
            //_accessTokenExpiryMinutes = int.Parse(configuration["Jwt:AccessTokenExpiryMinutes"] ?? "15");
            _options = options.Value;
            _dbContext = dbContext;
        }

        /// <summary>
        /// Generate JWT Access Token
        /// </summary>
        /// <param name="user">User for which the JWT access token needs to be generated</param>
        public string GenerateAccessToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_options.SecretKey);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("username", user.Username),
                new Claim("created_at", user.CreatedAt.ToString("o")),
                new Claim("two_factor_enabled", user.TwoFactorEnabled.ToString()),
                new Claim("consent_given", user.ConsentGiven.ToString())
            };

            // Add custom claims based on user properties

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(_options.AccessTokenExpiryMinutes),
                Issuer = _options.Issuer,
                Audience = _options.Audience,
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        /// <summary>
        /// Generate Refresh Token
        /// </summary>
        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        /// <summary>
        /// Validate JWT Token
        /// </summary>
        /// <param name="token">Token to validate</param>
        public ClaimsPrincipal ValidateToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_options.SecretKey);

            try
            {
                var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidIssuer = _options.Issuer,
                    ValidateAudience = true,
                    ValidAudience = _options.Audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero // No tolerance for expired tokens
                }, out SecurityToken validatedToken);

                return principal;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Validate Refresh Token
        /// </summary>
        /// <param name="refreshToken">Refresh token to validate</param>
        /// <param name="userId">User's unique identifier</param>
        public bool ValidateRefreshToken(string refreshToken, string userId)
        {
            _dbContext.RefreshTokens.TryGetValue(refreshToken, out var storedToken);

            if (storedToken == null || storedToken.IsRevoked || storedToken.Expiry < DateTime.UtcNow)
            {
                return false;
            }

            if (storedToken.UserId != userId)
            {
                return false;
            }

            return refreshToken.Length == 88;
        }

        public bool RevokeRefreshToken(string userId, string refreshToken)
        {
            // Revoke the refresh token
            if (!string.IsNullOrEmpty(refreshToken) &&
                _dbContext.RefreshTokens.TryGetValue(refreshToken, out var token))
            {
                token.IsRevoked = true;
            }

            // Clear user's refresh tokens
            var userTokens = _dbContext.RefreshTokens
                .Where(t => t.Value.UserId == userId && !t.Value.IsRevoked)
                .ToList();

            foreach (var tokenEntry in userTokens)
            {
                tokenEntry.Value.IsRevoked = true;
            }

            return true;
        }
    }
}

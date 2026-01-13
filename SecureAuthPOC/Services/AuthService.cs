using Microsoft.IdentityModel.Tokens;
using SecureAuthPOC.API.Data;
using SecureAuthPOC.API.Enums;
using SecureAuthPOC.API.Exceptions;
using SecureAuthPOC.API.Models;

namespace SecureAuthPOC.API.Services
{
    public class AuthService : IAuthService
    {
        private readonly InMemoryDbContext _dbContext;
        private readonly ITokenService _tokenService;
        private readonly IPasswordService _passwordService;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly int _refreshTokenExpiryMinutes;

        public AuthService(
            IConfiguration configuration,
            InMemoryDbContext dbContext,
            ITokenService tokenService,
            IPasswordService passwordService,
            IHttpContextAccessor httpContextAccessor)
        {
            _dbContext = dbContext;
            _tokenService = tokenService;
            _passwordService = passwordService;
            _httpContextAccessor = httpContextAccessor;
            _refreshTokenExpiryMinutes = int.Parse(configuration["Jwt:RefreshTokenExpiryDays"] ?? "7");
        }

        public async Task<AuthResponse> RegisterAsync(RegisterRequest request)
        {
            // Check if user already exists
            if (_dbContext.Users.Values.Any(u => u.Email == request.Email))
            {
                throw new InvalidInputException(ErrorCode.FIELD_INVALID, "Email already registered");
            }

            if (_dbContext.Users.Values.Any(u => u.Username == request.Username))
            {
                throw new InvalidInputException(ErrorCode.FIELD_INVALID, "Username already taken");
            }

            // Validate password strength
            var passwordScore = _passwordService.GetPasswordStrengthScore(request.Password);
            if (passwordScore < 5) // Minimum score threshold
            {
                throw new InvalidInputException(ErrorCode.FIELD_INVALID, "Password is too weak");
            }

            // Hash password
            var passwordHash = _passwordService.HashPassword(request.Password, out var salt);

            // Create user
            var user = new User
            {
                Email = request.Email.ToLower().Trim(),
                Username = request.Username.Trim(),
                PasswordHash = passwordHash,
                TwoFactorSecret = request.TwoFactorCode,
                TwoFactorEnabled = string.IsNullOrEmpty(request.TwoFactorCode) ? false : true,
                Salt = salt,
                ConsentGiven = request.AcceptTerms,
                ConsentDate = DateTime.UtcNow,
                ConsentVersion = "1.0",
                MarketingOptIn = request.MarketingOptIn
            };

            _dbContext.Users[user.Id] = user;

            // Generate tokens
            var token = _tokenService.GenerateAccessToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken();

            // Store refresh token
            _dbContext.RefreshTokens[refreshToken] = new RefreshToken
            {
                Token = refreshToken,
                UserId = user.Id.ToString(),
                Expiry = DateTime.UtcNow.AddDays(_refreshTokenExpiryMinutes)
            };

            return new AuthResponse
            {
                Success = true,
                Token = token,
                RefreshToken = refreshToken,
                TokenExpiry = DateTime.UtcNow.AddMinutes(15),
                RefreshTokenExpiry = DateTime.UtcNow.AddDays(7),
                UserId = user.Id.ToString(),
                Email = user.Email,
                Message = "Registration successful"
            };
        }

        public async Task<AuthResponse> LoginAsync(AuthRequest request)
        {
            // Check for failed attempts
            var failedAttemptKey = $"{request.Email}:{_httpContextAccessor.HttpContext?.Connection.RemoteIpAddress}";
            if (_dbContext.FailedAttempts.TryGetValue(failedAttemptKey, out var failedAttempt))
            {
                if (failedAttempt.IsBlocked && failedAttempt.BlockedUntil > DateTime.UtcNow)
                {
                    throw new ResouceLockedException("Account temporarily locked");
                }

                if (failedAttempt.Attempts >= 5)
                {
                    failedAttempt.IsBlocked = true;
                    failedAttempt.BlockedUntil = DateTime.UtcNow.AddMinutes(15);
                    throw new ResouceLockedException("Account locked due to too many failed attempts");
                }
            }

            // Find user
            var user = _dbContext.Users.Values.FirstOrDefault(u =>
                u.Email == request.Email.ToLower().Trim());

            if (user == null)
            {
                RecordFailedAttempt(failedAttemptKey);
                await LogFailedLogin(request.Email, "User not found");
                throw new UnauthorizedException("Invalid credentials");

            }

            // Check if account is locked
            if (user.IsLocked && user.LockedUntil.HasValue && user.LockedUntil > DateTime.UtcNow)
            {
                throw new ResouceLockedException("Account is locked");
            }

            // Verify password
            if (!_passwordService.VerifyPassword(request.Password, user.PasswordHash, user.Salt))
            {
                user.FailedLoginAttempts++;

                // Lock account after 5 failed attempts
                if (user.FailedLoginAttempts >= 5)
                {
                    user.IsLocked = true;
                    user.LockedUntil = DateTime.UtcNow.AddMinutes(15);
                }

                RecordFailedAttempt(failedAttemptKey);
                await LogFailedLogin(request.Email, "Invalid password");
                throw new UnauthorizedException("Invalid credentials");
            }

            // Check if 2FA is required
            if (user.TwoFactorEnabled && string.IsNullOrEmpty(request.TwoFactorCode))
            {
                return new AuthResponse
                {
                    Success = false,
                    RequiresTwoFactor = true,
                    Message = "Two-factor authentication required"
                };
            }

            // Validate 2FA code if provided
            if (user.TwoFactorEnabled && !string.IsNullOrEmpty(request.TwoFactorCode))
            {
                if (!ValidateTwoFactorAsync(user.Id.ToString(), request.TwoFactorCode))
                {
                    RecordFailedAttempt(failedAttemptKey);
                    await LogFailedLogin(request.Email, "Invalid 2FA code");
                    throw new UnauthorizedException("Invalid 2FA code" );
                }
            }

            // Reset failed attempts on successful login
            user.FailedLoginAttempts = 0;
            user.IsLocked = false;
            user.LockedUntil = null;
            user.LastLoginAt = DateTime.UtcNow;
            user.LastLoginIp = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString();
            user.LastLoginUserAgent = _httpContextAccessor.HttpContext?.Request.Headers["User-Agent"];

            ResetFailedAttempts(failedAttemptKey);

            // Generate tokens
            var token = _tokenService.GenerateAccessToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken();

            // Store refresh token
            _dbContext.RefreshTokens[refreshToken] = new RefreshToken
            {
                Token = refreshToken,
                UserId = user.Id.ToString(),
                Expiry = DateTime.UtcNow.AddDays(7)
            };

            return new AuthResponse
            {
                Success = true,
                Token = token,
                RefreshToken = refreshToken,
                TokenExpiry = DateTime.UtcNow.AddMinutes(15),
                RefreshTokenExpiry = DateTime.UtcNow.AddDays(7),
                UserId = user.Id.ToString(),
                Email = user.Email,
                Message = "Login successful"
            };
        }

        public AuthResponse RefreshTokenAsync(RefreshTokenRequest refreshTokenRequest)
        {
           // Find refresh token
            if (_dbContext.RefreshTokens.TryGetValue(refreshTokenRequest.RefreshToken, out var storedToken))
            {
                if (storedToken.IsRevoked || storedToken.Expiry < DateTime.UtcNow)
                {
                    return new AuthResponse { Success = false, Message = "Invalid or expired refresh token" };
                }

                // Get user
                var userId = Guid.Parse(storedToken.UserId);
                if (_dbContext.Users.TryGetValue(userId, out var user))
                {
                    if (string.IsNullOrEmpty(storedToken.UserId) || !_tokenService.ValidateRefreshToken(refreshTokenRequest.RefreshToken, storedToken.UserId))
                    {
                        throw new UnauthorizedException("Invalid refresh token");
                    }
                    // Generate new tokens
                    var newAccessToken = _tokenService.GenerateAccessToken(user);
                    var newRefreshToken = _tokenService.GenerateRefreshToken();

                    // Revoke old refresh token
                    storedToken.IsRevoked = true;

                    // Store new refresh token
                    _dbContext.RefreshTokens[newRefreshToken] = new RefreshToken
                    {
                        Token = newRefreshToken,
                        UserId = user.Id.ToString(),
                        Expiry = DateTime.UtcNow.AddDays(7)
                    };

                    return new AuthResponse
                    {
                        Success = true,
                        Token = newAccessToken,
                        RefreshToken = newRefreshToken,
                        TokenExpiry = DateTime.UtcNow.AddMinutes(15),
                        RefreshTokenExpiry = DateTime.UtcNow.AddDays(7),
                        UserId = user.Id.ToString(),
                        Email = user.Email
                    };
                }
                else
                {
                    throw new UnauthorizedException("User not found");
                }
            }

            return new AuthResponse { Success = false, Message = "Invalid refresh token" };
        }

        public bool LogoutAsync(string userId, string refreshToken)
        {
            try
            {
                if(string.IsNullOrEmpty(refreshToken))
                {
                    throw new InvalidInputException(ErrorCode.FIELD_REQUIRED, "Refresh token is required for logout");
                }
                if(string.IsNullOrEmpty(userId))
                {
                    throw new UnauthorizedException("User not found");
                }

                return _tokenService.RevokeRefreshToken(userId, refreshToken);
            }
            catch
            {
                return false;
            }
        }

        public bool ValidateTwoFactorAsync(string userId, string code)
        {
            // For POC, we'll use a simple TOTP simulation
            // Simple demo: accept "123456" as valid for any user with 2FA enabled
            if (code == "123456")
            {
                // Check if user has 2FA enabled
                var userGuid = Guid.Parse(userId);
                if (_dbContext.Users.TryGetValue(userGuid, out var user) && user.TwoFactorEnabled)
                {
                    return true;
                }
            }

            return false;
        }


        public void RecordFailedAttempt(string key)
        {
            var now = DateTime.UtcNow;

            if (_dbContext.FailedAttempts.TryGetValue(key, out var attempt))
            {
                attempt.Attempts++;
                attempt.LastAttempt = now;

                // Reset if last attempt was more than 15 minutes ago
                if ((now - attempt.FirstAttempt).TotalMinutes > 15)
                {
                    attempt.Attempts = 1;
                    attempt.FirstAttempt = now;
                    attempt.IsBlocked = false;
                }

                // Block after 5 failed attempts
                if (attempt.Attempts >= 5 && !attempt.IsBlocked)
                {
                    attempt.IsBlocked = true;
                    attempt.BlockedUntil = now.AddMinutes(15);
                }
            }
            else
            {
                _dbContext.FailedAttempts[key] = new FailedLoginAttempt
                {
                    Key = key,
                    Attempts = 1,
                    FirstAttempt = now,
                    LastAttempt = now,
                    IsBlocked = false
                };
            }
        }

        public void ResetFailedAttempts(string key)
        {
            if (_dbContext.FailedAttempts.TryGetValue(key, out var attempt))
            {
                attempt.Attempts = 0;
                attempt.IsBlocked = false;
            }
        }

        public async Task LogAuditEventAsync(AuditLog log)
        {
            // In production, this would be async and might write to a database
            // For POC, we'll just add to in-memory collection
            _dbContext.AuditLogs.Add(log);

            // Simulate async operation
            await Task.CompletedTask;
        }

        private async Task LogFailedLogin(string email, string reason)
        {
            await LogAuditEventAsync(new AuditLog
            {
                Action = "LOGIN_FAILED",
                Endpoint = "/api/auth/login",
                IpAddress = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString(),
                UserAgent = _httpContextAccessor.HttpContext?.Request.Headers["User-Agent"],
                Success = false,
                Details = $"Failed login attempt for {email}: {reason}"
            });
        }

    }
}

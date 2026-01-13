using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureAuthPOC.API.Data;
using SecureAuthPOC.API.Filters;
using SecureAuthPOC.API.Models;
using SecureAuthPOC.API.Services;
using System.Security.Claims;

namespace SecureAuthPOC.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [ServiceFilter(typeof(AuditLogFilter))]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IPasswordService _passwordService;
        private readonly ITokenService _tokenService;
        private readonly InMemoryDbContext _dbContext;

        public AuthController(
            IAuthService authService,
            IPasswordService passwordService,
            ITokenService tokenService,
            InMemoryDbContext dbContext)
        {
            _authService = authService;
            _passwordService = passwordService;
            _tokenService = tokenService;
            _dbContext = dbContext;
        }

        [HttpPost("register")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(AuthResponse), 200)]
        [ProducesResponseType(typeof(ProblemDetails), 400)]
        [ProducesResponseType(typeof(ProblemDetails), 429)]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var response = await _authService.RegisterAsync(request);

            return Ok(response);
        }

        [HttpPost("login")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(AuthResponse), 200)]
        [ProducesResponseType(typeof(ProblemDetails), 400)]
        [ProducesResponseType(typeof(ProblemDetails), 401)]
        [ProducesResponseType(typeof(ProblemDetails), 429)]
        public async Task<IActionResult> Login([FromBody] AuthRequest request)
        {
            var response = await _authService.LoginAsync(request);

            return Ok(response);
        }

        [HttpPost("refresh")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(AuthResponse), 200)]
        [ProducesResponseType(typeof(ProblemDetails), 400)]
        [ProducesResponseType(typeof(ProblemDetails), 401)]
        [ProducesResponseType(typeof(ProblemDetails), 429)]
        public IActionResult RefreshToken([FromBody] RefreshTokenRequest request)
        {
            var response = _authService.RefreshTokenAsync(request);

            return Ok(response);
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var refreshToken = Request.Headers["X-Refresh-Token"];

            if (_authService.LogoutAsync(userId, refreshToken))
            {
                await _authService.LogAuditEventAsync(new AuditLog
                {
                    UserId = userId,
                    Action = "LOGOUT",
                    Endpoint = "/api/auth/logout",
                    IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                    UserAgent = HttpContext.Request.Headers["User-Agent"],
                    Success = true,
                    Details = "User logged out successfully"
                });

                return Ok(new { message = "Logout successful" });
            }

            return BadRequest(new { error = "Logout failed" });
        }

        [HttpGet("password-strength")]
        [AllowAnonymous]
        public IActionResult CheckPasswordStrength([FromQuery] string password)
        {
            var score = _passwordService.GetPasswordStrengthScore(password);
            var isStrong = score >= 5;

            return Ok(new
            {
                score,
                isStrong,
                feedback = _passwordService.GetPasswordFeedback(password)
            });
        }

        [HttpPost("generate-password")]
        [AllowAnonymous]
        public IActionResult GeneratePassword()
        {
            var password = _passwordService.GenerateSecurePassword();
            return Ok(new { password });
        }
    }
}

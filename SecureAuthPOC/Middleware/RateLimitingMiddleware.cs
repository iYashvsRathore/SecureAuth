using Microsoft.Extensions.Options;
using SecureAuthPOC.API.Data;
using SecureAuthPOC.API.Exceptions;
using SecureAuthPOC.API.Models;

namespace SecureAuthPOC.API.Middleware
{
    public class RateLimitingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<RateLimitingMiddleware> _logger;
        private readonly InMemoryDbContext _dbContext;
        private readonly RateLimitingOptions _options;

        public RateLimitingMiddleware(
            RequestDelegate next,
            ILogger<RateLimitingMiddleware> logger,
            InMemoryDbContext dbContext,
            IOptions<RateLimitingOptions> options)
        {
            _next = next;
            _logger = logger;
            _dbContext = dbContext;
            _options = options.Value;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Check if rate limiting is enabled
            if (!_options.Enabled)
            {
                await _next(context);
                return;
            }

            // Check if path is excluded from rate limiting
            var path = context.Request.Path.ToString();
            if (_options.ExcludePaths != null && _options.ExcludePaths.Any(p =>
                path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
            {
                await _next(context);
                return;
            }

            var endpoint = context.Request.Path;
            var clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var key = $"{clientIp}:{endpoint}";

            // Check if IP is already blocked
            if (_dbContext.BlockedIPs.TryGetValue(clientIp, out var blockedUntil))
            {
                if (blockedUntil > DateTime.UtcNow)
                {
                    _logger.LogWarning($"IP {clientIp} is blocked until {blockedUntil}");
                    throw new RateLimitException("Too many registration attempts");
                }
                else
                {
                    // Remove from blocked list if block duration has expired
                    _dbContext.BlockedIPs.TryRemove(clientIp, out _);
                }
            }

            if (!await CheckRateLimit(key, clientIp))
            {
                _logger.LogWarning($"Rate limit exceeded for IP {clientIp} on endpoint {endpoint}");
                context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{\"error\":\"Too many requests. Please try again later.\"}");
                return;
            }

            await _next(context);
        }

        private async Task<bool> CheckRateLimit(string key, string clientIp)
        {
            var now = DateTime.UtcNow;

            // Calculate refill rate based on RequestsPerMinute
            var refillRateSeconds = 60.0 / _options.RequestsPerMinute;

            if (_dbContext.RateLimits.TryGetValue(key, out var record))
            {
                // Calculate tokens to add based on time passed
                var timePassed = now - record.LastRefill;
                var tokensToAdd = (int)(timePassed.TotalSeconds / refillRateSeconds);

                if (tokensToAdd > 0)
                {
                    // Refill tokens, but never exceed BurstLimit
                    record.Tokens = Math.Min(_options.BurstLimit, record.Tokens + tokensToAdd);
                    record.LastRefill = now;
                }

                // Check if tokens available
                if (record.Tokens > 0)
                {
                    record.Tokens--;
                    return true;
                }
                else
                {
                    // Block the IP if it consistently exceeds rate limits
                    await BlockIPIfNeeded(clientIp);
                    return false;
                }
            }
            else
            {
                // New entry - start with full bucket minus one token for current request
                _dbContext.RateLimits[key] = new RateLimitRecord
                {
                    Key = key,
                    Tokens = _options.BurstLimit - 1,
                    LastRefill = now
                };
                return true;
            }
        }

        private async Task BlockIPIfNeeded(string clientIp)
        {
            // Track how many times this IP has hit rate limits
            if (!_dbContext.RateLimitExceededCounts.TryGetValue(clientIp, out var count))
            {
                count = 0;
            }

            count++;
            _dbContext.RateLimitExceededCounts[clientIp] = count;

            // Block IP if it exceeds rate limits multiple times
            if (count >= 3)
            {
                var blockUntil = DateTime.UtcNow.AddMinutes(_options.BlockDurationMinutes);
                _dbContext.BlockedIPs[clientIp] = blockUntil;
                _logger.LogWarning($"IP {clientIp} blocked until {blockUntil} due to repeated rate limit violations");
            }

            await Task.CompletedTask;
        }
    }
}

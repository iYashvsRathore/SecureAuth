using Microsoft.EntityFrameworkCore;
using SecureAuthPOC.API.Models;
using System.Collections.Concurrent;

namespace SecureAuthPOC.API.Data
{
    public class InMemoryDbContext : DbContext
    {
        // In-memory collections
        public ConcurrentDictionary<Guid, User> Users { get; set; } = new();
        public ConcurrentDictionary<string, FailedLoginAttempt> FailedAttempts { get; set; } = new();
        public ConcurrentDictionary<string, RefreshToken> RefreshTokens { get; set; } = new();
        public ConcurrentDictionary<string, RateLimitRecord> RateLimits { get; set; } = new();
        public ConcurrentDictionary<string, DateTime> BlockedIPs { get; set; } = new();

        public ConcurrentDictionary<string, int> RateLimitExceededCounts { get; set; } = new();
        public ConcurrentBag<AuditLog> AuditLogs { get; set; } = new();
    }
}

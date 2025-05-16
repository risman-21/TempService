using System.Collections.Concurrent;
using System.Threading.RateLimiting;
namespace EmailAddressVerificationAPI.Policies
{

    public static class IpRateLimitStore
    {
        private static readonly ConcurrentDictionary<string, TokenBucketRateLimiter> _limiters = new();

        public static TokenBucketRateLimiter GetLimiterForIp(string ip)
        {
            return _limiters.GetOrAdd(ip, _ =>
            {
                return new TokenBucketRateLimiter(new TokenBucketRateLimiterOptions
                {
                    TokenLimit = 2,
                    TokensPerPeriod = 2,
                    ReplenishmentPeriod = TimeSpan.FromSeconds(100),
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    AutoReplenishment = true,
                    QueueLimit = 0
                });
            });
        }
    }
}
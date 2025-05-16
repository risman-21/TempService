using Microsoft.Extensions.Caching.Memory;
using EmailAddressVerificationAPI.Models;

namespace EmailAddressVerificationAPI.Services
{
    public class WhiteListedEmailProvider
    {
        private readonly IMemoryCache _cache;
        private const string CacheKey = "WhitelistedEmailProviders";
        private const string FilePath = "WhiteListedDomains.txt";
        private static readonly object CacheLock = new();

        public WhiteListedEmailProvider(IMemoryCache memoryCache)
        {
            _cache = memoryCache;
            LoadWhitelistedProviders();
        }

        private void LoadWhitelistedProviders()
        {
            try
            {
                var whitelistedProviders = new HashSet<string>();

                if (File.Exists(FilePath))
                {
                    foreach (var line in File.ReadLines(FilePath))
                    {
                        var domain = line.Trim().ToLower();
                        if (!string.IsNullOrEmpty(domain))
                        {
                            whitelistedProviders.Add(domain);
                        }
                    }
                }

                _cache.Set(CacheKey, whitelistedProviders, new MemoryCacheEntryOptions
                {
                    SlidingExpiration = TimeSpan.FromMinutes(60)
                });
            }
            catch(Exception)
            {
                throw;
            }
        }

        public Task<EmailStatusCode> IsWhitelisted(string domain)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(domain))
                    return Task.FromResult(EmailStatusCode.Invalid);

                if (!_cache.TryGetValue(CacheKey, out HashSet<string>? whitelistedProviders))
                {
                    lock (CacheLock)
                    {
                        if (!_cache.TryGetValue(CacheKey, out whitelistedProviders))
                        {
                            LoadWhitelistedProviders();
                            _cache.TryGetValue(CacheKey, out whitelistedProviders);
                        }
                    }
                }
                EmailStatusCode result = EmailStatusCode.Invalid;
                if(whitelistedProviders.Contains(domain.ToLower()))
                {
                    result = EmailStatusCode.Valid;
                }

                return Task.FromResult(result);
            }
            catch (Exception)
            {
                return Task.FromResult(EmailStatusCode.InternalServerError);
            }
        }
    }
}

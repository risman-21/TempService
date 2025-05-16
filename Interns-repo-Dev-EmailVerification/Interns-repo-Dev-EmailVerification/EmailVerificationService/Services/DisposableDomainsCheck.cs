using EmailAddressVerificationAPI.Models;
using Microsoft.Extensions.Caching.Memory;

namespace EmailAddressVerificationAPI.Services
{
    public class DisposableDomainsCheck
    {
        private readonly IMemoryCache _cache;
        private const string CacheKey = "DisposableDomains";
        private const string FilePath = "disposable_domains_no_empty_final.txt";

        private static readonly object CacheLock = new();

        public DisposableDomainsCheck(IMemoryCache memoryCache)
        {
            _cache = memoryCache;
            LoadDisposableDomains();
        }

        private void LoadDisposableDomains()
        {
            try
            {
                var topLevelDomains = new HashSet<string>();

                if (File.Exists(FilePath))
                {
                    foreach (var line in File.ReadLines(FilePath))
                    {
                        var domain = line.Trim().ToLower();
                        if (!string.IsNullOrEmpty(domain))
                        {
                            topLevelDomains.Add(domain);
                        }
                    }
                }

                _cache.Set(CacheKey, topLevelDomains, new MemoryCacheEntryOptions
                {
                    SlidingExpiration = TimeSpan.FromMinutes(60)
                });
            }
            catch (Exception)
            {
                throw;
            }
        }

        public Task<EmailStatusCode> IsDisposableDomain(string domain)
        {
            try
            {

                if (string.IsNullOrWhiteSpace(domain))
                    return Task.FromResult(EmailStatusCode.Invalid);

                if (!_cache.TryGetValue(CacheKey, out HashSet<string>? disposableDomains))
                {
                    lock (CacheLock)
                    {
                        if (!_cache.TryGetValue(CacheKey, out disposableDomains))
                        {
                            LoadDisposableDomains();
                            _cache.TryGetValue(CacheKey, out disposableDomains);
                        }
                    }
                }

                EmailStatusCode result = EmailStatusCode.Invalid;

                if (disposableDomains.Contains(domain.ToLower()))
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
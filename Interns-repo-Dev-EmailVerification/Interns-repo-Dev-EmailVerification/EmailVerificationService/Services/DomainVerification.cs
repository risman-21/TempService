using EmailAddressVerificationAPI.Models;
using System.Text.RegularExpressions;

namespace EmailAddressVerificationAPI.Services
{
    public class DomainVerification
    {
        private WhiteListedEmailProvider _whiteListedEmailProvider;
        private TopLevelDomainVerification _topLevelDomainVerifier;
        private VulgarWordSearch _vulgarWordsChecker;
        private DisposableDomainsCheck _disposableDomainsCheker;
        private SmtpServerVerification _smtpServerVerification;

        public DomainVerification(
            WhiteListedEmailProvider whiteListedEmailProvider,
            TopLevelDomainVerification topLevelDomainVerifier,
            VulgarWordSearch vulgarWordVerifier,
            DisposableDomainsCheck disposableDomainsCheker,
            SmtpServerVerification smtpServerVerification)
        {
            _whiteListedEmailProvider = whiteListedEmailProvider;
            _topLevelDomainVerifier = topLevelDomainVerifier;
            _vulgarWordsChecker = vulgarWordVerifier;
            _disposableDomainsCheker = disposableDomainsCheker;
            _smtpServerVerification = smtpServerVerification;
        }

        public async Task<EmailStatusCode> HasVulgarWords(string userName)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(userName)) return EmailStatusCode.Invalid;
                return await _vulgarWordsChecker.HasVulgarWordsAsync(userName);
            }
            catch
            {
                return EmailStatusCode.InternalServerError;
            }
        }

        private async Task<EmailStatusCode> IsDomainWhitelisted(string domain)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(domain)) return EmailStatusCode.Invalid;
                return await _whiteListedEmailProvider.IsWhitelisted(domain);
            }
            catch
            {
                return EmailStatusCode.InternalServerError;
            }
        }

        private async Task<EmailStatusCode> IsTldRegistered(string tld)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(tld)) return EmailStatusCode.Invalid;
                return await _topLevelDomainVerifier.IsRegisteredTLD(tld);
            }
            catch
            {
                return EmailStatusCode.InternalServerError;
            }
        }

        private async Task<EmailStatusCode> IsDisposableDomain(string domain)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(domain)) return EmailStatusCode.Invalid;
                return await _disposableDomainsCheker.IsDisposableDomain(domain);
            }
            catch
            {
                return EmailStatusCode.InternalServerError;
            }
        }

        private EmailStatusCode IsValidRegex(string email)
        {
            try
            {
                string pattern = @"^[^@\s]+@[^@\s]+\.[^@\s]+$";
                return Regex.IsMatch(email, pattern) ? EmailStatusCode.Valid : EmailStatusCode.Invalid;
            }
            catch
            {
                return EmailStatusCode.InternalServerError;
            }
        }

        public async Task<ResponseDTO> VerifyEmailDomain(string emailAddress, int strictness)
{
    var response = new ResponseDTO(new List<ChecklistElementDTO>())
    {
        EmailAddress = emailAddress
    };

    try
    {
        string[] parts = emailAddress.Split('@');
        if (parts.Length != 2) return response;

        var userName = parts[0];
        var domain = parts[1];
        var tld = domain.Split('.').LastOrDefault()?.ToLower() ?? "";

        var smtpResults = await _smtpServerVerification.SmtpServerAsync(emailAddress, domain);

        // Define checks and scores
        var checklist = new List<ChecklistElementDTO>
        {
            new ChecklistElementDTO
            {
                Name = "IsValidRegex",
                WeightageAllocated = 10,
                IsVerified = IsValidRegex(emailAddress).ToString()
            },
            new ChecklistElementDTO
            {
                Name = "IsRegisteredTLD",
                WeightageAllocated = 10,
                IsVerified = (await IsTldRegistered(tld)).ToString()
            },
            new ChecklistElementDTO
            {
                Name = "HasMxRecords",
                WeightageAllocated = 10,
                IsVerified = smtpResults[0].ToString()
            },
            new ChecklistElementDTO
            {
                Name = "AnMxRecordVerified",
                WeightageAllocated = 10,
                IsVerified = smtpResults[1].ToString()
            }
        };

        if (strictness >= 1)
        {
            checklist.AddRange(new[]
            {
                new ChecklistElementDTO
                {
                    Name = "HasSpfRecords",
                    WeightageAllocated = 10,
                    IsVerified = smtpResults[2].ToString()
                },
                new ChecklistElementDTO
                {
                    Name = "HasDmarcRecords",
                    WeightageAllocated = 10,
                    IsVerified = smtpResults[4].ToString()
                },
                new ChecklistElementDTO
                {
                    Name = "IsNotDisposableDomain",
                    WeightageAllocated = 10,
                    IsVerified = (await IsDisposableDomain(domain)).ToString()
                }
            });
        }

        if (strictness >= 2)
        {
            checklist.AddRange(new[]
            {
                new ChecklistElementDTO
                {
                    Name = "IsWhiteListed",
                    WeightageAllocated = 10,
                    IsVerified = (await IsDomainWhitelisted(domain)).ToString()
                },
                new ChecklistElementDTO
                {
                    Name = "ContainsVulgar",
                    WeightageAllocated = 10,
                    IsVerified = (await HasVulgarWords(userName)).ToString()
                },
                new ChecklistElementDTO
                {
                    Name = "HasDkimRecords",
                    WeightageAllocated = 10,
                    IsVerified = smtpResults[3].ToString()
                }
            });
        }

        // Calculate scores
        foreach (var item in checklist)
        {
            var status = (EmailStatusCode)Enum.Parse(typeof(EmailStatusCode), item.IsVerified);
            if (status == EmailStatusCode.Valid || status == EmailStatusCode.BadRequest)
            {
                item.ObtainedScore = item.WeightageAllocated;
                response.TotalScore += item.ObtainedScore;
            }
            response.ChecklistElements.Add(item);
        }

        // Final decision based on score
        response.Status = response.TotalScore >= 70;

        return response;
    }
    catch
    {
        return response;
    }
}

    }
}

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

        public DomainVerification(WhiteListedEmailProvider whiteListedEmailProvider, TopLevelDomainVerification topLevelDomainVerifier, VulgarWordSearch vulgarWordVerifier, DisposableDomainsCheck disposableDomainsCheker, SmtpServerVerification smtpServerVerification)
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
            catch (Exception)
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
            catch (Exception)
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
            catch (Exception)
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
            catch (Exception)
            {
                return EmailStatusCode.InternalServerError;
            }
        }

        private EmailStatusCode IsValidRegex(string email)
        {
            try
            {
                string pattern = @"^[^@\s]+@[^@\s]+\.[^@\s]+$";

                if (Regex.IsMatch(email, pattern))
                {
                    return EmailStatusCode.Valid;
                }
                return EmailStatusCode.Invalid;
            }
            catch (Exception)
            {
                return EmailStatusCode.InternalServerError;
            }
        }

      public async Task<ResponseDTO> VerifyEmailDomain(string emailAddress, int strictness)
{
    try
    {
        bool low = strictness >= 0;
        bool medium = strictness >= 1;
        bool high = strictness >= 2;

        ResponseDTO _responseDTO = new ResponseDTO(new List<ChecklistElementDTO>());
        _responseDTO.EmailAddress = emailAddress;

        var userName = emailAddress.Split('@').FirstOrDefault();
        var domain = emailAddress.Split('@').LastOrDefault();
        var domainParts = domain.Split('.');
        string tld = domainParts[^1].ToLower();

        List<EmailStatusCode> smtpVerificationResults = new();

        if (low)
        {
            var regexCheck = new ChecklistElementDTO
            {
                Name = "IsValidRegex",
                WeightageAllocated = 10,
                IsVerified = IsValidRegex(emailAddress).ToString()
            };
            _responseDTO.ChecklistElements.Add(regexCheck);
            regexCheck.ObtainedScore = (int)Enum.Parse(typeof(EmailStatusCode), regexCheck.IsVerified) == 200
                ? regexCheck.WeightageAllocated : -regexCheck.WeightageAllocated;
            _responseDTO.TotalScore += regexCheck.ObtainedScore;

            var tldCheck = new ChecklistElementDTO
            {
                Name = "IsRegisteredTLD",
                WeightageAllocated = 10,
                IsVerified = (await IsTldRegistered(tld)).ToString()
            };
            _responseDTO.ChecklistElements.Add(tldCheck);
            tldCheck.ObtainedScore = (int)Enum.Parse(typeof(EmailStatusCode), tldCheck.IsVerified) == 200
                ? tldCheck.WeightageAllocated : -tldCheck.WeightageAllocated;
            _responseDTO.TotalScore += tldCheck.ObtainedScore;

            smtpVerificationResults = await _smtpServerVerification.SmtpServerAsync(emailAddress, domain);

            var mxCheck = new ChecklistElementDTO
            {
                Name = "HasMxRecords",
                WeightageAllocated = 10,
                IsVerified = smtpVerificationResults[0].ToString()
            };
            mxCheck.ObtainedScore = (int)smtpVerificationResults[0] == 200 ? mxCheck.WeightageAllocated : -mxCheck.WeightageAllocated;
            _responseDTO.ChecklistElements.Add(mxCheck);
            _responseDTO.TotalScore += mxCheck.ObtainedScore;

            var singleMxCheck = new ChecklistElementDTO
            {
                Name = "AnMxRecordVerified",
                WeightageAllocated = 10,
                IsVerified = smtpVerificationResults[1].ToString()
            };
            singleMxCheck.ObtainedScore = (int)smtpVerificationResults[1] == 200 ? singleMxCheck.WeightageAllocated : -singleMxCheck.WeightageAllocated;
            _responseDTO.ChecklistElements.Add(singleMxCheck);
            _responseDTO.TotalScore += singleMxCheck.ObtainedScore;
        }

        if (medium)
        {
            var spfCheck = new ChecklistElementDTO
            {
                Name = "HasSpfRecords",
                WeightageAllocated = 10,
                IsVerified = smtpVerificationResults[2].ToString()
            };
            spfCheck.ObtainedScore = (int)smtpVerificationResults[2] == 200 ? spfCheck.WeightageAllocated : -spfCheck.WeightageAllocated;
            _responseDTO.ChecklistElements.Add(spfCheck);
            _responseDTO.TotalScore += spfCheck.ObtainedScore;

            var dmarcCheck = new ChecklistElementDTO
            {
                Name = "HasDmarcRecords",
                WeightageAllocated = 10,
                IsVerified = smtpVerificationResults[4].ToString()
            };
            dmarcCheck.ObtainedScore = (int)smtpVerificationResults[4] == 200 ? dmarcCheck.WeightageAllocated : -dmarcCheck.WeightageAllocated;
            _responseDTO.ChecklistElements.Add(dmarcCheck);
            _responseDTO.TotalScore += dmarcCheck.ObtainedScore;

            var disposableCheck = new ChecklistElementDTO
            {
                Name = "IsDisposableDomain",
                WeightageAllocated = 10,
                IsVerified = (await IsDisposableDomain(domain)).ToString()
            };
            disposableCheck.ObtainedScore = (int)Enum.Parse(typeof(EmailStatusCode), disposableCheck.IsVerified) == 400
                ? disposableCheck.WeightageAllocated : -disposableCheck.WeightageAllocated;
            _responseDTO.ChecklistElements.Add(disposableCheck);
            _responseDTO.TotalScore += disposableCheck.ObtainedScore;
        }

        if (high)
        {
            var whiteListCheck = new ChecklistElementDTO
            {
                Name = "IsWhiteListed",
                WeightageAllocated = 10,
                IsVerified = (await IsDomainWhitelisted(domain)).ToString()
            };
            whiteListCheck.ObtainedScore = (int)Enum.Parse(typeof(EmailStatusCode), whiteListCheck.IsVerified) == 200
                ? whiteListCheck.WeightageAllocated : -whiteListCheck.WeightageAllocated;
            _responseDTO.ChecklistElements.Add(whiteListCheck);
            _responseDTO.TotalScore += whiteListCheck.ObtainedScore;

            var vulgarCheck = new ChecklistElementDTO
            {
                Name = "ContainsVulgar",
                WeightageAllocated = 10,
                IsVerified = (await HasVulgarWords(userName)).ToString()
            };
            vulgarCheck.ObtainedScore = (int)Enum.Parse(typeof(EmailStatusCode), vulgarCheck.IsVerified) == 400
                ? vulgarCheck.WeightageAllocated : -vulgarCheck.WeightageAllocated;
            _responseDTO.ChecklistElements.Add(vulgarCheck);
            _responseDTO.TotalScore += vulgarCheck.ObtainedScore;

            var dkimCheck = new ChecklistElementDTO
            {
                Name = "HasDkimRecords",
                WeightageAllocated = 10,
                IsVerified = smtpVerificationResults[3].ToString()
            };
            dkimCheck.ObtainedScore = (int)smtpVerificationResults[3] == 200 ? dkimCheck.WeightageAllocated : -dkimCheck.WeightageAllocated;
            _responseDTO.ChecklistElements.Add(dkimCheck);
            _responseDTO.TotalScore += dkimCheck.ObtainedScore;
        }

        // Final status based on whether total score is positive
        _responseDTO.Status = _responseDTO.TotalScore >=70;
        return _responseDTO;
    }
    catch (Exception)
    {
        throw;
    }
}

    }
}

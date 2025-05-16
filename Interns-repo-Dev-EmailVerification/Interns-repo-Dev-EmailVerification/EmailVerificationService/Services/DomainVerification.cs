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
            try
            {
                bool low = strictness >= 0;
                bool medium = strictness >= 1;
                bool high = strictness >= 2;

                ResponseDTO _responseDTO = new ResponseDTO(new List<ChecklistElementDTO>())
                {
                    EmailAddress = emailAddress
                };

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

                    if ((int)Enum.Parse(typeof(EmailStatusCode), regexCheck.IsVerified) == 200)
                        regexCheck.ObtainedScore = regexCheck.WeightageAllocated;

                    _responseDTO.TotalScore += regexCheck.ObtainedScore;

                    var tldCheck = new ChecklistElementDTO
                    {
                        Name = "IsRegisteredTLD",
                        WeightageAllocated = 10,
                        IsVerified = (await IsTldRegistered(tld)).ToString()
                    };
                    _responseDTO.ChecklistElements.Add(tldCheck);

                    if ((int)Enum.Parse(typeof(EmailStatusCode), tldCheck.IsVerified) == 200)
                        tldCheck.ObtainedScore = tldCheck.WeightageAllocated;

                    _responseDTO.TotalScore += tldCheck.ObtainedScore;

                    smtpVerificationResults = await _smtpServerVerification.SmtpServerAsync(emailAddress, domain);

                    var mxRecordsCheck = new ChecklistElementDTO
                    {
                        Name = "HasMxRecords",
                        WeightageAllocated = 10,
                        IsVerified = smtpVerificationResults[0].ToString()
                    };
                    if ((int)smtpVerificationResults[0] == 200)
                        mxRecordsCheck.ObtainedScore = mxRecordsCheck.WeightageAllocated;
                    _responseDTO.ChecklistElements.Add(mxRecordsCheck);
                    _responseDTO.TotalScore += mxRecordsCheck.ObtainedScore;

                    var singleMxCheck = new ChecklistElementDTO
                    {
                        Name = "AnMxRecordVerified",
                        WeightageAllocated = 10,
                        IsVerified = smtpVerificationResults[1].ToString()
                    };
                    if ((int)smtpVerificationResults[1] == 200)
                        singleMxCheck.ObtainedScore = singleMxCheck.WeightageAllocated;
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
                    if ((int)smtpVerificationResults[2] == 200)
                        spfCheck.ObtainedScore = spfCheck.WeightageAllocated;
                    _responseDTO.ChecklistElements.Add(spfCheck);
                    _responseDTO.TotalScore += spfCheck.ObtainedScore;

                    var dmarkCheck = new ChecklistElementDTO
                    {
                        Name = "HasDmarcRecords",
                        WeightageAllocated = 10,
                        IsVerified = smtpVerificationResults[4].ToString()
                    };
                    if ((int)smtpVerificationResults[4] == 200)
                        dmarkCheck.ObtainedScore = dmarkCheck.WeightageAllocated;
                    _responseDTO.ChecklistElements.Add(dmarkCheck);
                    _responseDTO.TotalScore += dmarkCheck.ObtainedScore;

                    var disposableDomainCheck = new ChecklistElementDTO
                    {
                        Name = "IsDisposableDomain",
                        WeightageAllocated = 10,
                        IsVerified = (await IsDisposableDomain(domain)).ToString()
                    };
                    if ((int)Enum.Parse(typeof(EmailStatusCode), disposableDomainCheck.IsVerified) == 400)
                        disposableDomainCheck.ObtainedScore = disposableDomainCheck.WeightageAllocated;

                    _responseDTO.ChecklistElements.Add(disposableDomainCheck);
                    _responseDTO.TotalScore += disposableDomainCheck.ObtainedScore;
                }

                if (high)
                {
                    var whiteListCheck = new ChecklistElementDTO
                    {
                        Name = "IsWhiteListed",
                        WeightageAllocated = 10,
                        IsVerified = (await IsDomainWhitelisted(domain)).ToString()
                    };
                    if ((int)Enum.Parse(typeof(EmailStatusCode), whiteListCheck.IsVerified) == 200)
                        whiteListCheck.ObtainedScore = whiteListCheck.WeightageAllocated;

                    _responseDTO.ChecklistElements.Add(whiteListCheck);
                    _responseDTO.TotalScore += whiteListCheck.ObtainedScore;

                    var vulgarCheck = new ChecklistElementDTO
                    {
                        Name = "ContainsVulgar",
                        WeightageAllocated = 10,
                        IsVerified = (await HasVulgarWords(userName)).ToString()
                    };
                    if ((int)Enum.Parse(typeof(EmailStatusCode), vulgarCheck.IsVerified) == 400)
                        vulgarCheck.ObtainedScore = vulgarCheck.WeightageAllocated;

                    _responseDTO.ChecklistElements.Add(vulgarCheck);
                    _responseDTO.TotalScore += vulgarCheck.ObtainedScore;

                    var dkimCheck = new ChecklistElementDTO
                    {
                        Name = "HasDkimRecords",
                        WeightageAllocated = 10,
                        IsVerified = smtpVerificationResults[3].ToString()
                    };
                    if ((int)smtpVerificationResults[3] == 200)
                        dkimCheck.ObtainedScore = dkimCheck.WeightageAllocated;

                    _responseDTO.ChecklistElements.Add(dkimCheck);
                    _responseDTO.TotalScore += dkimCheck.ObtainedScore;
                }

                // ✅ Final success check based on total score
                _responseDTO.Status = _responseDTO.TotalScore >= 70;

                return _responseDTO;
            }
            catch
            {
                throw;
            }
        }
    }
}

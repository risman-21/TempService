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
                bool low=false, medium=false, high=false;

                if (strictness >=0)
                {
                    low = true;
                }
                if (strictness >= 1)
                {
                    medium = true;
                }
                if (strictness >= 2)
                {
                    high = true;
                }

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

                    if ((int)Enum.Parse(typeof(EmailStatusCode), regexCheck.IsVerified) == 200)
                    {
                        _responseDTO.ChecklistElements.LastOrDefault().ObtainedScore = regexCheck.WeightageAllocated;
                        _responseDTO.TotalScore += regexCheck.WeightageAllocated;
                    }
                    else
                    {
                        return _responseDTO;
                    }

                    var tldCheck = new ChecklistElementDTO
                    {
                        Name = "IsRegisteredTLD",
                        WeightageAllocated = 10,
                        IsVerified = (await IsTldRegistered(tld)).ToString()
                    };
                    _responseDTO.ChecklistElements.Add(tldCheck);

                    if ((int)Enum.Parse(typeof(EmailStatusCode), tldCheck.IsVerified) == 200)
                    {
                        _responseDTO.ChecklistElements.LastOrDefault().ObtainedScore = tldCheck.WeightageAllocated;
                        _responseDTO.TotalScore += tldCheck.ObtainedScore;
                    }
                    else
                    {
                        return _responseDTO;
                    }


                    smtpVerificationResults = await _smtpServerVerification.SmtpServerAsync(emailAddress, domain);

                    var mxRecordsCheck = new ChecklistElementDTO
                    {
                        Name = "HasMxRecords",
                        WeightageAllocated = 10,
                        IsVerified = smtpVerificationResults[0].ToString(),
                        ObtainedScore = (int)smtpVerificationResults[0] == 200 ? 10 : 0
                    };
                    _responseDTO.ChecklistElements.Add(mxRecordsCheck);

                    _responseDTO.TotalScore += mxRecordsCheck.ObtainedScore;

                    if ((int)Enum.Parse(typeof(EmailStatusCode), mxRecordsCheck.IsVerified) == 400)
                    {
                        return _responseDTO;
                    }


                    var singleMxCheck = new ChecklistElementDTO
                    {
                        Name = "AnMxRecordVerified",
                        WeightageAllocated = 10,
                        IsVerified = smtpVerificationResults[1].ToString(),
                        ObtainedScore = (int)smtpVerificationResults[1] == 200 ? 10 : 0
                    };
                    _responseDTO.ChecklistElements.Add(singleMxCheck);

                    _responseDTO.TotalScore += singleMxCheck.ObtainedScore;

                    if ((int)Enum.Parse(typeof(EmailStatusCode), singleMxCheck.IsVerified) == 400)
                    {
                        return _responseDTO;
                    }

                    _responseDTO.Status = true;
                }


                if (medium)
                {
                    _responseDTO.Status = false;
                    var spfCheck = new ChecklistElementDTO
                    {
                        Name = "HasSpfRecords",
                        WeightageAllocated = 10,
                        IsVerified = smtpVerificationResults[2].ToString(),
                        ObtainedScore = (int)smtpVerificationResults[2] == 200 ? 10 : 0
                    };
                    _responseDTO.ChecklistElements.Add(spfCheck);

                    _responseDTO.TotalScore += spfCheck.ObtainedScore;

                    if ((int)Enum.Parse(typeof(EmailStatusCode), spfCheck.IsVerified) == 400)
                    {
                        return _responseDTO;
                    }



                    var dmarkCheck = new ChecklistElementDTO
                    {
                        Name = "HasDmarcRecords",
                        WeightageAllocated = 10,
                        IsVerified = smtpVerificationResults[4].ToString(),
                        ObtainedScore = (int)smtpVerificationResults[4] == 200 ? 10 : 0
                    };

                    _responseDTO.ChecklistElements.Add(dmarkCheck);

                    _responseDTO.TotalScore += dmarkCheck.ObtainedScore;

                    if ((int)Enum.Parse(typeof(EmailStatusCode), dmarkCheck.IsVerified) == 400)
                    {
                        return _responseDTO;
                    }

                    var disposableDomainCheck = new ChecklistElementDTO
                    {
                        Name = "IsDisposableDomain",
                        WeightageAllocated = 10,
                        IsVerified = (await IsDisposableDomain(domain)).ToString()
                    };

                    _responseDTO.ChecklistElements.Add(disposableDomainCheck);

                    if ((int)Enum.Parse(typeof(EmailStatusCode), disposableDomainCheck.IsVerified) == 400)
                    {
                        _responseDTO.ChecklistElements.LastOrDefault().ObtainedScore = disposableDomainCheck.WeightageAllocated;
                        _responseDTO.TotalScore += disposableDomainCheck.ObtainedScore;
                    }
                    else
                    {
                        return _responseDTO;
                    }
                    _responseDTO.Status = true;
                }


                if (high)
                {
                    _responseDTO.Status = false;
                    var whiteListCheck = new ChecklistElementDTO
                    {
                        Name = "IsWhiteListed",
                        WeightageAllocated = 10,
                        IsVerified = (await IsDomainWhitelisted(domain)).ToString()
                    };

                    _responseDTO.ChecklistElements.Add(whiteListCheck);

                    if ((int)Enum.Parse(typeof(EmailStatusCode), whiteListCheck.IsVerified) == 200)
                    {
                        _responseDTO.ChecklistElements.LastOrDefault().ObtainedScore = whiteListCheck.WeightageAllocated;
                        _responseDTO.TotalScore += whiteListCheck.ObtainedScore;
                    }
                    else
                    {
                        return _responseDTO;
                    }

                    var vulgarCheck = new ChecklistElementDTO
                    {
                        Name = "ContainsVulgar",
                        WeightageAllocated = 10,
                        IsVerified = (await HasVulgarWords(userName)).ToString()
                    };
                    _responseDTO.ChecklistElements.Add(vulgarCheck);

                    if ((int)Enum.Parse(typeof(EmailStatusCode), vulgarCheck.IsVerified) == 400)
                    {
                        _responseDTO.ChecklistElements.LastOrDefault().ObtainedScore = vulgarCheck.WeightageAllocated;
                        _responseDTO.TotalScore += vulgarCheck.ObtainedScore;
                    }
                    else
                    {
                        return _responseDTO;
                    }

                    _responseDTO.Status = true;

                    var dkimCheck = new ChecklistElementDTO
                    {
                        Name = "HasDkimRecords",
                        WeightageAllocated = 10,
                        IsVerified = smtpVerificationResults[3].ToString(),
                        ObtainedScore = (int)smtpVerificationResults[3] == 200 ? 10 : 0
                    };
                    _responseDTO.ChecklistElements.Add(dkimCheck);

                    _responseDTO.TotalScore += dkimCheck.ObtainedScore;

                    if ((int)Enum.Parse(typeof(EmailStatusCode), dkimCheck.IsVerified) == 400)
                    {
                        return _responseDTO;
                    }

                }

                return _responseDTO;
            }
            catch (Exception)
            {
                throw;
            }
        }
    }
}

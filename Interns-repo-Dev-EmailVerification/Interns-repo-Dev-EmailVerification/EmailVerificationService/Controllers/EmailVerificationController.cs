using EmailAddressVerificationAPI.Services;
using EmailAddressVerificationAPI.Models;
using Microsoft.AspNetCore.Mvc;


namespace EmailAddressVerificationAPI.Controllers
{
    [ApiController]
    [Route("/")]
    public class EmailVerificationController : Controller
    {
        private readonly DomainVerification _domainVerification;

        public EmailVerificationController(DomainVerification domainVerification)
        {
            _domainVerification = domainVerification;
        }

        [HttpPost("verify")]

        public async Task<IActionResult> VerifyEmail([FromBody] List<RequestDTO> RequestList )
        {
            try
            {
                if (RequestList.Count==0)
                {
                    return BadRequest("Email is required");
                }


                var tasks = RequestList.Select(async request =>
                {
                    var verificationTask = _domainVerification.VerifyEmailDomain(request.Email, request.Strictness);
                    var timeoutTask = Task.Delay(request.Timeout);

                    var completedTask = await Task.WhenAny(verificationTask, timeoutTask);

                    if (completedTask == timeoutTask)
                    {
                        return null;
                    }

                    return await verificationTask;
                });

                var results = await Task.WhenAll(tasks);

                int numberOfRequest = RequestList.Count;
                for (int i = 0; i < numberOfRequest; i++)
                {
                    int totalChecks = 0;
                    if (RequestList[i].Strictness == 0)
                    {
                        totalChecks = 4;
                    }
                    else if (RequestList[i].Strictness == 1)
                    {
                        totalChecks = 7;
                    }
                    else
                    {
                        totalChecks = 10;
                    }

                    if(results[i] != null)
                    {
                        results[i].TotalScore = (int)((results[i].TotalScore / (double)totalChecks) * 10);
                    }
                }

                return Ok(results);
            }
            catch (Exception)
            {
                return StatusCode(500, "An unexpected error occurred while processing the request.");
            }
        }

    }
}
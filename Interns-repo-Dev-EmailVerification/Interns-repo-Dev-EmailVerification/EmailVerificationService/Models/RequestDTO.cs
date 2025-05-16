namespace EmailAddressVerificationAPI.Models
{
    public class RequestDTO
    {
        public string Email { get; set; }

        public int Timeout { get; set; }

        public int Strictness { get; set; }
    }
}

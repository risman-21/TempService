namespace EmailAddressVerificationAPI.Models
{
    public enum EmailStatusCode
    {
        Valid = 200,
        Invalid = 400,
        Null = 204,
        InternalServerError = 500
    }
}
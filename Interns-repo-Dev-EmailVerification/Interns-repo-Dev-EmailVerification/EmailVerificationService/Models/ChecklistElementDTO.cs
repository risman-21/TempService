namespace EmailAddressVerificationAPI.Models
{
    public class ChecklistElementDTO
    {
        public int WeightageAllocated { get; set; }
        public int ObtainedScore { get; set; }
        public string Name { get; set; }
        public string IsVerified { get; set; }
    }
}

using System.ComponentModel.DataAnnotations;

namespace identityapps.Models
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}

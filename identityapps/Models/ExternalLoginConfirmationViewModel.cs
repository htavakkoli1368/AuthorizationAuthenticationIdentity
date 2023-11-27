using System.ComponentModel.DataAnnotations;

namespace identityapps.Models
{
    public class ExternalLoginConfirmationViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}

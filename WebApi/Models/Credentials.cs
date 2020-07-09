using System.ComponentModel.DataAnnotations;

namespace WebApi.Models
{
    public class Credentials
    {
        [Required]
        public string User { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
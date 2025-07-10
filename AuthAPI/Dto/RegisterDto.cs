using System.ComponentModel.DataAnnotations;
namespace AuthAPI.Dto
{
    public class RegisterDto
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string FullName { get; set; } = string.Empty;

        public string Password { get; set;} = string.Empty;

        public List<string> Roles { get; set; }


    }
}

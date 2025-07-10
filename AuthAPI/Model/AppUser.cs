using Microsoft.AspNetCore.Identity;

namespace AuthAPI.Model
{
    public class AppUser : IdentityUser //Heredar el modelo de entity User
    {

        public string? FullName { get; set; }


    }
}

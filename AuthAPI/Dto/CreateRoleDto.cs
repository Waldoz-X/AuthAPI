using System.ComponentModel.DataAnnotations;

namespace AuthAPI.Dtos
{
    public class CreateRoleDto
    {
        [Required(ErrorMessage = "El nombre del rol es necesario")]
        public string RoleName { get; set; } = null!;
    }
}

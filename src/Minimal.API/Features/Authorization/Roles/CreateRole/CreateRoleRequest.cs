using System.ComponentModel.DataAnnotations;

namespace Minimal.API.Features.Authorization.Roles.CreateRole;

public sealed record CreateRoleRequest
(
    [Required]
    [MinLength(1)]
    [MaxLength(50)]
    string Name
);
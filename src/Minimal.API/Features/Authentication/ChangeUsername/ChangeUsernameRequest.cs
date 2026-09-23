using System.ComponentModel.DataAnnotations;

namespace Minimal.API.Features.Authentication.ChangeUsername;

public sealed record ChangeUsernameRequest
(
    [Required]
    [MinLength(3)]
    [MaxLength(30)]
    string NewUsername,

    [Required]
    string CurrentPassword
);
using System.ComponentModel.DataAnnotations;

namespace Minimal.API.Features.TwoFactor.Login;

public sealed record LoginRequest
(
    [Required]
    [EmailAddress]
    string Email,

    [Required]
    string Code
);
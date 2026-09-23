using System.ComponentModel.DataAnnotations;

namespace Minimal.API.Features.Authentication.TwoFactor.Login;

public sealed record LoginRequest
(
    [Required]
    [EmailAddress]
    string Email,

    [Required]
    string Code
);
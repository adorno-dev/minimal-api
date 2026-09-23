using System.ComponentModel.DataAnnotations;

namespace Minimal.API.Features.Authentication.Login;

public sealed record LoginRequest
(
    [Required]
    [EmailAddress]
    string Email,

    [Required]
    string Password
);
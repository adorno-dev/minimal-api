using System.ComponentModel.DataAnnotations;

namespace Minimal.API.Features.Authentication.ConfirmEmail;

public sealed record ConfirmEmailRequest
(
    [Required]
    [EmailAddress]
    string Email,

    [Required]
    string Token
);
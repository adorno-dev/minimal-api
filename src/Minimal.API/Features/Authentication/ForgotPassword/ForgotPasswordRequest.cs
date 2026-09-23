using System.ComponentModel.DataAnnotations;

namespace Minimal.API.Features.Authentication.ForgotPassword;

public sealed record ForgotPasswordRequest
(
    [Required]
    [EmailAddress]
    string Email
);
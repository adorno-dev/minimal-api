using System.ComponentModel.DataAnnotations;

namespace Minimal.API.Features.Authentication.ChangeEmail;

public sealed record ChangeEmailRequest
(
    [Required]
    [EmailAddress]
    string NewEmail,

    [Required]
    string CurrentPassword
);
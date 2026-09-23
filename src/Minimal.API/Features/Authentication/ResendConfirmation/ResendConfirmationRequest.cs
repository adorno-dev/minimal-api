using System.ComponentModel.DataAnnotations;

namespace Minimal.API.Features.Authentication.ResendConfirmation;

public sealed record ResendConfirmationRequest
(
    [Required]
    [EmailAddress]
    string Email
);
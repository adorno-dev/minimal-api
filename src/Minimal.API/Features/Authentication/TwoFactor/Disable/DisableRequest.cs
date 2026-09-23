using System.ComponentModel.DataAnnotations;

namespace Minimal.API.Features.Authentication.TwoFactor.Disable;

public sealed record DisableRequest
(
    [Required]
    string CurrentPassword,

    [Required]
    string Code
);
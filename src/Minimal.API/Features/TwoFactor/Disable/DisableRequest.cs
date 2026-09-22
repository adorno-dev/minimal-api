using System.ComponentModel.DataAnnotations;

namespace Minimal.API.Features.TwoFactor.Disable;

public sealed record DisableRequest
(
    [Required]
    string CurrentPassword,

    [Required]
    string Code
);
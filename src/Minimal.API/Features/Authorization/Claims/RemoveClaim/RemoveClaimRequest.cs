using System.ComponentModel.DataAnnotations;

namespace Minimal.API.Features.Authorization.Claims.RemoveClaim;

public sealed record RemoveClaimRequest
(
    [Required]
    string Type,

    [Required]
    string Value
);
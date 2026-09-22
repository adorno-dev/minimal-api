using System.ComponentModel.DataAnnotations;

namespace Minimal.API.Features.Authorization.Claims.AddClaim;

public sealed record AddClaimRequest
(
    [Required]
    string Type,

    [Required]
    string Value
);
using System.ComponentModel.DataAnnotations;

namespace Minimal.API.Features.Shared.Contracts;

public sealed record RefreshTokenRequest
(
    [Required]
    string RefreshToken
);
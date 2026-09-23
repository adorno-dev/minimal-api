using System.ComponentModel.DataAnnotations;

namespace Minimal.API.Features.Authentication.RefreshToken;

public sealed record RefreshTokenRequest
(
    [Required]
    string RefreshToken
);